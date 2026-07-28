package lumina

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/segfaultd/lux/internal/access"
	"github.com/segfaultd/lux/internal/auth"
	"github.com/segfaultd/lux/internal/config"
	"github.com/segfaultd/lux/internal/observability"
	"github.com/segfaultd/lux/internal/protocol"
	"github.com/segfaultd/lux/internal/session"
	"github.com/segfaultd/lux/internal/store"
)

type Server struct {
	cfg      config.Config
	store    *store.Store
	auth     *auth.Service
	metrics  *observability.Metrics
	sessions *session.Registry
	log      *slog.Logger
}

func New(cfg config.Config, store *store.Store, metrics *observability.Metrics, log *slog.Logger) *Server {
	return &Server{
		cfg: cfg, store: store, auth: auth.New(store), metrics: metrics,
		sessions: session.NewRegistry(), log: log,
	}
}

func (s *Server) Sessions() *session.Registry { return s.sessions }

func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	if s.cfg.TLSCert != "" {
		cert, err := tls.LoadX509KeyPair(s.cfg.TLSCert, s.cfg.TLSKey)
		if err != nil {
			return fmt.Errorf("load Lumina TLS identity: %w", err)
		}
		listener = tls.NewListener(listener, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		})
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.log.Warn("Lumina accept failed", "error", err)
			continue
		}
		s.metrics.Connections.Add(1)
		s.metrics.ActiveConnections.Add(1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer s.metrics.ActiveConnections.Add(-1)
			defer conn.Close()
			closed := make(chan struct{})
			go func() {
				select {
				case <-ctx.Done():
					_ = conn.Close()
				case <-closed:
				}
			}()
			s.handleConnection(ctx, conn)
			close(closed)
		}()
	}
}

func (s *Server) handleConnection(ctx context.Context, conn net.Conn) {
	trackedConn := session.Track(conn)
	conn = trackedConn
	remote := conn.RemoteAddr().String()
	if err := conn.SetReadDeadline(time.Now().Add(s.cfg.HelloWait)); err != nil {
		s.log.Debug("setting hello deadline", "error", err)
	}
	packet, err := protocol.ReadPacket(conn)
	if err != nil {
		if errors.Is(err, protocol.ErrHTTP) {
			s.writeHTTPBadRequest(conn)
			return
		}
		if !errors.Is(err, io.EOF) {
			s.log.Debug("reading hello", "remote", remote, "error", err)
		}
		return
	}
	if packet.Code != protocol.CodeHello {
		s.fail(conn, 0, s.cfg.ServerName+": bad sequence.")
		return
	}
	hello, err := protocol.DecodeHello(packet.Payload)
	if err != nil {
		s.fail(conn, 0, s.cfg.ServerName+": invalid hello.")
		return
	}
	s.metrics.RecordVersion(hello.ProtocolVersion)
	if hello.Credentials == nil {
		s.fail(conn, 1, s.cfg.ServerName+": username and password required.")
		return
	}
	authCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	principal, err := s.auth.Authenticate(authCtx, hello.Credentials.Username, hello.Credentials.Password)
	cancel()
	if errors.Is(err, auth.ErrInvalidCredentials) {
		s.log.Warn("Lumina authentication failed",
			"remote", remote, "username", hello.Credentials.Username)
		s.fail(conn, 1, s.cfg.ServerName+": invalid username or password.")
		return
	}
	if err != nil {
		s.log.Error("authenticate Lumina client", "error", err)
		s.fail(conn, 3, s.cfg.ServerName+": authentication database error; try again later.")
		return
	}
	if hello.ProtocolVersion <= 4 {
		if err := protocol.WritePacket(conn, protocol.CodeOK, nil); err != nil {
			return
		}
	} else {
		var features uint32
		if s.cfg.AllowDeletes && principal.Can(access.CapabilityDeleteHistory) {
			features |= 0x02
		}
		if err := protocol.WritePacket(conn, protocol.CodeHelloResult, protocol.EncodeHelloResult(features)); err != nil {
			return
		}
	}
	current := s.sessions.Register(session.Identity{
		AccountID: principal.ID, Username: principal.Username,
		IsAdmin: principal.IsAdmin, CanDeleteHistory: principal.CanDeleteHistory,
		RemoteAddress: remote, ProtocolVersion: hello.ProtocolVersion,
	}, trackedConn)
	defer s.sessions.Unregister(current.ID)
	s.log.Debug("Lumina client connected",
		"session", current.ID, "username", principal.Username,
		"is_admin", principal.IsAdmin, "can_delete_history", principal.CanDeleteHistory,
		"remote", remote, "protocol", hello.ProtocolVersion)
	for {
		if ctx.Err() != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(s.cfg.CommandWait))
		packet, err = protocol.ReadPacket(conn)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				var netErr net.Error
				if !errors.As(err, &netErr) || !netErr.Timeout() {
					s.log.Debug("reading Lumina command", "remote", remote, "error", err)
				}
			}
			return
		}
		_ = conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		s.sessions.StartRequest(current.ID, operationName(packet.Code))
		keep := s.handlePacket(ctx, conn, hello, principal, current.ID, packet)
		s.sessions.FinishRequest(current.ID)
		if !keep {
			return
		}
	}
}

func (s *Server) handlePacket(
	parent context.Context,
	conn net.Conn,
	hello protocol.Hello,
	principal auth.Principal,
	sessionID uint64,
	packet protocol.Packet,
) bool {
	switch packet.Code {
	case protocol.CodePullMetadata:
		if !principal.Can(access.CapabilityPull) {
			return s.failSession(conn, sessionID, 2, s.cfg.ServerName+": permission denied for metadata pulls.")
		}
		req, err := protocol.DecodePullMetadata(packet.Payload)
		if err != nil {
			return s.failSession(conn, sessionID, 0, s.cfg.ServerName+": invalid pull request.")
		}
		hashes := make([][]byte, len(req.Funcs))
		for i, f := range req.Funcs {
			if err := protocol.ValidateHash(f.Hash); err != nil {
				return s.failSession(conn, sessionID, 0, s.cfg.ServerName+": invalid function hash.")
			}
			hashes[i] = f.Hash
		}
		ctx, cancel := context.WithTimeout(parent, s.cfg.PullWait)
		funcs, err := s.store.PullWithFlags(ctx, hashes, req.Flags)
		cancel()
		if err != nil {
			s.log.Error("pull metadata", "error", err)
			return s.failSession(conn, sessionID, 3, s.cfg.ServerName+": database error; try again later.")
		}
		status := make([]uint32, len(funcs))
		found := make([]protocol.PullResultFunction, 0, len(funcs))
		for i, f := range funcs {
			if f == nil {
				status[i] = 1
				continue
			}
			found = append(found, *f)
		}
		s.metrics.Queried.Add(uint64(len(funcs)))
		s.metrics.Pulls.Add(uint64(len(found)))
		return s.write(conn, protocol.CodePullMetadataResult, protocol.EncodePullResult(status, found))

	case protocol.CodePushMetadata:
		if !principal.Can(access.CapabilityPush) {
			return s.failSession(conn, sessionID, 2, s.cfg.ServerName+": permission denied for metadata pushes.")
		}
		req, err := protocol.DecodePushMetadata(packet.Payload)
		if err != nil {
			return s.failSession(conn, sessionID, 0, s.cfg.ServerName+": invalid push request.")
		}
		for _, f := range req.Funcs {
			if err := protocol.ValidateHash(f.Hash); err != nil {
				return s.failSession(conn, sessionID, 0, s.cfg.ServerName+": invalid function hash.")
			}
		}
		status, err := s.store.Push(parent, store.PushIdentity{
			LicenseNumber: hello.LicenseNumber[:],
			LicenseData:   hello.LicenseData,
			Hostname:      req.Hostname,
			AccountID:     principal.ID,
			Username:      principal.Username,
			Protocol:      hello.ProtocolVersion,
		}, req)
		s.sessions.SetHostname(sessionID, req.Hostname)
		if err != nil {
			s.log.Error("push metadata", "error", err)
			return s.failSession(conn, sessionID, 3, s.cfg.ServerName+": database error; try again later.")
		}
		s.metrics.Pushes.Add(uint64(len(status)))
		for _, v := range status {
			if v != 0 {
				s.metrics.NewFunctions.Add(1)
			}
		}
		return s.write(conn, protocol.CodePushMetadataResult, protocol.EncodePushResult(status))

	case protocol.CodeDeleteHistory:
		if !s.cfg.AllowDeletes {
			return s.failSession(conn, sessionID, 2, s.cfg.ServerName+": delete command is disabled.")
		}
		if !principal.Can(access.CapabilityDeleteHistory) {
			return s.failSession(conn, sessionID, 2, s.cfg.ServerName+": permission denied for history deletion.")
		}
		req, err := protocol.DecodeDeleteHistory(packet.Payload)
		if err != nil {
			return s.failSession(conn, sessionID, 0, s.cfg.ServerName+": invalid delete request.")
		}
		deleted, err := s.store.DeleteHashes(parent, req.FunctionHashes)
		if err != nil {
			s.log.Error("delete histories", "error", err)
			return s.failSession(conn, sessionID, 3, s.cfg.ServerName+": database error; try again later.")
		}
		s.log.Debug("deleted function metadata", "versions", deleted, "hashes", len(req.FunctionHashes))
		return s.write(conn, protocol.CodeDeleteHistoryResult, protocol.EncodeDeleteResult(uint32(len(req.FunctionHashes))))

	case protocol.CodeGetFuncHistories:
		if !principal.Can(access.CapabilityReadHistory) {
			return s.failSession(conn, sessionID, 2, s.cfg.ServerName+": permission denied for function histories.")
		}
		if s.cfg.HistoryLimit == 0 {
			return s.failSession(conn, sessionID, 4, s.cfg.ServerName+": function histories are disabled.")
		}
		req, err := protocol.DecodeGetFuncHistories(packet.Payload)
		if err != nil {
			return s.failSession(conn, sessionID, 0, s.cfg.ServerName+": invalid history request.")
		}
		status := make([]uint32, len(req.Funcs))
		var histories [][]protocol.FunctionHistory
		for i, f := range req.Funcs {
			rows, err := s.store.Histories(parent, f.Hash, uint32(s.cfg.HistoryLimit))
			if err != nil {
				s.log.Error("get histories", "error", err)
				return s.failSession(conn, sessionID, 3, s.cfg.ServerName+": database error; try again later.")
			}
			if len(rows) > 0 {
				status[i] = 1
				histories = append(histories, rows)
			}
		}
		return s.write(conn, protocol.CodeGetFuncHistoriesResult, protocol.EncodeHistoriesResult(status, histories))
	default:
		return s.failSession(conn, sessionID, 0, s.cfg.ServerName+": invalid command.")
	}
}

func (s *Server) write(conn net.Conn, code byte, payload []byte) bool {
	if err := protocol.WritePacket(conn, code, payload); err != nil {
		s.log.Debug("writing Lumina response", "error", err)
		return false
	}
	return true
}

func (s *Server) fail(conn net.Conn, code uint32, message string) bool {
	s.metrics.Failures.Add(1)
	return s.write(conn, protocol.CodeFail, protocol.EncodeFail(code, message))
}

func (s *Server) failSession(conn net.Conn, sessionID uint64, code uint32, message string) bool {
	s.sessions.RecordError(sessionID)
	return s.fail(conn, code, message)
}

func operationName(code byte) string {
	switch code {
	case protocol.CodePullMetadata:
		return "pull_metadata"
	case protocol.CodePushMetadata:
		return "push_metadata"
	case protocol.CodeDeleteHistory:
		return "delete_history"
	case protocol.CodeGetFuncHistories:
		return "get_function_histories"
	default:
		return fmt.Sprintf("unknown_0x%02x", code)
	}
}

func (s *Server) writeHTTPBadRequest(conn net.Conn) {
	body := "<!doctype html><title>Wrong port</title><h1>This is the Lux Lumina protocol port.</h1><p>Open the management HTTP port instead.</p>"
	_, _ = fmt.Fprintf(conn,
		"HTTP/1.1 400 Bad Request\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		len(body), body)
}
