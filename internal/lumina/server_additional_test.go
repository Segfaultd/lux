package lumina

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/segfaultd/lux/internal/config"
	"github.com/segfaultd/lux/internal/observability"
	"github.com/segfaultd/lux/internal/protocol"
	"github.com/segfaultd/lux/internal/store"
)

func TestHelloVariantsAndWrongPort(t *testing.T) {
	t.Run("legacy protocol gets OK", func(t *testing.T) {
		server := newLuminaTestServer(t, config.Config{Username: "guest"})
		conn, done := startDirectConnection(server)
		sendHello(t, conn, 4, nil)
		packet := readPacket(t, conn)
		if packet.Code != protocol.CodeOK || len(packet.Payload) != 0 {
			t.Fatalf("unexpected hello response: %#v", packet)
		}
		conn.Close()
		waitConnection(t, done)
	})

	t.Run("bad sequence", func(t *testing.T) {
		server := newLuminaTestServer(t, config.Config{ServerName: "unit"})
		conn, done := startDirectConnection(server)
		if err := protocol.WritePacket(conn, protocol.CodePullMetadata, []byte{0, 0, 0}); err != nil {
			t.Fatal(err)
		}
		assertFailure(t, readPacket(t, conn), 0, "bad sequence")
		conn.Close()
		waitConnection(t, done)
	})

	t.Run("malformed hello", func(t *testing.T) {
		server := newLuminaTestServer(t, config.Config{ServerName: "unit"})
		conn, done := startDirectConnection(server)
		if err := protocol.WritePacket(conn, protocol.CodeHello, []byte{5}); err != nil {
			t.Fatal(err)
		}
		assertFailure(t, readPacket(t, conn), 0, "invalid hello")
		conn.Close()
		waitConnection(t, done)
	})

	t.Run("invalid credentials", func(t *testing.T) {
		for _, creds := range []protocol.Credentials{
			{Username: "other", Password: "secret"},
			{Username: "guest", Password: "wrong"},
		} {
			server := newLuminaTestServer(t, config.Config{
				ServerName: "unit", Username: "guest", Password: "secret",
			})
			conn, done := startDirectConnection(server)
			sendHello(t, conn, 5, &creds)
			assertFailure(t, readPacket(t, conn), 1, "invalid username")
			conn.Close()
			waitConnection(t, done)
		}
	})

	t.Run("HTTP request", func(t *testing.T) {
		server := newLuminaTestServer(t, config.Config{})
		conn, done := startDirectConnection(server)
		if _, err := conn.Write([]byte("gEt /")); err != nil {
			t.Fatal(err)
		}
		response, err := io.ReadAll(conn)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(response), "400 Bad Request") ||
			!strings.Contains(string(response), "Lumina protocol port") {
			t.Fatalf("unexpected HTTP response: %q", response)
		}
		waitConnection(t, done)
	})
}

func TestHelloAndCommandTimeouts(t *testing.T) {
	t.Run("hello timeout", func(t *testing.T) {
		server := newLuminaTestServer(t, config.Config{HelloWait: 20 * time.Millisecond})
		conn, done := startDirectConnection(server)
		defer conn.Close()
		waitConnection(t, done)
	})
	t.Run("command timeout", func(t *testing.T) {
		server := newLuminaTestServer(t, config.Config{
			HelloWait: time.Second, CommandWait: 20 * time.Millisecond,
		})
		conn, done := startDirectConnection(server)
		sendHello(t, conn, 5, nil)
		if packet := readPacket(t, conn); packet.Code != protocol.CodeHelloResult {
			t.Fatalf("hello code %#x", packet.Code)
		}
		waitConnection(t, done)
		conn.Close()
	})
}

func TestMalformedAndUnsupportedCommands(t *testing.T) {
	server := newLuminaTestServer(t, config.Config{
		ServerName: "unit", Username: "guest", HistoryLimit: 10, HelloWait: time.Second, CommandWait: time.Second,
	})
	conn, done := startDirectConnection(server)
	sendHello(t, conn, 5, &protocol.Credentials{Username: "guest"})
	if packet := readPacket(t, conn); packet.Code != protocol.CodeHelloResult {
		t.Fatalf("hello code %#x", packet.Code)
	}

	requests := []struct {
		name    string
		code    byte
		payload []byte
		message string
	}{
		{"unknown command", 0x7e, []byte{1}, "invalid command"},
		{"malformed pull", protocol.CodePullMetadata, nil, "invalid pull"},
		{"malformed push", protocol.CodePushMetadata, nil, "invalid push"},
		{"malformed delete", protocol.CodeDeleteHistory, nil, "delete command is disabled"},
		{"malformed histories", protocol.CodeGetFuncHistories, nil, "invalid history"},
	}
	for _, request := range requests {
		t.Run(request.name, func(t *testing.T) {
			if err := protocol.WritePacket(conn, request.code, request.payload); err != nil {
				t.Fatal(err)
			}
			assertFailure(t, readPacket(t, conn), failureCodeFor(request.code), request.message)
		})
	}

	var pull protocol.Encoder
	pull.DD(0)
	pull.U32s(nil)
	pull.DD(1)
	pull.DD(0)
	pull.Bytes([]byte{1})
	if err := protocol.WritePacket(conn, protocol.CodePullMetadata, pull.Payload()); err != nil {
		t.Fatal(err)
	}
	assertFailure(t, readPacket(t, conn), 0, "invalid function hash")

	var push protocol.Encoder
	push.DD(0)
	push.CString("a.i64")
	push.CString("a.bin")
	push.Fixed(make([]byte, 16))
	push.CString("host")
	push.DD(1)
	push.CString("bad")
	push.DD(1)
	push.Bytes(nil)
	push.DD(0)
	push.Bytes([]byte{1})
	push.DD(0)
	if err := protocol.WritePacket(conn, protocol.CodePushMetadata, push.Payload()); err != nil {
		t.Fatal(err)
	}
	assertFailure(t, readPacket(t, conn), 0, "invalid function hash")

	conn.Close()
	waitConnection(t, done)
}

func TestDeleteAndHistoryCommands(t *testing.T) {
	t.Run("history disabled", func(t *testing.T) {
		server := newLuminaTestServer(t, config.Config{HistoryLimit: 0, HelloWait: time.Second, CommandWait: time.Second})
		conn, done := connectedSession(t, server)
		if err := protocol.WritePacket(conn, protocol.CodeGetFuncHistories, historyRequest(bytes.Repeat([]byte{1}, 16))); err != nil {
			t.Fatal(err)
		}
		assertFailure(t, readPacket(t, conn), 4, "histories are disabled")
		conn.Close()
		waitConnection(t, done)
	})

	t.Run("delete and history success", func(t *testing.T) {
		db, hash := populatedLuminaStore(t)
		server := testServerWithStore(config.Config{
			ServerName: "unit", AllowDeletes: true, HistoryLimit: 10,
			HelloWait: time.Second, CommandWait: time.Second, PullWait: time.Second,
		}, db)
		conn, done := connectedSession(t, server)

		if err := protocol.WritePacket(conn, protocol.CodeGetFuncHistories, historyRequest(hash)); err != nil {
			t.Fatal(err)
		}
		packet := readPacket(t, conn)
		if packet.Code != protocol.CodeGetFuncHistoriesResult {
			t.Fatalf("history response code %#x", packet.Code)
		}
		d := protocol.NewDecoder(packet.Payload)
		status, err := d.U32s(10)
		if err != nil || len(status) != 1 || status[0] != 1 {
			t.Fatalf("history status %v, error %v", status, err)
		}

		missing := bytes.Repeat([]byte{0x99}, 16)
		if err := protocol.WritePacket(conn, protocol.CodeGetFuncHistories, historyRequest(missing)); err != nil {
			t.Fatal(err)
		}
		packet = readPacket(t, conn)
		d = protocol.NewDecoder(packet.Payload)
		status, _ = d.U32s(10)
		if status[0] != 0 {
			t.Fatalf("missing history status %v", status)
		}

		if err := protocol.WritePacket(conn, protocol.CodeDeleteHistory, deleteRequest(hash)); err != nil {
			t.Fatal(err)
		}
		packet = readPacket(t, conn)
		if packet.Code != protocol.CodeDeleteHistoryResult {
			t.Fatalf("delete response code %#x", packet.Code)
		}
		d = protocol.NewDecoder(packet.Payload)
		if deleted, _ := d.DD(); deleted != 1 {
			t.Fatalf("deleted hashes %d", deleted)
		}
		conn.Close()
		waitConnection(t, done)
	})

	t.Run("malformed enabled delete", func(t *testing.T) {
		server := newLuminaTestServer(t, config.Config{
			AllowDeletes: true, HistoryLimit: 10, HelloWait: time.Second, CommandWait: time.Second,
		})
		conn, done := connectedSession(t, server)
		if err := protocol.WritePacket(conn, protocol.CodeDeleteHistory, nil); err != nil {
			t.Fatal(err)
		}
		assertFailure(t, readPacket(t, conn), 0, "invalid delete")
		conn.Close()
		waitConnection(t, done)
	})
}

func TestDatabaseFailuresBecomeRPCFailures(t *testing.T) {
	db, hash := populatedLuminaStore(t)
	server := testServerWithStore(config.Config{
		ServerName: "unit", AllowDeletes: true, HistoryLimit: 10,
		HelloWait: time.Second, CommandWait: time.Second, PullWait: time.Second,
	}, db)
	conn, done := connectedSession(t, server)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	var pull protocol.Encoder
	pull.DD(0)
	pull.U32s(nil)
	pull.DD(1)
	pull.DD(0)
	pull.Bytes(hash)
	if err := protocol.WritePacket(conn, protocol.CodePullMetadata, pull.Payload()); err != nil {
		t.Fatal(err)
	}
	assertFailure(t, readPacket(t, conn), 3, "database error")

	var push protocol.Encoder
	push.DD(0)
	push.CString("a.i64")
	push.CString("a.bin")
	push.Fixed(make([]byte, 16))
	push.CString("host")
	push.DD(0)
	push.DD(0)
	if err := protocol.WritePacket(conn, protocol.CodePushMetadata, push.Payload()); err != nil {
		t.Fatal(err)
	}
	assertFailure(t, readPacket(t, conn), 3, "database error")

	if err := protocol.WritePacket(conn, protocol.CodeDeleteHistory, deleteRequest(hash)); err != nil {
		t.Fatal(err)
	}
	assertFailure(t, readPacket(t, conn), 3, "database error")

	if err := protocol.WritePacket(conn, protocol.CodeGetFuncHistories, historyRequest(hash)); err != nil {
		t.Fatal(err)
	}
	assertFailure(t, readPacket(t, conn), 3, "database error")

	conn.Close()
	waitConnection(t, done)
}

func TestServeConfigurationAndCancellation(t *testing.T) {
	t.Run("invalid TLS identity", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		server := newLuminaTestServer(t, config.Config{
			TLSCert: filepath.Join(t.TempDir(), "missing.crt"),
			TLSKey:  filepath.Join(t.TempDir(), "missing.key"),
		})
		if err := server.Serve(context.Background(), listener); err == nil {
			t.Fatal("expected TLS identity error")
		}
	})

	t.Run("cancellation closes idle clients", func(t *testing.T) {
		server := newLuminaTestServer(t, config.Config{HelloWait: time.Hour})
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- server.Serve(ctx, listener) }()
		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("server did not stop after cancellation")
		}
		_ = conn.Close()
	})

	t.Run("TLS hello", func(t *testing.T) {
		certPath, keyPath := testTLSIdentity(t)
		server := newLuminaTestServer(t, config.Config{
			TLSCert: certPath, TLSKey: keyPath, HelloWait: time.Second, CommandWait: time.Second,
		})
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- server.Serve(ctx, listener) }()
		client, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
			InsecureSkipVerify: true, // Test certificate is intentionally self-signed.
			MinVersion:         tls.VersionTLS12,
		})
		if err != nil {
			t.Fatal(err)
		}
		sendHello(t, client, 5, &protocol.Credentials{Username: "guest"})
		if packet := readPacket(t, client); packet.Code != protocol.CodeHelloResult {
			t.Fatalf("TLS hello response code %#x", packet.Code)
		}
		_ = client.Close()
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("TLS server did not stop")
		}
	})
}

func newLuminaTestServer(t *testing.T, cfg config.Config) *Server {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "lux.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if cfg.ServerName == "" {
		cfg.ServerName = "lux-test"
	}
	if cfg.Username == "" {
		cfg.Username = "guest"
	}
	if cfg.HelloWait == 0 {
		cfg.HelloWait = time.Second
	}
	if cfg.CommandWait == 0 {
		cfg.CommandWait = time.Second
	}
	if cfg.PullWait == 0 {
		cfg.PullWait = time.Second
	}
	return testServerWithStore(cfg, db)
}

func testServerWithStore(cfg config.Config, db *store.Store) *Server {
	if cfg.Username == "" {
		cfg.Username = "guest"
	}
	return New(cfg, db, observability.NewMetrics(), slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func startDirectConnection(server *Server) (net.Conn, <-chan struct{}) {
	client, peer := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer peer.Close()
		server.handleConnection(context.Background(), peer)
	}()
	return client, done
}

func connectedSession(t *testing.T, server *Server) (net.Conn, <-chan struct{}) {
	t.Helper()
	conn, done := startDirectConnection(server)
	sendHello(t, conn, 5, &protocol.Credentials{Username: "guest"})
	packet := readPacket(t, conn)
	if packet.Code != protocol.CodeHelloResult {
		t.Fatalf("hello response code %#x", packet.Code)
	}
	return conn, done
}

func sendHello(t *testing.T, conn net.Conn, version uint32, creds *protocol.Credentials) {
	t.Helper()
	var e protocol.Encoder
	e.DD(version)
	e.Bytes([]byte("license"))
	e.Fixed([]byte{1, 2, 3, 4, 5, 6})
	e.DD(0)
	if creds != nil {
		e.CString(creds.Username)
		e.CString(creds.Password)
	}
	if err := protocol.WritePacket(conn, protocol.CodeHello, e.Payload()); err != nil {
		t.Fatal(err)
	}
}

func readPacket(t *testing.T, conn net.Conn) protocol.Packet {
	t.Helper()
	packet, err := protocol.ReadPacket(conn)
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

func assertFailure(t *testing.T, packet protocol.Packet, wantCode uint32, message string) {
	t.Helper()
	if packet.Code != protocol.CodeFail {
		t.Fatalf("response code %#x, want failure", packet.Code)
	}
	d := protocol.NewDecoder(packet.Payload)
	code, err := d.DD()
	if err != nil {
		t.Fatal(err)
	}
	text, err := d.CString()
	if err != nil {
		t.Fatal(err)
	}
	if code != wantCode || !strings.Contains(text, message) {
		t.Fatalf("failure code=%d message=%q, want code=%d containing %q", code, text, wantCode, message)
	}
}

func waitConnection(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("connection handler did not stop")
	}
}

func historyRequest(hash []byte) []byte {
	var e protocol.Encoder
	e.DD(1)
	e.DD(0)
	e.Bytes(hash)
	e.DD(0)
	return append([]byte(nil), e.Payload()...)
}

func deleteRequest(hash []byte) []byte {
	var e protocol.Encoder
	e.DD(8)
	e.Strings(nil)
	for range 2 {
		e.DD(0)
	}
	for range 4 {
		e.Strings(nil)
	}
	e.DD(0)
	e.DD(1)
	e.Fixed(hash)
	e.DD(0)
	e.DQ(0)
	return append([]byte(nil), e.Payload()...)
}

func populatedLuminaStore(t *testing.T) (*store.Store, []byte) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "lux.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	hash := bytes.Repeat([]byte{0x77}, 16)
	var md protocol.Encoder
	md.DD(3)
	md.Bytes([]byte("comment"))
	_, err = db.Push(context.Background(), store.PushIdentity{
		LicenseNumber: []byte{1, 2, 3, 4, 5, 6}, LicenseData: []byte("license"), Hostname: "host",
	}, protocol.PushMetadata{
		IDBPath: "sample.i64", FilePath: "sample.bin", Hostname: "host",
		Funcs: []protocol.PushFunction{{
			Name: "known", Length: 12, Hash: hash, Metadata: append([]byte(nil), md.Payload()...),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return db, hash
}

func failureCodeFor(code byte) uint32 {
	if code == protocol.CodeDeleteHistory {
		return 2
	}
	return 0
}

func testTLSIdentity(t *testing.T) (string, string) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	certPath := filepath.Join(directory, "server.crt")
	keyPath := filepath.Join(directory, "server.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}
