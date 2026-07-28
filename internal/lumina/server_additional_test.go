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

	"github.com/segfaultd/lux/internal/auth"
	"github.com/segfaultd/lux/internal/config"
	"github.com/segfaultd/lux/internal/observability"
	"github.com/segfaultd/lux/internal/protocol"
	"github.com/segfaultd/lux/internal/session"
	"github.com/segfaultd/lux/internal/store"
	"github.com/segfaultd/lux/internal/testdb"
)

func TestHelloVariantsAndWrongPort(t *testing.T) {
	t.Run("legacy protocol gets OK", func(t *testing.T) {
		server := newLuminaTestServer(t, config.Config{Username: "guest"})
		conn, done := startDirectConnection(server)
		sendHello(t, conn, 4, &protocol.Credentials{Username: "guest"})
		packet := readPacket(t, conn)
		if packet.Code != protocol.CodeOK || len(packet.Payload) != 0 {
			t.Fatalf("unexpected hello response: %#v", packet)
		}
		conn.Close()
		waitConnection(t, done)
	})

	t.Run("credentials required", func(t *testing.T) {
		server := newLuminaTestServer(t, config.Config{ServerName: "unit"})
		conn, done := startDirectConnection(server)
		sendHello(t, conn, 5, nil)
		assertFailure(t, readPacket(t, conn), 1, "required")
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
				ServerName: "unit", Username: "guest", Password: "valid secret",
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
		sendHello(t, conn, 5, &protocol.Credentials{Username: "guest"})
		if packet := readPacket(t, conn); packet.Code != protocol.CodeHelloResult {
			t.Fatalf("hello code %#x", packet.Code)
		}
		waitConnection(t, done)
		conn.Close()
	})
}

func TestAuthenticatedConnectionSessionLifecycle(t *testing.T) {
	server := newLuminaTestServer(t, config.Config{
		HelloWait: time.Second, CommandWait: time.Second,
	})
	conn, done := startDirectConnection(server)
	sendHello(t, conn, 5, &protocol.Credentials{Username: "guest"})
	if packet := readPacket(t, conn); packet.Code != protocol.CodeHelloResult {
		t.Fatalf("hello code %#x", packet.Code)
	}
	active := waitForSessions(t, server, 1)
	if active[0].Username != "guest" || !active[0].IsAdmin || !active[0].CanDeleteHistory ||
		active[0].ProtocolVersion != 5 || active[0].RemoteAddress == "" ||
		active[0].BytesRead == 0 || active[0].BytesWritten == 0 {
		t.Fatalf("authenticated session %#v", active[0])
	}

	if err := protocol.WritePacket(conn, protocol.CodePushMetadata, emptyPushRequest()); err != nil {
		t.Fatal(err)
	}
	if packet := readPacket(t, conn); packet.Code != protocol.CodePushMetadataResult {
		t.Fatalf("push response %#x", packet.Code)
	}
	active = waitForSessionOperation(t, server, "push_metadata")
	if active[0].Hostname != "role-host" || active[0].Requests != 1 ||
		active[0].CurrentOperation != "" || active[0].BytesRead == 0 || active[0].BytesWritten == 0 {
		t.Fatalf("completed session request %#v", active[0])
	}

	if err := protocol.WritePacket(conn, 0x7e, nil); err != nil {
		t.Fatal(err)
	}
	assertFailure(t, readPacket(t, conn), 0, "invalid command")
	active = waitForSessionOperation(t, server, "unknown_0x7e")
	if active[0].Requests != 2 || active[0].Errors != 1 {
		t.Fatalf("failed session request %#v", active[0])
	}
	conn.Close()
	waitConnection(t, done)
	waitForSessions(t, server, 0)
}

func TestDynamicDatabaseAuthentication(t *testing.T) {
	db, err := store.Open(testdb.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	authService := auth.New(db)
	if err := authService.Bootstrap(context.Background(), "guest", "initial password"); err != nil {
		t.Fatal(err)
	}
	if _, err := authService.Create(context.Background(), "analyst", "analyst password"); err != nil {
		t.Fatal(err)
	}
	server := testServerWithStore(t, config.Config{
		ServerName: "unit", Username: "ignored-static-value", Password: "ignored-static-value",
		HelloWait: time.Second, CommandWait: time.Second,
	}, db)

	for _, credentials := range []protocol.Credentials{
		{Username: "guest", Password: "initial password"},
		{Username: "ANALYST", Password: "analyst password"},
	} {
		conn, done := startDirectConnection(server)
		sendHello(t, conn, 5, &credentials)
		if packet := readPacket(t, conn); packet.Code != protocol.CodeHelloResult {
			t.Fatalf("%s login response %#x", credentials.Username, packet.Code)
		}
		conn.Close()
		waitConnection(t, done)
	}

	if _, err := authService.SetPassword(context.Background(), "analyst", "rotated password"); err != nil {
		t.Fatal(err)
	}
	conn, done := startDirectConnection(server)
	sendHello(t, conn, 5, &protocol.Credentials{Username: "analyst", Password: "analyst password"})
	assertFailure(t, readPacket(t, conn), 1, "invalid username")
	conn.Close()
	waitConnection(t, done)

	if _, err := authService.SetEnabled(context.Background(), "analyst", false); err != nil {
		t.Fatal(err)
	}
	conn, done = startDirectConnection(server)
	sendHello(t, conn, 5, &protocol.Credentials{Username: "analyst", Password: "rotated password"})
	assertFailure(t, readPacket(t, conn), 1, "invalid username")
	conn.Close()
	waitConnection(t, done)

	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	conn, done = startDirectConnection(server)
	sendHello(t, conn, 5, &protocol.Credentials{Username: "guest", Password: "initial password"})
	assertFailure(t, readPacket(t, conn), 3, "authentication database")
	conn.Close()
	waitConnection(t, done)
}

func TestAuthenticationFailuresAreAudited(t *testing.T) {
	db, err := store.Open(testdb.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := auth.New(db).Bootstrap(context.Background(), "guest", "valid password"); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	server := New(
		config.Config{ServerName: "unit", HelloWait: time.Second},
		db,
		observability.NewMetrics(),
		slog.New(slog.NewTextHandler(&logs, nil)),
	)
	conn, done := startDirectConnection(server)
	sendHello(t, conn, 5, &protocol.Credentials{Username: "guest", Password: "wrong password"})
	assertFailure(t, readPacket(t, conn), 1, "invalid username")
	conn.Close()
	waitConnection(t, done)
	if output := logs.String(); !strings.Contains(output, "Lumina authentication failed") ||
		!strings.Contains(output, "username=guest") {
		t.Fatalf("authentication failure was not audited: %s", output)
	}
}

func TestOfficialUserCapabilitiesAreEnforced(t *testing.T) {
	db, hash := populatedLuminaStore(t)
	authService := auth.New(db)
	if err := authService.Bootstrap(context.Background(), "admin", "admin password"); err != nil {
		t.Fatal(err)
	}
	if _, err := authService.Create(
		context.Background(), "regular", "regular password",
	); err != nil {
		t.Fatal(err)
	}
	if _, err := authService.CreateWithProfile(
		context.Background(), "deleter", "deleter password", store.AuthAccountProfile{
			CanDeleteHistory: true,
		},
	); err != nil {
		t.Fatal(err)
	}
	server := testServerWithStore(t, config.Config{
		ServerName: "unit", Username: "ignored", AllowDeletes: true, HistoryLimit: 10,
		HelloWait: time.Second, CommandWait: time.Second, PullWait: time.Second,
	}, db)

	regular, regularDone := startDirectConnection(server)
	sendHello(t, regular, 5, &protocol.Credentials{Username: "regular", Password: "regular password"})
	if features := helloFeatures(t, readPacket(t, regular)); features&0x02 != 0 {
		t.Fatalf("regular user received delete feature %#x", features)
	}
	if err := protocol.WritePacket(regular, protocol.CodePullMetadata, pullRequest(hash)); err != nil {
		t.Fatal(err)
	}
	if packet := readPacket(t, regular); packet.Code != protocol.CodePullMetadataResult {
		t.Fatalf("regular pull response %#x", packet.Code)
	}
	if err := protocol.WritePacket(regular, protocol.CodePushMetadata, emptyPushRequest()); err != nil {
		t.Fatal(err)
	}
	if packet := readPacket(t, regular); packet.Code != protocol.CodePushMetadataResult {
		t.Fatalf("regular push response %#x", packet.Code)
	}
	if err := protocol.WritePacket(regular, protocol.CodeGetFuncHistories, historyRequest(hash)); err != nil {
		t.Fatal(err)
	}
	if packet := readPacket(t, regular); packet.Code != protocol.CodeGetFuncHistoriesResult {
		t.Fatalf("regular history response %#x", packet.Code)
	}
	if err := protocol.WritePacket(regular, protocol.CodeDeleteHistory, deleteRequest(hash)); err != nil {
		t.Fatal(err)
	}
	assertFailure(t, readPacket(t, regular), 2, "permission denied")
	regular.Close()
	waitConnection(t, regularDone)

	deleter, deleterDone := startDirectConnection(server)
	sendHello(t, deleter, 5, &protocol.Credentials{Username: "deleter", Password: "deleter password"})
	if features := helloFeatures(t, readPacket(t, deleter)); features&0x02 == 0 {
		t.Fatalf("history deleter did not receive delete feature %#x", features)
	}
	if err := protocol.WritePacket(deleter, protocol.CodeDeleteHistory, deleteRequest(hash)); err != nil {
		t.Fatal(err)
	}
	if packet := readPacket(t, deleter); packet.Code != protocol.CodeDeleteHistoryResult {
		t.Fatalf("history deleter response %#x", packet.Code)
	}
	deleter.Close()
	waitConnection(t, deleterDone)

	admin, adminDone := startDirectConnection(server)
	sendHello(t, admin, 5, &protocol.Credentials{Username: "admin", Password: "admin password"})
	if features := helloFeatures(t, readPacket(t, admin)); features&0x02 == 0 {
		t.Fatalf("admin did not receive delete feature %#x", features)
	}
	if err := protocol.WritePacket(admin, protocol.CodeDeleteHistory, deleteRequest(hash)); err != nil {
		t.Fatal(err)
	}
	if packet := readPacket(t, admin); packet.Code != protocol.CodeDeleteHistoryResult {
		t.Fatalf("admin delete response %#x", packet.Code)
	}
	admin.Close()
	waitConnection(t, adminDone)
}

func TestOfficialPopularFunctionsAndServerInfoRPCs(t *testing.T) {
	db, hash := populatedLuminaStore(t)
	if err := auth.New(db).Bootstrap(context.Background(), "guest", "guest password"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pull(context.Background(), [][]byte{hash}); err != nil {
		t.Fatal(err)
	}
	server := testServerWithStore(t, config.Config{
		ServerName: "unit", Password: "guest password", AllowDeletes: true,
		HelloWait: time.Second, CommandWait: time.Second, PullWait: time.Second,
	}, db)
	conn, done := startDirectConnection(server)
	sendHello(t, conn, 5, &protocol.Credentials{Username: "guest", Password: "guest password"})
	hello := readPacket(t, conn)
	if hello.Code != protocol.CodeHelloResult {
		t.Fatalf("hello response %#x", hello.Code)
	}
	helloDecoder := protocol.NewDecoder(hello.Payload)
	licenseID, _ := helloDecoder.CString()
	licenseName, _ := helloDecoder.CString()
	email, _ := helloDecoder.CString()
	username, _ := helloDecoder.CString()
	_, _ = helloDecoder.DD()
	_, _ = helloDecoder.DQ()
	features, _ := helloDecoder.DD()
	if licenseID != "" || licenseName != "guest" || email != "" ||
		username != "guest" ||
		features != protocol.UserIsAdmin|protocol.UserCanDeleteHistory {
		t.Fatalf("hello user profile %q %q %q %q %#x",
			licenseID, licenseName, email, username, features)
	}

	var popularRequest protocol.Encoder
	popularRequest.DD(1)
	if err := protocol.WritePacket(
		conn, protocol.CodeGetPopular, popularRequest.Payload(),
	); err != nil {
		t.Fatal(err)
	}
	popular := readPacket(t, conn)
	if popular.Code != protocol.CodeGetPopularResult {
		t.Fatalf("popular response %#x", popular.Code)
	}
	decoder := protocol.NewDecoder(popular.Payload)
	count, _ := decoder.DD()
	name, _ := decoder.CString()
	length, _ := decoder.DD()
	_, _ = decoder.Bytes()
	patternType, _ := decoder.DD()
	pattern, _ := decoder.Bytes()
	frequency, _ := decoder.DD()
	hostname, _ := decoder.CString()
	filePath, _ := decoder.CString()
	_, _ = decoder.Fixed(16)
	address, _ := decoder.DQ()
	if count != 1 || name != "known" || length != 12 || patternType != 1 ||
		!bytes.Equal(pattern, hash) || frequency != 1 || hostname != "host" ||
		filePath != "sample.bin" || address != 0x401000 || decoder.Remaining() != 0 {
		t.Fatalf("popular result count=%d name=%q frequency=%d address=%#x",
			count, name, frequency, address)
	}

	if err := protocol.WritePacket(conn, protocol.CodeGetLuminaInfo, nil); err != nil {
		t.Fatal(err)
	}
	info := readPacket(t, conn)
	if info.Code != protocol.CodeGetLuminaInfoResult {
		t.Fatalf("info response %#x", info.Code)
	}
	decoder = protocol.NewDecoder(info.Payload)
	sessionID, _ := decoder.DD()
	peerName, _ := decoder.CString()
	for range 3 {
		_, _ = decoder.CString()
	}
	infoUsername, _ := decoder.CString()
	_, _ = decoder.DD()
	_, _ = decoder.DQ()
	infoFeatures, _ := decoder.DD()
	established, _ := decoder.DQ()
	_, _ = decoder.CString()
	version, _ := decoder.CString()
	started, _ := decoder.DQ()
	current, _ := decoder.DQ()
	if sessionID == 0 || peerName == "" || infoUsername != "guest" ||
		infoFeatures != features || established == 0 || version != "lux" ||
		started == 0 || current < started || decoder.Remaining() != 0 {
		t.Fatalf("server info session=%d peer=%q user=%q version=%q times=%d/%d",
			sessionID, peerName, infoUsername, version, started, current)
	}

	if err := protocol.WritePacket(conn, protocol.CodeGetLuminaInfo, []byte{1}); err != nil {
		t.Fatal(err)
	}
	assertFailure(t, readPacket(t, conn), 0, "invalid server-information")
	conn.Close()
	waitConnection(t, done)
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
		{"malformed popular", protocol.CodeGetPopular, nil, "invalid popular-functions"},
		{"malformed info", protocol.CodeGetLuminaInfo, []byte{1}, "invalid server-information"},
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
		server := testServerWithStore(t, config.Config{
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
	server := testServerWithStore(t, config.Config{
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
	db, err := store.Open(testdb.URL(t))
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
	return testServerWithStore(t, cfg, db)
}

func testServerWithStore(t *testing.T, cfg config.Config, db *store.Store) *Server {
	t.Helper()
	if cfg.Username == "" {
		cfg.Username = "guest"
	}
	if cfg.Password == "" {
		cfg.Password = "test password"
	}
	if err := auth.New(db).Bootstrap(context.Background(), cfg.Username, cfg.Password); err != nil {
		t.Fatal(err)
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
		if creds.Password == "" {
			creds = &protocol.Credentials{Username: creds.Username, Password: "test password"}
		}
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

func waitForSessions(t *testing.T, server *Server, count int) []session.Session {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		active := server.Sessions().List()
		if len(active) == count {
			return active
		}
		if time.Now().After(deadline) {
			t.Fatalf("active sessions = %d, want %d: %#v", len(active), count, active)
		}
		time.Sleep(time.Millisecond)
	}
}

func waitForSessionOperation(t *testing.T, server *Server, operation string) []session.Session {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		active := server.Sessions().List()
		if len(active) == 1 && active[0].LastOperation == operation {
			return active
		}
		if time.Now().After(deadline) {
			t.Fatalf("last operation did not become %q: %#v", operation, active)
		}
		time.Sleep(time.Millisecond)
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

func pullRequest(hash []byte) []byte {
	var e protocol.Encoder
	e.DD(0)
	e.U32s(nil)
	e.DD(1)
	e.DD(0)
	e.Bytes(hash)
	return append([]byte(nil), e.Payload()...)
}

func emptyPushRequest() []byte {
	var e protocol.Encoder
	e.DD(0)
	e.CString("roles.i64")
	e.CString("roles.bin")
	e.Fixed(make([]byte, 16))
	e.CString("role-host")
	e.DD(0)
	e.DD(0)
	return append([]byte(nil), e.Payload()...)
}

func helloFeatures(t *testing.T, packet protocol.Packet) uint32 {
	t.Helper()
	if packet.Code != protocol.CodeHelloResult {
		t.Fatalf("hello response code %#x", packet.Code)
	}
	d := protocol.NewDecoder(packet.Payload)
	for range 4 {
		if _, err := d.CString(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.DD(); err != nil {
		t.Fatal(err)
	}
	if _, err := d.DQ(); err != nil {
		t.Fatal(err)
	}
	features, err := d.DD()
	if err != nil {
		t.Fatal(err)
	}
	return features
}

func populatedLuminaStore(t *testing.T) (*store.Store, []byte) {
	t.Helper()
	db, err := store.Open(testdb.URL(t))
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
		Addresses: []uint64{0x401000},
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
