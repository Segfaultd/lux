package lumina

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/segfaultd/lux/internal/auth"
	"github.com/segfaultd/lux/internal/config"
	"github.com/segfaultd/lux/internal/observability"
	"github.com/segfaultd/lux/internal/protocol"
	"github.com/segfaultd/lux/internal/store"
	"github.com/segfaultd/lux/internal/testdb"
)

func TestHelloPushPullRoundTrip(t *testing.T) {
	db, err := store.Open(testdb.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cfg := config.Config{
		ServerName: "lux-test", Username: "guest", Password: "test password", HistoryLimit: 10,
		HelloWait: time.Second, CommandWait: time.Second, PullWait: time.Second,
	}
	if err := auth.New(db).Bootstrap(context.Background(), cfg.Username, cfg.Password); err != nil {
		t.Fatal(err)
	}
	server := New(cfg, db, observability.NewMetrics(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	var hello protocol.Encoder
	hello.DD(5)
	hello.Bytes([]byte("license"))
	hello.Fixed([]byte{1, 2, 3, 4, 5, 6})
	hello.DD(0)
	hello.CString("guest")
	hello.CString("test password")
	if err := protocol.WritePacket(conn, protocol.CodeHello, hello.Payload()); err != nil {
		t.Fatal(err)
	}
	packet, err := protocol.ReadPacket(conn)
	if err != nil {
		t.Fatal(err)
	}
	if packet.Code != protocol.CodeHelloResult {
		t.Fatalf("hello response code %#x", packet.Code)
	}

	hash := bytes.Repeat([]byte{0x33}, 16)
	var push protocol.Encoder
	push.DD(0)
	push.CString("sample.i64")
	push.CString("/samples/sample.bin")
	push.Fixed(bytes.Repeat([]byte{0x44}, 16))
	push.CString("workstation")
	push.DD(1)
	push.CString("known_function")
	push.DD(64)
	push.Bytes(nil)
	push.DD(0)
	push.Bytes(hash)
	push.DD(0)
	if err := protocol.WritePacket(conn, protocol.CodePushMetadata, push.Payload()); err != nil {
		t.Fatal(err)
	}
	packet, err = protocol.ReadPacket(conn)
	if err != nil {
		t.Fatal(err)
	}
	if packet.Code != protocol.CodePushMetadataResult {
		t.Fatalf("push response code %#x", packet.Code)
	}
	versions, err := db.Function(context.Background(), strings.Repeat("33", 16))
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 1 || versions[0].Username != "guest" {
		t.Fatalf("push account attribution: %#v", versions)
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
	packet, err = protocol.ReadPacket(conn)
	if err != nil {
		t.Fatal(err)
	}
	if packet.Code != protocol.CodePullMetadataResult {
		t.Fatalf("pull response code %#x", packet.Code)
	}
	d := protocol.NewDecoder(packet.Payload)
	status, err := d.U32s(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(status) != 1 || status[0] != 0 {
		t.Fatalf("pull status %v", status)
	}
	count, err := d.Count(10)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("pull function count %d", count)
	}
	name, err := d.CString()
	if err != nil || name != "known_function" {
		t.Fatalf("pull name %q, error %v", name, err)
	}
	if _, err := d.DD(); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Bytes(); err != nil {
		t.Fatal(err)
	}
	frequency, err := d.DD()
	if err != nil || frequency != 1 {
		t.Fatalf("pull frequency %d, error %v", frequency, err)
	}
	cancel()
	_ = conn.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop")
	}
}
