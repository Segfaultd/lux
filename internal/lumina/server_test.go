package lumina

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/segfaultd/lux/internal/config"
	"github.com/segfaultd/lux/internal/observability"
	"github.com/segfaultd/lux/internal/protocol"
	"github.com/segfaultd/lux/internal/store"
)

func TestHelloPushPullRoundTrip(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "lux.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cfg := config.Config{
		ServerName: "lux-test", Username: "guest", HistoryLimit: 10,
		HelloWait: time.Second, CommandWait: time.Second, PullWait: time.Second,
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
	hello.CString("anything")
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
