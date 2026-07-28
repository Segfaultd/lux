package main

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/segfaultd/lux/internal/testdb"
)

func TestRunValidationAndStartupErrors(t *testing.T) {
	t.Run("invalid configuration", func(t *testing.T) {
		if err := run(context.Background(), []string{"-tls-cert", "only-cert.pem"}); err == nil {
			t.Fatal("expected configuration error")
		}
	})
	t.Run("database error", func(t *testing.T) {
		err := run(context.Background(), []string{
			"-database-url", "postgres://lux:lux@127.0.0.1:1/lux?sslmode=disable&connect_timeout=1",
		})
		if err == nil || !strings.Contains(err.Error(), "open database") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("Lumina listener error", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		err = run(context.Background(), []string{
			"-database-url", testdb.URL(t),
			"-lumina-addr", listener.Addr().String(),
			"-http-addr", "127.0.0.1:0",
		})
		if err == nil || !strings.Contains(err.Error(), "listen for Lumina") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("HTTP listener error", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		err = run(context.Background(), []string{
			"-database-url", testdb.URL(t),
			"-lumina-addr", "127.0.0.1:0",
			"-http-addr", listener.Addr().String(),
		})
		if err == nil || !strings.Contains(err.Error(), "listen for management") {
			t.Fatalf("got %v", err)
		}
	})
}

func TestRunGracefulCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	databaseURL := testdb.URL(t)
	go func() {
		done <- run(ctx, []string{
			"-database-url", databaseURL,
			"-lumina-addr", "127.0.0.1:0",
			"-http-addr", "127.0.0.1:0",
			"-shutdown-timeout", "1s",
		})
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("run did not stop after context cancellation")
	}
}
