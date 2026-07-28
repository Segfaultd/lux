package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/segfaultd/lux/internal/auth"
	"github.com/segfaultd/lux/internal/config"
	"github.com/segfaultd/lux/internal/lumina"
	"github.com/segfaultd/lux/internal/observability"
	"github.com/segfaultd/lux/internal/store"
	management "github.com/segfaultd/lux/internal/web"
)

var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "lux:", err)
		os.Exit(1)
	}
}

func run(parent context.Context, args []string) error {
	cfg, err := config.Parse(args)
	if err != nil {
		return err
	}
	level := slog.LevelInfo
	if os.Getenv("LUX_LOG_LEVEL") == "debug" {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	db, err := store.Open(cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()
	if parent.Err() != nil {
		return nil
	}
	if err := auth.New(db).Bootstrap(parent, cfg.Username, cfg.Password); err != nil {
		return fmt.Errorf("bootstrap authentication account: %w", err)
	}

	luminaListener, err := net.Listen("tcp", cfg.LuminaAddr)
	if err != nil {
		return fmt.Errorf("listen for Lumina clients: %w", err)
	}
	defer luminaListener.Close()
	httpListener, err := net.Listen("tcp", cfg.HTTPAddr)
	if err != nil {
		return fmt.Errorf("listen for management HTTP: %w", err)
	}
	defer httpListener.Close()

	ctx, stop := context.WithCancel(parent)
	defer stop()
	metrics := observability.NewMetrics()
	luminaServer := lumina.New(cfg, db, metrics, log)
	webServer := management.New(cfg, db, metrics, log)
	httpServer := &http.Server{
		Handler:           webServer.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
	}

	errs := make(chan error, 2)
	go func() { errs <- luminaServer.Serve(ctx, luminaListener) }()
	go func() {
		err := httpServer.Serve(httpListener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errs <- err
	}()
	log.Info("Lux started",
		"version", version,
		"lumina", luminaListener.Addr(),
		"management", "http://"+httpListener.Addr().String(),
		"database", "postgresql",
		"tls", cfg.TLSCert != "")

	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-errs:
		stop()
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownWait)
	defer cancel()
	_ = httpServer.Shutdown(shutdownCtx)
	_ = luminaListener.Close()
	log.Info("Lux stopped")
	return serveErr
}
