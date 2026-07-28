package testdb

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

var schemaSequence atomic.Uint64

// URL creates an isolated PostgreSQL schema and returns a connection URL that
// uses it as the default search path. Tests are skipped when no test database
// has been configured.
func URL(t testing.TB) string {
	t.Helper()
	base := os.Getenv("LUX_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("LUX_TEST_DATABASE_URL is required for PostgreSQL integration tests")
	}
	parsed, err := url.Parse(base)
	if err != nil || parsed.Scheme == "" {
		t.Fatalf("parse LUX_TEST_DATABASE_URL: %v", err)
	}

	schema := fmt.Sprintf("lux_test_%d_%d", os.Getpid(), schemaSequence.Add(1))
	admin, err := sql.Open("pgx", base)
	if err != nil {
		t.Fatalf("open test PostgreSQL database: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA "`+schema+`"`); err != nil {
		_ = admin.Close()
		t.Fatalf("create test PostgreSQL schema: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		if _, err := admin.ExecContext(cleanupCtx, `DROP SCHEMA IF EXISTS "`+schema+`" CASCADE`); err != nil {
			t.Errorf("drop test PostgreSQL schema: %v", err)
		}
		if err := admin.Close(); err != nil {
			t.Errorf("close test PostgreSQL connection: %v", err)
		}
	})

	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}
