package store

import (
	"bytes"
	"context"
	"testing"

	"github.com/segfaultd/lux/internal/protocol"
	"github.com/segfaultd/lux/internal/testdb"
)

func TestPushLedgerAndImmutableFunctionChanges(t *testing.T) {
	s, err := Open(testdb.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()
	hash := bytes.Repeat([]byte{0xa1}, 16)
	request := protocol.PushMetadata{
		IDBPath: "history.i64", FilePath: "/samples/history.bin", MD5: [16]byte{0xb2},
		Funcs: []protocol.PushFunction{{
			Name: "first_name", Length: 32, Hash: hash, Metadata: []byte{1, 2},
		}},
	}
	identity := PushIdentity{
		LicenseNumber: []byte("license"), LicenseData: []byte("data"),
		Hostname: "history-host", Username: "historian", Protocol: 5,
	}
	if status, err := s.Push(ctx, identity, request); err != nil || status[0] != 1 {
		t.Fatalf("initial push = %v, %v", status, err)
	}
	if status, err := s.Push(ctx, identity, request); err != nil || status[0] != 0 {
		t.Fatalf("identical push = %v, %v", status, err)
	}
	request.Funcs[0].Name = "second_name"
	request.Funcs[0].Metadata = []byte{3, 4}
	if status, err := s.Push(ctx, identity, request); err != nil || status[0] != 0 {
		t.Fatalf("changed push = %v, %v", status, err)
	}

	stats, err := s.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Pushes != 3 || stats.HistoryRecords != 2 {
		t.Fatalf("ledger stats = %#v", stats)
	}
	history, err := s.Histories(ctx, hash, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 2 || history[0].Name != "second_name" || history[1].Name != "first_name" {
		t.Fatalf("history = %#v", history)
	}
	var protocolVersion, submitted, changed int
	var source string
	if err := s.db.QueryRowContext(ctx, `
SELECT protocol_version, source, submitted_functions, changed_functions
FROM pushes ORDER BY id LIMIT 1`).Scan(&protocolVersion, &source, &submitted, &changed); err != nil {
		t.Fatal(err)
	}
	if protocolVersion != 5 || source != "native" || submitted != 1 || changed != 1 {
		t.Fatalf("push record = protocol %d source %q submitted %d changed %d",
			protocolVersion, source, submitted, changed)
	}
	var unchangedPushID int64
	var unchanged int
	if err := s.db.QueryRowContext(ctx,
		"SELECT id, changed_functions FROM pushes ORDER BY id OFFSET 1 LIMIT 1").
		Scan(&unchangedPushID, &unchanged); err != nil {
		t.Fatal(err)
	}
	if unchanged != 0 {
		t.Fatalf("identical push recorded %d changes", unchanged)
	}
	unchangedPush, err := s.PushRecord(ctx, unchangedPushID)
	if err != nil || len(unchangedPush.Changes) != 0 {
		t.Fatalf("unchanged push detail = %#v, %v", unchangedPush, err)
	}

	versions, err := s.Function(ctx, bytesToHex(hash))
	if err != nil || len(versions) != 1 {
		t.Fatalf("versions = %#v, %v", versions, err)
	}
	if _, err := s.UpdateFunctionVersion(ctx, versions[0].ID, "admin_name", 48, []byte{5, 6}); err != nil {
		t.Fatal(err)
	}
	stats, err = s.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Pushes != 4 || stats.HistoryRecords != 3 {
		t.Fatalf("admin ledger stats = %#v", stats)
	}
	if _, err := s.UpdateFunctionVersion(ctx, versions[0].ID, "admin_name", 48, []byte{5, 6}); err != nil {
		t.Fatal(err)
	}
	unchangedStats, err := s.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if unchangedStats.Pushes != stats.Pushes || unchangedStats.HistoryRecords != stats.HistoryRecords {
		t.Fatalf("identical admin save created history: before=%#v after=%#v", stats, unchangedStats)
	}
	var operation string
	if err := s.db.QueryRowContext(ctx,
		"SELECT operation FROM function_changes ORDER BY id DESC LIMIT 1").Scan(&operation); err != nil {
		t.Fatal(err)
	}
	if operation != "admin-edit" {
		t.Fatalf("admin operation = %q", operation)
	}
	deleted, err := s.DeletePush(ctx, unchangedPushID)
	if err != nil || !deleted.Found || deleted.DeletedChanges != 0 {
		t.Fatalf("delete unchanged push = %#v, %v", deleted, err)
	}
}

func TestHistoryMigrationBackfillsOnce(t *testing.T) {
	s, _, _, _ := populatedStore(t)
	ctx := context.Background()
	if _, err := s.db.ExecContext(ctx, "DELETE FROM pushes"); err != nil {
		t.Fatal(err)
	}
	var changes int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM function_changes").Scan(&changes); err != nil {
		t.Fatal(err)
	}
	if changes != 0 {
		t.Fatalf("push cascade left %d changes", changes)
	}
	if err := s.migrate(ctx); err != nil {
		t.Fatal(err)
	}
	first, err := s.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if first.Pushes != first.Databases || first.HistoryRecords != first.Versions {
		t.Fatalf("backfill stats = %#v", first)
	}
	if err := s.migrate(ctx); err != nil {
		t.Fatal(err)
	}
	second, err := s.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if second.Pushes != first.Pushes || second.HistoryRecords != first.HistoryRecords {
		t.Fatalf("migration duplicated history: first=%#v second=%#v", first, second)
	}
}
