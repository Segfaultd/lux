package store

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/segfaultd/lux/internal/protocol"
)

func TestFileHistoryAndSearchQueries(t *testing.T) {
	s, firstHash, secondHash, fileMD5 := populatedStore(t)
	ctx := context.Background()

	histories, err := s.Histories(ctx, firstHash, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(histories) != 2 || histories[0].Name != "best_function" {
		t.Fatalf("unexpected histories: %#v", histories)
	}
	if empty, err := s.Histories(ctx, bytes.Repeat([]byte{0xee}, 16), 10); err != nil || len(empty) != 0 {
		t.Fatalf("missing histories: %#v, %v", empty, err)
	}

	files, err := s.ListFiles(ctx, "sample", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || !strings.EqualFold(files[0].MD5, bytesToHex(fileMD5[:])) || files[0].Functions != 2 {
		t.Fatalf("unexpected files: %#v", files)
	}
	if empty, err := s.ListFiles(ctx, "does-not-exist", 50, 0); err != nil || len(empty) != 0 {
		t.Fatalf("missing file search: %#v, %v", empty, err)
	}
	// Invalid pagination values exercise the server-side defaults.
	if _, err := s.ListFiles(ctx, "", 0, -1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ListFunctions(ctx, "", 1000, -1); err != nil {
		t.Fatal(err)
	}

	functions, err := s.FileFunctions(ctx, bytesToHex(fileMD5[:]))
	if err != nil {
		t.Fatal(err)
	}
	if len(functions) != 3 {
		t.Fatalf("file should expose all versions, got %#v", functions)
	}
	if _, err := s.FileFunctions(ctx, "not-a-hash"); err == nil {
		t.Fatal("invalid file hash accepted")
	}

	containing, err := s.FilesWithFunction(ctx, bytesToHex(firstHash))
	if err != nil {
		t.Fatal(err)
	}
	if len(containing) != 1 || !strings.EqualFold(containing[0], bytesToHex(fileMD5[:])) {
		t.Fatalf("unexpected containing files: %v", containing)
	}
	if _, err := s.FilesWithFunction(ctx, "short"); err == nil {
		t.Fatal("invalid function hash accepted")
	}
	missing, err := s.FilesWithFunction(ctx, bytesToHex(bytes.Repeat([]byte{0x99}, 16)))
	if err != nil || len(missing) != 0 {
		t.Fatalf("unexpected missing containing files: %v, %v", missing, err)
	}

	versions, err := s.Function(ctx, bytesToHex(secondHash))
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 1 || versions[0].Name != "second_function" {
		t.Fatalf("unexpected second function: %#v", versions)
	}
	missingVersions, err := s.Function(ctx, bytesToHex(bytes.Repeat([]byte{0xfe}, 16)))
	if err != nil || len(missingVersions) != 0 {
		t.Fatalf("unexpected missing function: %#v, %v", missingVersions, err)
	}
}

func TestDeleteCleanupAndEmptyDelete(t *testing.T) {
	s, firstHash, secondHash, _ := populatedStore(t)
	ctx := context.Background()
	if deleted, err := s.DeleteHashes(ctx, nil); err != nil || deleted != 0 {
		t.Fatalf("empty delete: %d, %v", deleted, err)
	}
	if deleted, err := s.DeleteHashes(ctx, [][]byte{bytes.Repeat([]byte{0xfa}, 16)}); err != nil || deleted != 0 {
		t.Fatalf("missing delete: %d, %v", deleted, err)
	}
	if deleted, err := s.DeleteHashes(ctx, [][]byte{firstHash, secondHash}); err != nil || deleted != 3 {
		t.Fatalf("delete all: %d, %v", deleted, err)
	}
	stats, err := s.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats != (Stats{}) {
		t.Fatalf("orphan cleanup failed: %#v", stats)
	}
}

func TestStoreValidationAndClosedDatabaseErrors(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "missing", "lux.db")); err == nil {
		t.Fatal("database in missing parent unexpectedly opened")
	}
	if _, err := parseHash("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"); err == nil {
		t.Fatal("invalid hexadecimal hash accepted")
	}
	if _, err := parseHash("abcd"); err == nil {
		t.Fatal("short hash accepted")
	}

	pathWithSpace := filepath.Join(t.TempDir(), "lux data.db")
	s, err := Open(pathWithSpace)
	if err != nil {
		t.Fatalf("database path with spaces: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	hash := bytes.Repeat([]byte{1}, 16)
	md5 := [16]byte{2}
	push := protocol.PushMetadata{
		IDBPath: "a.i64", FilePath: "a.bin", MD5: md5, Hostname: "host",
		Funcs: []protocol.PushFunction{{Name: "a", Hash: hash}},
	}
	identity := PushIdentity{LicenseNumber: []byte{1}, LicenseData: []byte{2}, Hostname: "host"}
	errorCalls := []struct {
		name string
		call func() error
	}{
		{"stats", func() error { _, err := s.Stats(ctx); return err }},
		{"pull", func() error { _, err := s.Pull(ctx, [][]byte{hash}); return err }},
		{"push", func() error { _, err := s.Push(ctx, identity, push); return err }},
		{"delete", func() error { _, err := s.DeleteHashes(ctx, [][]byte{hash}); return err }},
		{"histories", func() error { _, err := s.Histories(ctx, hash, 1); return err }},
		{"list functions", func() error { _, err := s.ListFunctions(ctx, "", 1, 0); return err }},
		{"function", func() error { _, err := s.Function(ctx, bytesToHex(hash)); return err }},
		{"list files", func() error { _, err := s.ListFiles(ctx, "", 1, 0); return err }},
		{"file functions", func() error { _, err := s.FileFunctions(ctx, bytesToHex(md5[:])); return err }},
		{"files with function", func() error { _, err := s.FilesWithFunction(ctx, bytesToHex(hash)); return err }},
	}
	for _, test := range errorCalls {
		t.Run(test.name, func(t *testing.T) {
			if err := test.call(); err == nil {
				t.Fatal("expected closed database error")
			}
		})
	}
	if err := s.Close(); err != nil {
		t.Fatalf("database close should be idempotent: %v", err)
	}
}

func TestPushCanceledContext(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "lux.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = s.Push(ctx, PushIdentity{}, protocol.PushMetadata{})
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context canceled", err)
	}
}

func populatedStore(t *testing.T) (*Store, []byte, []byte, [16]byte) {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "lux.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()
	firstHash := bytes.Repeat([]byte{0x11}, 16)
	secondHash := bytes.Repeat([]byte{0x22}, 16)
	fileMD5 := [16]byte{0xaa, 0xbb, 0xcc}
	identity := PushIdentity{
		LicenseNumber: []byte{1, 2, 3, 4, 5, 6},
		LicenseData:   []byte("license"),
		Hostname:      "workstation",
	}
	var comment protocol.Encoder
	comment.DD(3)
	comment.Bytes([]byte("useful note"))
	request := protocol.PushMetadata{
		IDBPath: "first.i64", FilePath: "/samples/sample.bin", MD5: fileMD5, Hostname: "workstation",
		Funcs: []protocol.PushFunction{
			{Name: "old_function", Length: 10, Hash: firstHash},
			{Name: "second_function", Length: 20, Hash: secondHash},
		},
	}
	if _, err := s.Push(ctx, identity, request); err != nil {
		t.Fatal(err)
	}
	request.IDBPath = "second.i64"
	request.Funcs = []protocol.PushFunction{{
		Name: "best_function", Length: 10, Hash: firstHash,
		Metadata: append([]byte(nil), comment.Payload()...),
	}}
	if _, err := s.Push(ctx, identity, request); err != nil {
		t.Fatal(err)
	}
	return s, firstHash, secondHash, fileMD5
}
