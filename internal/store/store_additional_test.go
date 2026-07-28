package store

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/segfaultd/lux/internal/protocol"
	"github.com/segfaultd/lux/internal/testdb"
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
	if _, err := s.Pull(ctx, [][]byte{firstHash, secondHash}); err != nil {
		t.Fatal(err)
	}
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
	var frequencies int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM function_frequencies").Scan(&frequencies); err != nil {
		t.Fatal(err)
	}
	if frequencies != 0 {
		t.Fatalf("orphan frequencies remained: %d", frequencies)
	}
}

func TestStoreValidationAndClosedDatabaseErrors(t *testing.T) {
	if _, err := Open("postgres://lux:lux@127.0.0.1:1/lux?sslmode=disable&connect_timeout=1"); err == nil {
		t.Fatal("unreachable PostgreSQL server unexpectedly opened")
	}
	if _, err := parseHash("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"); err == nil {
		t.Fatal("invalid hexadecimal hash accepted")
	}
	if _, err := parseHash("abcd"); err == nil {
		t.Fatal("short hash accepted")
	}

	s, err := Open(testdb.URL(t))
	if err != nil {
		t.Fatal(err)
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
		{"user stats", func() error { _, err := s.StatsForUsers(ctx, []string{"user"}); return err }},
		{"pull", func() error { _, err := s.Pull(ctx, [][]byte{hash}); return err }},
		{"popular functions", func() error { _, err := s.PopularFunctions(ctx, 10); return err }},
		{"push", func() error { _, err := s.Push(ctx, identity, push); return err }},
		{"delete", func() error { _, err := s.DeleteHashes(ctx, [][]byte{hash}); return err }},
		{"histories", func() error { _, err := s.Histories(ctx, hash, 1); return err }},
		{"list functions", func() error { _, err := s.ListFunctions(ctx, "", 1, 0); return err }},
		{"function", func() error { _, err := s.Function(ctx, bytesToHex(hash)); return err }},
		{"list files", func() error { _, err := s.ListFiles(ctx, "", 1, 0); return err }},
		{"file functions", func() error { _, err := s.FileFunctions(ctx, bytesToHex(md5[:])); return err }},
		{"files with function", func() error { _, err := s.FilesWithFunction(ctx, bytesToHex(hash)); return err }},
		{"list projects", func() error { _, err := s.ListProjects(ctx, "", 1, 0); return err }},
		{"project", func() error { _, err := s.Project(ctx, 1); return err }},
		{"update project", func() error { _, err := s.UpdateProject(ctx, 1, "a", "b"); return err }},
		{"delete project", func() error { _, err := s.DeleteProject(ctx, 1); return err }},
		{"function version", func() error { _, err := s.FunctionVersion(ctx, 1); return err }},
		{"update function version", func() error { _, err := s.UpdateFunctionVersion(ctx, 1, "a", 1, nil); return err }},
		{"delete function version", func() error { _, err := s.DeleteFunctionVersion(ctx, 1); return err }},
		{"list pushes", func() error { _, err := s.ListPushes(ctx, PushFilter{}, 1, 0); return err }},
		{"push record", func() error { _, err := s.PushRecord(ctx, 1); return err }},
		{"list history", func() error { _, err := s.ListHistory(ctx, HistoryFilter{}, 1, 0); return err }},
		{"function change", func() error { _, err := s.FunctionChange(ctx, 1); return err }},
		{"function change diff", func() error { _, err := s.FunctionChangeDiff(ctx, 1); return err }},
		{"restore function change", func() error { _, err := s.RestoreFunctionChange(ctx, 1); return err }},
		{"delete function change", func() error { _, err := s.DeleteFunctionChange(ctx, 1); return err }},
		{"delete push", func() error { _, err := s.DeletePush(ctx, 1); return err }},
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
	s, err := Open(testdb.URL(t))
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

func TestPushNormalizesNilIdentityAndMigrationIsIdempotent(t *testing.T) {
	s, err := Open(testdb.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if err := s.migrate(ctx); err != nil {
		t.Fatalf("repeat migration: %v", err)
	}
	request := protocol.PushMetadata{
		IDBPath:  "nil-identity.i64",
		FilePath: "nil-identity.bin",
		Funcs: []protocol.PushFunction{{
			Name: "nil_identity",
			Hash: bytes.Repeat([]byte{0x7f}, 16),
		}},
	}
	status, err := s.Push(ctx, PushIdentity{}, request)
	if err != nil {
		t.Fatal(err)
	}
	if len(status) != 1 || status[0] != 1 {
		t.Fatalf("unexpected push status: %v", status)
	}
	stats, err := s.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Users != 1 || stats.Functions != 1 {
		t.Fatalf("unexpected stats: %#v", stats)
	}
}

func TestPushSeparatesAuthenticationAccountsForTheSameIDB(t *testing.T) {
	s, err := Open(testdb.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	alice, err := s.CreateAuthAccount(ctx, "alice", []byte("hash"))
	if err != nil {
		t.Fatal(err)
	}
	bob, err := s.CreateAuthAccount(ctx, "bob", []byte("hash"))
	if err != nil {
		t.Fatal(err)
	}
	hash := bytes.Repeat([]byte{0x6a}, 16)
	request := protocol.PushMetadata{
		IDBPath: "shared.i64", FilePath: "shared.bin",
		Funcs: []protocol.PushFunction{{Name: "shared_function", Hash: hash}},
	}
	identity := PushIdentity{
		LicenseNumber: []byte{1}, LicenseData: []byte{2}, Hostname: "shared-host",
		AccountID: alice.ID, Username: alice.Username,
	}
	status, err := s.Push(ctx, identity, request)
	if err != nil || len(status) != 1 || status[0] != 1 {
		t.Fatalf("alice push %v: %v", status, err)
	}
	identity.AccountID, identity.Username = bob.ID, bob.Username
	status, err = s.Push(ctx, identity, request)
	if err != nil || len(status) != 1 || status[0] != 0 {
		t.Fatalf("bob push %v: %v", status, err)
	}
	versions, err := s.Function(ctx, bytesToHex(hash))
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 2 {
		t.Fatalf("account-specific versions: %#v", versions)
	}
	usernames := map[string]bool{versions[0].Username: true, versions[1].Username: true}
	if !usernames["alice"] || !usernames["bob"] {
		t.Fatalf("account attribution: %#v", versions)
	}
	if _, err := s.DeleteAuthAccount(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	versions, err = s.Function(ctx, bytesToHex(hash))
	if err != nil || len(versions) != 2 {
		t.Fatalf("versions after account deletion: %#v, %v", versions, err)
	}
	usernames = map[string]bool{versions[0].Username: true, versions[1].Username: true}
	if !usernames["alice"] || !usernames["bob"] {
		t.Fatalf("historical attribution after account deletion: %#v", versions)
	}
}

func populatedStore(t *testing.T) (*Store, []byte, []byte, [16]byte) {
	t.Helper()
	s, err := Open(testdb.URL(t))
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
