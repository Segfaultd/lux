package store

import (
	"bytes"
	"context"
	"testing"

	"github.com/segfaultd/lux/internal/protocol"
	"github.com/segfaultd/lux/internal/testdb"
)

func TestPushPullAndManagementQueries(t *testing.T) {
	s, err := Open(testdb.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	hash := bytes.Repeat([]byte{0x42}, 16)
	fileMD5 := [16]byte{1, 2, 3}
	identity := PushIdentity{
		LicenseNumber: []byte{1, 2, 3, 4, 5, 6},
		LicenseData:   []byte("license"),
		Hostname:      "analyst-one",
	}
	account, err := s.CreateAuthAccount(ctx, "analyst", []byte("test-hash"))
	if err != nil {
		t.Fatal(err)
	}
	identity.AccountID = account.ID
	identity.Username = account.Username

	first := protocol.PushMetadata{
		IDBPath:  "first.i64",
		FilePath: "/samples/first.bin",
		MD5:      fileMD5,
		Hostname: identity.Hostname,
		Funcs: []protocol.PushFunction{{
			Name: "sub_1000", Length: 16, Hash: hash,
		}},
	}
	status, err := s.Push(ctx, identity, first)
	if err != nil {
		t.Fatal(err)
	}
	if len(status) != 1 || status[0] != 1 {
		t.Fatalf("first push status: %v", status)
	}

	var md protocol.Encoder
	md.DD(3)
	md.Bytes([]byte("recovered parser"))
	second := first
	second.IDBPath = "second.i64"
	second.Funcs = []protocol.PushFunction{{
		Name: "parse_header", Length: 16, Hash: hash, Metadata: append([]byte(nil), md.Payload()...),
	}}
	status, err = s.Push(ctx, identity, second)
	if err != nil {
		t.Fatal(err)
	}
	if status[0] != 0 {
		t.Fatalf("existing global function should return PDRES_OK: %v", status)
	}

	got, err := s.Pull(ctx, [][]byte{hash, bytes.Repeat([]byte{0x99}, 16)})
	if err != nil {
		t.Fatal(err)
	}
	if got[0] == nil || got[0].Name != "parse_header" || got[0].Popularity != 1 {
		t.Fatalf("best pull result: %#v", got[0])
	}
	if got[1] != nil {
		t.Fatalf("unknown hash returned: %#v", got[1])
	}

	stats, err := s.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Functions != 1 || stats.Versions != 2 || stats.Files != 1 {
		t.Fatalf("unexpected stats: %#v", stats)
	}
	list, err := s.ListFunctions(ctx, "parse", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Name != "parse_header" {
		t.Fatalf("unexpected function list: %#v", list)
	}
	versions, err := s.Function(ctx, bytesToHex(hash))
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 2 || len(versions[0].Comments) != 1 || versions[0].Username != "analyst" {
		t.Fatalf("unexpected versions: %#v", versions)
	}

	status, err = s.Push(ctx, identity, second)
	if err != nil {
		t.Fatal(err)
	}
	if status[0] != 0 {
		t.Fatalf("update should not be new: %v", status)
	}
	if _, err := s.CreateAuthAccount(ctx, "backup", []byte("test-hash")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteAuthAccount(ctx, "analyst"); err != nil {
		t.Fatal(err)
	}
	versions, err = s.Function(ctx, bytesToHex(hash))
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 2 || versions[0].Username != "analyst" {
		t.Fatalf("deleted account attribution was not preserved: %#v", versions)
	}
	deleted, err := s.DeleteHashes(ctx, [][]byte{hash})
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 2 {
		t.Fatalf("deleted %d versions, want 2", deleted)
	}
}

func TestPullFrequencyAndSeenFileFlag(t *testing.T) {
	s, err := Open(testdb.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	hash := bytes.Repeat([]byte{0x91}, 16)
	request := protocol.PushMetadata{
		IDBPath: "frequency.i64", FilePath: "frequency.bin",
		Funcs: []protocol.PushFunction{{Name: "popular", Hash: hash}},
	}
	if _, err := s.Push(ctx, PushIdentity{Hostname: "frequency-host"}, request); err != nil {
		t.Fatal(err)
	}
	assertFrequency := func(flags, want uint32) {
		t.Helper()
		result, err := s.PullWithFlags(ctx, [][]byte{hash, hash}, flags)
		if err != nil {
			t.Fatal(err)
		}
		if len(result) != 2 || result[0] == nil || result[1] == nil ||
			result[0].Popularity != want || result[1].Popularity != want {
			t.Fatalf("frequency result %#v, want %d", result, want)
		}
	}
	assertFrequency(0, 1)
	assertFrequency(0, 2)
	assertFrequency(protocol.PullSeenFile, 2)
}

func TestOfficialPushReplacementModes(t *testing.T) {
	s, err := Open(testdb.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	hash := bytes.Repeat([]byte{0x31}, 16)
	identity := PushIdentity{
		LicenseNumber: []byte{1}, LicenseData: []byte{2}, Hostname: "selection-host",
	}
	base := protocol.PushMetadata{
		IDBPath: "selection.i64", FilePath: "selection.bin", Hostname: identity.Hostname,
	}
	push := func(name string, comments []string, flags uint32) []uint32 {
		t.Helper()
		var encoded protocol.Encoder
		for _, comment := range comments {
			encoded.DD(3)
			encoded.Bytes([]byte(comment))
		}
		request := base
		request.Flags = flags
		request.Funcs = []protocol.PushFunction{{
			Name: name, Length: 32, Hash: hash,
			Metadata: append([]byte(nil), encoded.Payload()...),
		}}
		status, err := s.Push(ctx, identity, request)
		if err != nil {
			t.Fatal(err)
		}
		return status
	}
	pullName := func() string {
		t.Helper()
		result, err := s.Pull(ctx, [][]byte{hash})
		if err != nil {
			t.Fatal(err)
		}
		if len(result) != 1 || result[0] == nil {
			t.Fatalf("missing pull result: %#v", result)
		}
		return result[0].Name
	}

	if status := push("high", []string{"useful"}, protocol.PushOverrideIfBetterOrDifferent); status[0] != 1 {
		t.Fatalf("first push status %v", status)
	}
	if status := push("lower", nil, protocol.PushOverrideIfBetterOrDifferent); status[0] != 0 {
		t.Fatalf("existing push status %v", status)
	}
	if got := pullName(); got != "high" {
		t.Fatalf("lower score replaced current metadata: %q", got)
	}
	push("equal", []string{"different"}, protocol.PushOverrideIfBetterOrDifferent)
	if got := pullName(); got != "high" {
		t.Fatalf("equal score replaced current metadata: %q", got)
	}
	push("forced", nil, protocol.PushOverride)
	if got := pullName(); got != "forced" {
		t.Fatalf("override mode did not replace current metadata: %q", got)
	}
	push("blocked", []string{"one", "two"}, protocol.PushDoNotOverride)
	if got := pullName(); got != "forced" {
		t.Fatalf("do-not-override mode replaced current metadata: %q", got)
	}
	push("promoted", []string{"one", "two"}, protocol.PushOverrideIfBetterOrDifferent)
	if got := pullName(); got != "promoted" {
		t.Fatalf("higher score did not replace current metadata: %q", got)
	}
}

func bytesToHex(v []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(v)*2)
	for i, b := range v {
		out[i*2] = digits[b>>4]
		out[i*2+1] = digits[b&0xf]
	}
	return string(out)
}
