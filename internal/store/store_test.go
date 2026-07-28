package store

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/segfaultd/lux/internal/protocol"
)

func TestPushPullAndManagementQueries(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "lux.db"))
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
	if status[0] != 1 {
		t.Fatalf("second database should create a version: %v", status)
	}

	got, err := s.Pull(ctx, [][]byte{hash, bytes.Repeat([]byte{0x99}, 16)})
	if err != nil {
		t.Fatal(err)
	}
	if got[0] == nil || got[0].Name != "parse_header" || got[0].Popularity != 2 {
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
	if len(versions) != 2 || len(versions[0].Comments) != 1 {
		t.Fatalf("unexpected versions: %#v", versions)
	}

	status, err = s.Push(ctx, identity, second)
	if err != nil {
		t.Fatal(err)
	}
	if status[0] != 0 {
		t.Fatalf("update should not be new: %v", status)
	}
	deleted, err := s.DeleteHashes(ctx, [][]byte{hash})
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 2 {
		t.Fatalf("deleted %d versions, want 2", deleted)
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
