package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/segfaultd/lux/internal/protocol"
	"github.com/segfaultd/lux/internal/testdb"
)

func TestHistoryQueriesDiffRestoreAndDelete(t *testing.T) {
	s, err := Open(testdb.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()
	hash := bytes.Repeat([]byte{0xc3}, 16)
	request := protocol.PushMetadata{
		IDBPath: "audit.i64", FilePath: "/samples/audit.bin", MD5: [16]byte{0xd4},
		Funcs: []protocol.PushFunction{{Name: "revision_one", Length: 10, Hash: hash, Metadata: []byte{1}}},
	}
	identity := PushIdentity{
		LicenseNumber: []byte("license"), LicenseData: []byte("data"),
		Hostname: "audit-host", Username: "auditor", Protocol: 5,
	}
	for index, name := range []string{"revision_one", "revision_two", "revision_three"} {
		request.Funcs[0].Name = name
		request.Funcs[0].Length = uint32(10 + index)
		request.Funcs[0].Metadata = []byte{byte(index + 1)}
		if _, err := s.Push(ctx, identity, request); err != nil {
			t.Fatal(err)
		}
	}
	versions, err := s.Function(ctx, bytesToHex(hash))
	if err != nil || len(versions) != 1 {
		t.Fatalf("versions = %#v, %v", versions, err)
	}
	projectID := versions[0].ProjectID

	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)
	pushes, err := s.ListPushes(ctx, PushFilter{
		Search: "AUDIT", Username: "Auditor", ProjectID: projectID, From: &past, To: &future,
	}, 1000, -1)
	if err != nil || len(pushes) != 3 {
		t.Fatalf("pushes = %#v, %v", pushes, err)
	}
	if pushes[0].ProtocolVersion != 5 || pushes[0].FileMD5 != bytesToHex(request.MD5[:]) ||
		pushes[0].ChangedFunctions != 1 {
		t.Fatalf("push summary = %#v", pushes[0])
	}
	push, err := s.PushRecord(ctx, pushes[1].ID)
	if err != nil || len(push.Changes) != 1 || push.Changes[0].Name != "revision_two" {
		t.Fatalf("push detail = %#v, %v", push, err)
	}

	changes, err := s.ListHistory(ctx, HistoryFilter{
		Search: "revision", Username: "AUDITOR", Hash: bytesToHex(hash),
		ProjectID: projectID, From: &past, To: &future,
	}, 1000, -1)
	if err != nil || len(changes) != 3 {
		t.Fatalf("changes = %#v, %v", changes, err)
	}
	if changes[0].Name != "revision_three" || changes[2].Operation != "create" {
		t.Fatalf("history order = %#v", changes)
	}
	pushChanges, err := s.ListHistory(ctx, HistoryFilter{PushID: pushes[1].ID}, 10, 0)
	if err != nil || len(pushChanges) != 1 || pushChanges[0].Name != "revision_two" {
		t.Fatalf("push-filtered changes = %#v, %v", pushChanges, err)
	}
	if empty, err := s.ListHistory(ctx, HistoryFilter{Hash: strings.Repeat("ee", 16)}, 10, 0); err != nil || len(empty) != 0 {
		t.Fatalf("missing hash changes = %#v, %v", empty, err)
	}

	firstID := changes[2].ID
	secondID := changes[1].ID
	thirdID := changes[0].ID
	firstDiff, err := s.FunctionChangeDiff(ctx, firstID)
	if err != nil || firstDiff.Previous != nil || len(firstDiff.Fields) != 5 {
		t.Fatalf("first diff = %#v, %v", firstDiff, err)
	}
	secondDiff, err := s.FunctionChangeDiff(ctx, secondID)
	if err != nil || secondDiff.Previous == nil || secondDiff.Previous.Name != "revision_one" ||
		len(secondDiff.Fields) < 3 {
		t.Fatalf("second diff = %#v, %v", secondDiff, err)
	}

	restored, err := s.RestoreFunctionChange(ctx, firstID)
	if err != nil || restored.Operation != "restore" || restored.Name != "revision_one" {
		t.Fatalf("restore = %#v, %v", restored, err)
	}
	current, err := s.Function(ctx, bytesToHex(hash))
	if err != nil || current[0].Name != "revision_one" {
		t.Fatalf("current after restore = %#v, %v", current, err)
	}
	deleted, err := s.DeleteFunctionChange(ctx, restored.ID)
	if err != nil || !deleted.Found || deleted.DeletedChanges != 1 {
		t.Fatalf("delete restored change = %#v, %v", deleted, err)
	}
	current, _ = s.Function(ctx, bytesToHex(hash))
	if current[0].Name != "revision_three" {
		t.Fatalf("delete latest did not reconcile current: %#v", current)
	}
	if deleted, err = s.DeleteFunctionChange(ctx, thirdID); err != nil || !deleted.Found {
		t.Fatalf("delete third = %#v, %v", deleted, err)
	}
	current, _ = s.Function(ctx, bytesToHex(hash))
	if current[0].Name != "revision_two" {
		t.Fatalf("delete third did not revert to second: %#v", current)
	}
	if deleted, err = s.DeletePush(ctx, pushes[1].ID); err != nil || !deleted.Found || deleted.DeletedChanges != 1 {
		t.Fatalf("delete second push = %#v, %v", deleted, err)
	}
	current, _ = s.Function(ctx, bytesToHex(hash))
	if current[0].Name != "revision_one" {
		t.Fatalf("delete second push did not revert to first: %#v", current)
	}
	if deleted, err = s.DeletePush(ctx, pushes[2].ID); err != nil || !deleted.Found || deleted.DeletedChanges != 1 {
		t.Fatalf("delete first push = %#v, %v", deleted, err)
	}
	if current, err = s.Function(ctx, bytesToHex(hash)); err != nil || len(current) != 0 {
		t.Fatalf("last history deletion left function: %#v, %v", current, err)
	}
	if deleted, err = s.DeleteFunctionChange(ctx, 999999); err != nil || deleted.Found {
		t.Fatalf("delete missing change = %#v, %v", deleted, err)
	}
	if deleted, err = s.DeletePush(ctx, 999999); err != nil || deleted.Found {
		t.Fatalf("delete missing push = %#v, %v", deleted, err)
	}
	if _, err := s.PushRecord(ctx, 999999); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing push error = %v", err)
	}
	if _, err := s.FunctionChange(ctx, 999999); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing change error = %v", err)
	}
	if _, err := s.FunctionChangeDiff(ctx, 999999); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing diff error = %v", err)
	}
	if _, err := s.RestoreFunctionChange(ctx, 999999); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing restore error = %v", err)
	}
}
