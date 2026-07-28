package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/segfaultd/lux/internal/metadata"
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
		Hostname: "audit-host", Username: "auditor",
		AccountLicenseID: "AA-1234-CDEF-90", AccountEmail: "auditor@example.test",
		Protocol: 5,
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
		pushes[0].ChangedFunctions != 1 || pushes[0].LicenseID != "AA-1234-CDEF-90" ||
		pushes[0].LicenseName != "auditor" ||
		pushes[0].LicenseEmail != "auditor@example.test" {
		t.Fatalf("push summary = %#v", pushes[0])
	}
	chronologicalPushes, err := s.ListPushes(ctx, PushFilter{
		Username: "auditor", LicenseID: "aa-1234-cdef-90", Chronological: true,
	}, 10, 0)
	if err != nil || len(chronologicalPushes) != 3 ||
		chronologicalPushes[0].ID >= chronologicalPushes[2].ID {
		t.Fatalf("chronological pushes = %#v, %v", chronologicalPushes, err)
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
	chronologicalChanges, err := s.ListHistory(ctx, HistoryFilter{
		Username: "auditor", LicenseID: "aa-1234-cdef-90", Name: "REVISION",
		Hash: bytesToHex(hash), IDBPath: "AUDIT", FilePath: "SAMPLES",
		FileMD5: bytesToHex(request.MD5[:]), ProjectID: projectID,
		HistoryIDFrom: changes[2].ID, HistoryIDTo: changes[0].ID,
		PushIDFrom: pushes[2].ID, PushIDTo: pushes[0].ID,
		From: &past, To: &future, Chronological: true,
	}, 10, 0)
	if err != nil || len(chronologicalChanges) != 3 ||
		chronologicalChanges[0].Name != "revision_one" ||
		chronologicalChanges[2].Name != "revision_three" {
		t.Fatalf("fully filtered history = %#v, %v", chronologicalChanges, err)
	}
	userStats, err := s.StatsForUsers(ctx, []string{"auditor", "missing"})
	if err != nil || len(userStats) != 2 ||
		userStats[0].Functions != 1 || userStats[0].Pushes != 3 ||
		userStats[0].HistoryRecords != 3 || userStats[0].Databases != 1 ||
		userStats[0].Files != 1 || userStats[1].Pushes != 0 {
		t.Fatalf("user statistics = %#v, %v", userStats, err)
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
	if err != nil || firstDiff.Previous != nil || len(firstDiff.Fields) < 5 ||
		firstDiff.Metadata.Error == "" {
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

func TestHistoryDiffFieldSelection(t *testing.T) {
	base := HistoryChange{
		Name: "same", Length: 1, Score: 2, Metadata: "aa",
		Comments: []metadata.Comment{{Type: "function", Text: "before"}},
	}
	if fields := diffChanges(&base, base); len(fields) != 0 {
		t.Fatalf("identical diff = %#v", fields)
	}
	commentsChanged := base
	commentsChanged.Comments = []metadata.Comment{{Type: "function", Text: "after"}}
	fields := diffChanges(&base, commentsChanged)
	if len(fields) != 1 || fields[0].Field != "comments" {
		t.Fatalf("comment diff = %#v", fields)
	}

	var before, after protocol.Encoder
	before.DD(metadata.KeyFunctionComment)
	before.Bytes([]byte("before"))
	after.DD(metadata.KeyFunctionComment)
	after.Bytes([]byte("after"))
	metadataChanged := base
	metadataChanged.Metadata = hex.EncodeToString(after.Payload())
	base.Metadata = hex.EncodeToString(before.Payload())
	fields = diffChanges(&base, metadataChanged)
	var raw, semantic bool
	for _, field := range fields {
		raw = raw || field.Field == "metadata.raw"
		semantic = semantic || field.Field == "metadata.function_comment" &&
			field.Before == "before" && field.After == "after"
	}
	if !raw || !semantic {
		t.Fatalf("semantic metadata diff = %#v", fields)
	}

	initial := diffChanges(nil, metadataChanged)
	if len(initial) < 6 || initial[3].Field != "metadata.raw" {
		t.Fatalf("initial metadata diff = %#v", initial)
	}
}

func TestDeleteOnlyHistoryChangeRemovesCurrentFunction(t *testing.T) {
	s, err := Open(testdb.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()
	hash := bytes.Repeat([]byte{0xf1}, 16)
	if _, err := s.Push(ctx, PushIdentity{Hostname: "single"}, protocol.PushMetadata{
		IDBPath: "single.i64", FilePath: "single.bin", MD5: [16]byte{0xf2},
		Funcs: []protocol.PushFunction{{Name: "only_revision", Hash: hash}},
	}); err != nil {
		t.Fatal(err)
	}
	changes, err := s.ListHistory(ctx, HistoryFilter{}, 10, 0)
	if err != nil || len(changes) != 1 {
		t.Fatalf("changes = %#v, %v", changes, err)
	}
	deleted, err := s.DeleteFunctionChange(ctx, changes[0].ID)
	if err != nil || !deleted.Found {
		t.Fatalf("delete = %#v, %v", deleted, err)
	}
	stats, err := s.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Functions != 0 || stats.Versions != 0 || stats.Databases != 0 ||
		stats.Pushes != 0 || stats.HistoryRecords != 0 {
		t.Fatalf("orphan state = %#v", stats)
	}
}

func TestEmptyPushProjectDetail(t *testing.T) {
	s, err := Open(testdb.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()
	if _, err := s.Push(ctx, PushIdentity{Hostname: "empty"}, protocol.PushMetadata{
		IDBPath: "empty.i64", FilePath: "empty.bin", MD5: [16]byte{0xe1},
	}); err != nil {
		t.Fatal(err)
	}
	projects, err := s.ListProjects(ctx, "empty.i64", 10, 0)
	if err != nil || len(projects) != 1 {
		t.Fatalf("projects = %#v, %v", projects, err)
	}
	project, err := s.Project(ctx, projects[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if project.FunctionVersions == nil || len(project.FunctionVersions) != 0 {
		t.Fatalf("empty project versions = %#v", project.FunctionVersions)
	}
	deleted, err := s.DeleteProject(ctx, project.ID)
	if err != nil || !deleted.Found || deleted.DeletedVersions != 0 {
		t.Fatalf("delete empty project = %#v, %v", deleted, err)
	}
}
