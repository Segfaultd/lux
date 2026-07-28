package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/segfaultd/lux/internal/metadata"
	"github.com/segfaultd/lux/internal/protocol"
	"github.com/segfaultd/lux/internal/testdb"
)

func TestProjectAndMetadataManagement(t *testing.T) {
	s, err := Open(testdb.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()
	hashA := bytes.Repeat([]byte{0x71}, 16)
	hashB := bytes.Repeat([]byte{0x72}, 16)
	md5 := [16]byte{0x91}
	identity := PushIdentity{
		LicenseNumber: []byte("license-id"),
		LicenseData:   []byte("license-data"),
		Hostname:      "workstation-7",
		Username:      "operator",
	}
	for _, push := range []protocol.PushMetadata{
		{
			IDBPath: "alpha.i64", FilePath: "/samples/alpha.exe", MD5: md5,
			Funcs: []protocol.PushFunction{
				{Name: "alpha", Length: 10, Hash: hashA, Metadata: []byte{1}},
				{Name: "shared", Length: 20, Hash: hashB, Metadata: []byte{2}},
			},
		},
		{
			IDBPath: "beta.i64", FilePath: "/samples/beta.exe", MD5: md5,
			Funcs: []protocol.PushFunction{{Name: "beta", Length: 30, Hash: hashA, Metadata: []byte{3}}},
		},
	} {
		if _, err := s.Push(ctx, identity, push); err != nil {
			t.Fatal(err)
		}
	}

	projects, err := s.ListProjects(ctx, "WORKSTATION", 5000, -10)
	if err != nil {
		t.Fatal(err)
	}
	if len(projects) != 2 {
		t.Fatalf("projects = %#v", projects)
	}
	projectsByPath, err := s.ListProjects(ctx, "alpha.i64", 10, 0)
	if err != nil || len(projectsByPath) != 1 {
		t.Fatalf("path search = %#v, %v", projectsByPath, err)
	}
	alphaID := projectsByPath[0].ID
	if projectsByPath[0].Functions != 2 || projectsByPath[0].Versions != 2 || projectsByPath[0].Username != "operator" {
		t.Fatalf("project summary = %#v", projectsByPath[0])
	}

	project, err := s.Project(ctx, alphaID)
	if err != nil {
		t.Fatal(err)
	}
	if len(project.FunctionVersions) != 2 || project.FileMD5 != bytesToHex(md5[:]) {
		t.Fatalf("project detail = %#v", project)
	}
	versionID := project.FunctionVersions[0].ID
	version, err := s.FunctionVersion(ctx, versionID)
	if err != nil || version.ProjectID != alphaID {
		t.Fatalf("version = %#v, %v", version, err)
	}
	rawMetadata := []byte{0, 1, 2, 3, 4}
	version, err = s.UpdateFunctionVersion(ctx, versionID, "renamed", 99, rawMetadata)
	if err != nil {
		t.Fatal(err)
	}
	if version.Name != "renamed" || version.Length != 99 || version.Metadata != "0001020304" || version.Score != metadata.Score(rawMetadata) {
		t.Fatalf("updated version = %#v", version)
	}

	project, err = s.UpdateProject(ctx, alphaID, "/renamed/file.exe", "/idbs/renamed.i64")
	if err != nil {
		t.Fatal(err)
	}
	if project.FilePath != "/renamed/file.exe" || project.IDBPath != "/idbs/renamed.i64" {
		t.Fatalf("updated project = %#v", project)
	}

	if _, err := s.Project(ctx, 999999); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing project error = %v", err)
	}
	if _, err := s.UpdateProject(ctx, 999999, "", ""); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing project update error = %v", err)
	}
	if _, err := s.FunctionVersion(ctx, 999999); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing version error = %v", err)
	}
	if _, err := s.UpdateFunctionVersion(ctx, 999999, "", 0, nil); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing version update error = %v", err)
	}

	deleted, err := s.DeleteFunctionVersion(ctx, versionID)
	if err != nil || !deleted.Found || deleted.DeletedVersions != 1 {
		t.Fatalf("delete version = %#v, %v", deleted, err)
	}
	deleted, err = s.DeleteFunctionVersion(ctx, versionID)
	if err != nil || deleted.Found {
		t.Fatalf("delete missing version = %#v, %v", deleted, err)
	}

	beta, err := s.ListProjects(ctx, "beta.i64", 10, 0)
	if err != nil || len(beta) != 1 {
		t.Fatalf("beta project = %#v, %v", beta, err)
	}
	deleted, err = s.DeleteProject(ctx, beta[0].ID)
	if err != nil || !deleted.Found || deleted.DeletedVersions != 1 {
		t.Fatalf("delete project = %#v, %v", deleted, err)
	}
	deleted, err = s.DeleteProject(ctx, beta[0].ID)
	if err != nil || deleted.Found {
		t.Fatalf("delete missing project = %#v, %v", deleted, err)
	}
	stats, err := s.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Databases != 1 || stats.Versions != 1 || stats.Files != 1 || stats.Users != 1 {
		t.Fatalf("post-delete stats = %#v", stats)
	}
}
