package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"strings"
	"time"

	"github.com/segfaultd/lux/internal/metadata"
)

type ProjectSummary struct {
	ID        int64  `json:"id"`
	FileMD5   string `json:"file_md5"`
	FilePath  string `json:"file_path"`
	IDBPath   string `json:"idb_path"`
	Hostname  string `json:"hostname"`
	Username  string `json:"username"`
	Functions int64  `json:"functions"`
	Versions  int64  `json:"versions"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

type ProjectDetail struct {
	ProjectSummary
	FunctionVersions []FunctionVersion `json:"function_versions"`
}

type DeleteResult struct {
	Found           bool  `json:"found"`
	DeletedVersions int64 `json:"deleted_versions"`
}

func (s *Store) ListProjects(ctx context.Context, search string, limit, offset int) ([]ProjectSummary, error) {
	if limit < 1 || limit > 500 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	needle := "%" + strings.ToLower(search) + "%"
	rows, err := s.db.QueryContext(ctx, `
SELECT db.id, encode(fi.checksum, 'hex'), db.file_path, db.idb_path, u.hostname,
       COALESCE(NULLIF(db.auth_username, ''), a.username, ''),
       COUNT(DISTINCT fn.checksum), COUNT(fn.id), db.created_at,
       COALESCE(MAX(fn.updated_at), db.created_at)
FROM databases db
JOIN files fi ON fi.id=db.file_id
JOIN users u ON u.id=db.user_id
LEFT JOIN auth_accounts a ON a.id=db.auth_account_id
LEFT JOIN functions fn ON fn.database_id=db.id
WHERE lower(db.file_path) LIKE $1 OR lower(db.idb_path) LIKE $1
   OR lower(u.hostname) LIKE $1 OR lower(COALESCE(NULLIF(db.auth_username, ''), a.username, '')) LIKE $1
   OR encode(fi.checksum, 'hex') LIKE $1
GROUP BY db.id, fi.checksum, u.hostname, a.username
ORDER BY COALESCE(MAX(fn.updated_at), db.created_at) DESC, db.id DESC
LIMIT $2 OFFSET $3`, needle, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProjectSummary
	for rows.Next() {
		project, err := scanProject(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, project)
	}
	return out, rows.Err()
}

func (s *Store) Project(ctx context.Context, id int64) (ProjectDetail, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT db.id, encode(fi.checksum, 'hex'), db.file_path, db.idb_path, u.hostname,
       COALESCE(NULLIF(db.auth_username, ''), a.username, ''),
       COUNT(DISTINCT fn.checksum), COUNT(fn.id), db.created_at,
       COALESCE(MAX(fn.updated_at), db.created_at)
FROM databases db
JOIN files fi ON fi.id=db.file_id
JOIN users u ON u.id=db.user_id
LEFT JOIN auth_accounts a ON a.id=db.auth_account_id
LEFT JOIN functions fn ON fn.database_id=db.id
WHERE db.id=$1
GROUP BY db.id, fi.checksum, u.hostname, a.username`, id)
	project, err := scanProject(row)
	if err != nil {
		return ProjectDetail{}, err
	}
	versions, err := s.projectVersions(ctx, id)
	if err != nil {
		return ProjectDetail{}, err
	}
	if versions == nil {
		versions = []FunctionVersion{}
	}
	return ProjectDetail{ProjectSummary: project, FunctionVersions: versions}, nil
}

func (s *Store) UpdateProject(ctx context.Context, id int64, filePath, idbPath string) (ProjectDetail, error) {
	result, err := s.db.ExecContext(ctx, `
UPDATE databases SET file_path=$1, idb_path=$2 WHERE id=$3`, filePath, idbPath, id)
	if err != nil {
		return ProjectDetail{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return ProjectDetail{}, err
	}
	if affected == 0 {
		return ProjectDetail{}, sql.ErrNoRows
	}
	return s.Project(ctx, id)
}

func (s *Store) DeleteProject(ctx context.Context, id int64) (DeleteResult, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DeleteResult{}, err
	}
	defer tx.Rollback()
	var versions int64
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM functions WHERE database_id=$1", id).Scan(&versions); err != nil {
		return DeleteResult{}, err
	}
	result, err := tx.ExecContext(ctx, "DELETE FROM databases WHERE id=$1", id)
	if err != nil {
		return DeleteResult{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return DeleteResult{}, err
	}
	if affected == 0 {
		return DeleteResult{Found: false}, nil
	}
	if err := cleanupOrphans(ctx, tx); err != nil {
		return DeleteResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return DeleteResult{}, err
	}
	return DeleteResult{Found: true, DeletedVersions: versions}, nil
}

func (s *Store) FunctionVersion(ctx context.Context, id int64) (FunctionVersion, error) {
	row := s.db.QueryRowContext(ctx, versionSelect+` WHERE fn.id=$1`, id)
	return scanVersion(row)
}

func (s *Store) UpdateFunctionVersion(ctx context.Context, id int64, name string, length uint32, rawMetadata []byte) (FunctionVersion, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return FunctionVersion{}, err
	}
	defer tx.Rollback()
	var projectID int64
	var currentName string
	var currentLength uint32
	var currentMetadata []byte
	if err := tx.QueryRowContext(ctx,
		"SELECT database_id, name, length, metadata FROM functions WHERE id=$1", id).
		Scan(&projectID, &currentName, &currentLength, &currentMetadata); err != nil {
		return FunctionVersion{}, err
	}
	if currentName == name && currentLength == length && bytes.Equal(currentMetadata, rawMetadata) {
		if err := tx.Rollback(); err != nil {
			return FunctionVersion{}, err
		}
		return s.FunctionVersion(ctx, id)
	}
	score := metadata.Score(rawMetadata)
	result, err := tx.ExecContext(ctx, `
UPDATE functions
SET name=$1, length=$2, metadata=$3, score=$4, updated_at=CURRENT_TIMESTAMP
WHERE id=$5`, name, length, rawMetadata, score, id)
	if err != nil {
		return FunctionVersion{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return FunctionVersion{}, err
	}
	if affected == 0 {
		return FunctionVersion{}, sql.ErrNoRows
	}
	pushID, err := insertAdminPushTx(ctx, tx, projectID, "admin")
	if err != nil {
		return FunctionVersion{}, err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO function_changes (push_id, function_id, name, length, metadata, score, operation)
VALUES ($1, $2, $3, $4, $5, $6, 'admin-edit')`,
		pushID, id, name, length, rawMetadata, score); err != nil {
		return FunctionVersion{}, err
	}
	if err := tx.Commit(); err != nil {
		return FunctionVersion{}, err
	}
	return s.FunctionVersion(ctx, id)
}

func (s *Store) DeleteFunctionVersion(ctx context.Context, id int64) (DeleteResult, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DeleteResult{}, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, "DELETE FROM functions WHERE id=$1", id)
	if err != nil {
		return DeleteResult{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return DeleteResult{}, err
	}
	if affected == 0 {
		return DeleteResult{Found: false}, nil
	}
	if err := cleanupOrphans(ctx, tx); err != nil {
		return DeleteResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return DeleteResult{}, err
	}
	return DeleteResult{Found: true, DeletedVersions: 1}, nil
}

const versionSelect = `
SELECT fn.id, db.id, encode(fn.checksum, 'hex'), fn.name, fn.length, fn.score, fn.metadata,
       encode(fi.checksum, 'hex'), db.file_path, db.idb_path, u.hostname,
       COALESCE(NULLIF(db.auth_username, ''), a.username, ''),
       fn.pushed_at, fn.updated_at
FROM functions fn
JOIN databases db ON db.id=fn.database_id
JOIN files fi ON fi.id=db.file_id
JOIN users u ON u.id=db.user_id
LEFT JOIN auth_accounts a ON a.id=db.auth_account_id`

func (s *Store) projectVersions(ctx context.Context, projectID int64) ([]FunctionVersion, error) {
	rows, err := s.db.QueryContext(ctx, versionSelect+`
WHERE db.id=$1
ORDER BY fn.updated_at DESC, fn.id DESC`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FunctionVersion
	for rows.Next() {
		version, err := scanVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, version)
	}
	return out, rows.Err()
}

type scanner interface {
	Scan(dest ...any) error
}

func scanProject(row scanner) (ProjectSummary, error) {
	var project ProjectSummary
	var createdAt, updatedAt time.Time
	err := row.Scan(&project.ID, &project.FileMD5, &project.FilePath, &project.IDBPath,
		&project.Hostname, &project.Username, &project.Functions, &project.Versions,
		&createdAt, &updatedAt)
	if err != nil {
		return ProjectSummary{}, err
	}
	project.CreatedAt = formatTime(createdAt)
	project.UpdatedAt = formatTime(updatedAt)
	return project, nil
}

func scanVersion(row scanner) (FunctionVersion, error) {
	var version FunctionVersion
	var rawMetadata []byte
	var pushedAt, updatedAt time.Time
	err := row.Scan(&version.ID, &version.ProjectID, &version.Hash, &version.Name,
		&version.Length, &version.Score, &rawMetadata, &version.FileMD5,
		&version.FilePath, &version.IDBPath, &version.Hostname, &version.Username,
		&pushedAt, &updatedAt)
	if err != nil {
		return FunctionVersion{}, err
	}
	version.Metadata = hex.EncodeToString(rawMetadata)
	version.Comments = metadata.ParseBestEffort(rawMetadata)
	version.PushedAt = formatTime(pushedAt)
	version.UpdatedAt = formatTime(updatedAt)
	return version, nil
}

func cleanupOrphans(ctx context.Context, tx *sql.Tx) error {
	for _, query := range []string{
		"DELETE FROM databases WHERE NOT EXISTS (SELECT 1 FROM functions WHERE database_id=databases.id)",
		"DELETE FROM files WHERE NOT EXISTS (SELECT 1 FROM databases WHERE file_id=files.id)",
		"DELETE FROM users WHERE NOT EXISTS (SELECT 1 FROM databases WHERE user_id=users.id)",
	} {
		if _, err := tx.ExecContext(ctx, query); err != nil {
			return err
		}
	}
	return nil
}
