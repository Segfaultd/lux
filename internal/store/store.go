package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/segfaultd/lux/internal/metadata"
	"github.com/segfaultd/lux/internal/protocol"
)

type Store struct {
	db *sql.DB
}

type Stats struct {
	Functions int64 `json:"functions"`
	Versions  int64 `json:"versions"`
	Files     int64 `json:"files"`
	Users     int64 `json:"users"`
	Databases int64 `json:"databases"`
}

type FunctionSummary struct {
	Hash       string `json:"hash"`
	Name       string `json:"name"`
	Length     uint32 `json:"length"`
	Score      uint32 `json:"score"`
	Popularity uint32 `json:"popularity"`
	UpdatedAt  string `json:"updated_at"`
}

type FunctionVersion struct {
	ID        int64              `json:"id"`
	Hash      string             `json:"hash"`
	Name      string             `json:"name"`
	Length    uint32             `json:"length"`
	Score     uint32             `json:"score"`
	Metadata  string             `json:"metadata"`
	Comments  []metadata.Comment `json:"comments"`
	FileMD5   string             `json:"file_md5"`
	FilePath  string             `json:"file_path"`
	IDBPath   string             `json:"idb_path"`
	Hostname  string             `json:"hostname"`
	PushedAt  string             `json:"pushed_at"`
	UpdatedAt string             `json:"updated_at"`
}

type FileSummary struct {
	MD5       string `json:"md5"`
	Path      string `json:"path"`
	Functions int64  `json:"functions"`
	UpdatedAt string `json:"updated_at"`
}

type PushIdentity struct {
	LicenseNumber []byte
	LicenseData   []byte
	Hostname      string
}

func Open(connectionURL string) (*Store, error) {
	db, err := sql.Open("pgx", connectionURL)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(16)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(30 * time.Minute)
	db.SetConnMaxIdleTime(5 * time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	const schema = `
CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  license_id BYTEA NOT NULL,
  license_data BYTEA NOT NULL,
  hostname TEXT NOT NULL,
  first_seen TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (license_id, license_data, hostname)
);
CREATE TABLE IF NOT EXISTS files (
  id BIGSERIAL PRIMARY KEY,
  checksum BYTEA NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS databases (
  id BIGSERIAL PRIMARY KEY,
  file_path TEXT NOT NULL,
  idb_path TEXT NOT NULL,
  file_id BIGINT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (file_id, user_id, idb_path)
);
CREATE TABLE IF NOT EXISTS functions (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  length INTEGER NOT NULL,
  database_id BIGINT NOT NULL REFERENCES databases(id) ON DELETE CASCADE,
  checksum BYTEA NOT NULL,
  metadata BYTEA NOT NULL,
  score INTEGER NOT NULL DEFAULT 0,
  pushed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (checksum, database_id)
);
CREATE INDEX IF NOT EXISTS idx_functions_best ON functions(checksum, score DESC, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_functions_database ON functions(database_id);
CREATE INDEX IF NOT EXISTS idx_databases_file ON databases(file_id);
`
	_, err := s.db.ExecContext(ctx, schema)
	return err
}

func (s *Store) Stats(ctx context.Context) (Stats, error) {
	var out Stats
	queries := []struct {
		dest *int64
		sql  string
	}{
		{&out.Functions, "SELECT COUNT(DISTINCT checksum) FROM functions"},
		{&out.Versions, "SELECT COUNT(*) FROM functions"},
		{&out.Files, "SELECT COUNT(*) FROM files"},
		{&out.Users, "SELECT COUNT(*) FROM users"},
		{&out.Databases, "SELECT COUNT(*) FROM databases"},
	}
	for _, q := range queries {
		if err := s.db.QueryRowContext(ctx, q.sql).Scan(q.dest); err != nil {
			return Stats{}, err
		}
	}
	return out, nil
}

func (s *Store) Pull(ctx context.Context, hashes [][]byte) ([]*protocol.PullResultFunction, error) {
	const query = `
SELECT f.name, f.length, f.metadata,
       (SELECT COUNT(*) FROM functions p WHERE p.checksum = f.checksum)
FROM functions f
WHERE f.checksum = $1
ORDER BY f.score DESC, f.updated_at DESC, f.id DESC
LIMIT 1`
	stmt, err := s.db.PrepareContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()
	out := make([]*protocol.PullResultFunction, len(hashes))
	for i, hash := range hashes {
		var f protocol.PullResultFunction
		if err := stmt.QueryRowContext(ctx, hash).Scan(&f.Name, &f.Length, &f.Metadata, &f.Popularity); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			return nil, err
		}
		out[i] = &f
	}
	return out, nil
}

func (s *Store) Push(ctx context.Context, identity PushIdentity, request protocol.PushMetadata) ([]uint32, error) {
	if identity.LicenseNumber == nil {
		identity.LicenseNumber = []byte{}
	}
	if identity.LicenseData == nil {
		identity.LicenseData = []byte{}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	userID, err := upsertID(ctx, tx, `
INSERT INTO users (license_id, license_data, hostname) VALUES ($1, $2, $3)
ON CONFLICT (license_id, license_data, hostname) DO UPDATE SET hostname=excluded.hostname
RETURNING id`, identity.LicenseNumber, identity.LicenseData, identity.Hostname)
	if err != nil {
		return nil, err
	}
	fileID, err := upsertID(ctx, tx, `
INSERT INTO files (checksum) VALUES ($1)
ON CONFLICT (checksum) DO UPDATE SET checksum=excluded.checksum
RETURNING id`, request.MD5[:])
	if err != nil {
		return nil, err
	}
	databaseID, err := upsertID(ctx, tx, `
INSERT INTO databases (file_path, idb_path, file_id, user_id) VALUES ($1, $2, $3, $4)
ON CONFLICT (file_id, user_id, idb_path) DO UPDATE SET file_path=excluded.file_path
RETURNING id`, request.FilePath, request.IDBPath, fileID, userID)
	if err != nil {
		return nil, err
	}

	status := make([]uint32, len(request.Funcs))
	for i, f := range request.Funcs {
		if f.Metadata == nil {
			f.Metadata = []byte{}
		}
		var exists bool
		err := tx.QueryRowContext(ctx,
			"SELECT EXISTS(SELECT 1 FROM functions WHERE checksum=$1 AND database_id=$2)",
			f.Hash, databaseID).Scan(&exists)
		if err != nil {
			return nil, err
		}
		if !exists {
			status[i] = 1
		}
		_, err = tx.ExecContext(ctx, `
INSERT INTO functions (name, length, database_id, checksum, metadata, score)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (checksum, database_id) DO UPDATE SET
  name=excluded.name,
  length=excluded.length,
  metadata=excluded.metadata,
  score=excluded.score,
  updated_at=CURRENT_TIMESTAMP`,
			f.Name, f.Length, databaseID, f.Hash, f.Metadata, metadata.Score(f.Metadata))
		if err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return status, nil
}

func upsertID(ctx context.Context, tx *sql.Tx, query string, args ...any) (int64, error) {
	var id int64
	err := tx.QueryRowContext(ctx, query, args...).Scan(&id)
	return id, err
}

func (s *Store) DeleteHashes(ctx context.Context, hashes [][]byte) (int64, error) {
	if len(hashes) == 0 {
		return 0, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var deleted int64
	for _, hash := range hashes {
		res, err := tx.ExecContext(ctx, "DELETE FROM functions WHERE checksum=$1", hash)
		if err != nil {
			return 0, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return 0, err
		}
		deleted += n
	}
	cleanup := []string{
		"DELETE FROM databases WHERE NOT EXISTS (SELECT 1 FROM functions WHERE database_id=databases.id)",
		"DELETE FROM files WHERE NOT EXISTS (SELECT 1 FROM databases WHERE file_id=files.id)",
		"DELETE FROM users WHERE NOT EXISTS (SELECT 1 FROM databases WHERE user_id=users.id)",
	}
	for _, query := range cleanup {
		if _, err := tx.ExecContext(ctx, query); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return deleted, nil
}

func (s *Store) Histories(ctx context.Context, hash []byte, limit uint32) ([]protocol.FunctionHistory, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT name, metadata, EXTRACT(EPOCH FROM updated_at)::BIGINT
FROM functions WHERE checksum=$1
ORDER BY updated_at DESC, id DESC LIMIT $2`, hash, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []protocol.FunctionHistory
	for rows.Next() {
		var h protocol.FunctionHistory
		if err := rows.Scan(&h.Name, &h.Metadata, &h.Timestamp); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *Store) ListFunctions(ctx context.Context, search string, limit, offset int) ([]FunctionSummary, error) {
	if limit < 1 || limit > 500 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	needle := "%" + strings.ToLower(search) + "%"
	rows, err := s.db.QueryContext(ctx, `
WITH ranked AS (
  SELECT f.*, COUNT(*) OVER (PARTITION BY checksum) AS popularity,
         ROW_NUMBER() OVER (PARTITION BY checksum ORDER BY score DESC, updated_at DESC, id DESC) AS rank_no
  FROM functions f
)
SELECT encode(checksum, 'hex'), name, length, score, popularity, updated_at
FROM ranked
WHERE rank_no=1 AND (lower(name) LIKE $1 OR encode(checksum, 'hex') LIKE $2)
ORDER BY updated_at DESC, name
LIMIT $3 OFFSET $4`, needle, needle, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FunctionSummary
	for rows.Next() {
		var f FunctionSummary
		var updated time.Time
		if err := rows.Scan(&f.Hash, &f.Name, &f.Length, &f.Score, &f.Popularity, &updated); err != nil {
			return nil, err
		}
		f.UpdatedAt = formatTime(updated)
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *Store) Function(ctx context.Context, hash string) ([]FunctionVersion, error) {
	raw, err := parseHash(hash)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT fn.id, encode(fn.checksum, 'hex'), fn.name, fn.length, fn.score, fn.metadata,
       encode(fi.checksum, 'hex'), db.file_path, db.idb_path, u.hostname,
       fn.pushed_at, fn.updated_at
FROM functions fn
JOIN databases db ON db.id=fn.database_id
JOIN files fi ON fi.id=db.file_id
JOIN users u ON u.id=db.user_id
WHERE fn.checksum=$1
ORDER BY fn.score DESC, fn.updated_at DESC, fn.id DESC`, raw)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FunctionVersion
	for rows.Next() {
		var f FunctionVersion
		var md []byte
		var pushedAt, updatedAt time.Time
		if err := rows.Scan(&f.ID, &f.Hash, &f.Name, &f.Length, &f.Score, &md,
			&f.FileMD5, &f.FilePath, &f.IDBPath, &f.Hostname, &pushedAt, &updatedAt); err != nil {
			return nil, err
		}
		f.Metadata = hex.EncodeToString(md)
		f.Comments = metadata.ParseBestEffort(md)
		f.PushedAt = formatTime(pushedAt)
		f.UpdatedAt = formatTime(updatedAt)
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *Store) ListFiles(ctx context.Context, search string, limit, offset int) ([]FileSummary, error) {
	if limit < 1 || limit > 500 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	needle := "%" + strings.ToLower(search) + "%"
	rows, err := s.db.QueryContext(ctx, `
SELECT encode(fi.checksum, 'hex'), COALESCE(MAX(db.file_path), ''), COUNT(DISTINCT fn.checksum),
       MAX(fn.updated_at)
FROM files fi
LEFT JOIN databases db ON db.file_id=fi.id
LEFT JOIN functions fn ON fn.database_id=db.id
WHERE encode(fi.checksum, 'hex') LIKE $1 OR lower(db.file_path) LIKE $2
GROUP BY fi.id
ORDER BY MAX(fn.updated_at) DESC
LIMIT $3 OFFSET $4`, needle, needle, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FileSummary
	for rows.Next() {
		var f FileSummary
		var updated sql.NullTime
		if err := rows.Scan(&f.MD5, &f.Path, &f.Functions, &updated); err != nil {
			return nil, err
		}
		if updated.Valid {
			f.UpdatedAt = formatTime(updated.Time)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *Store) FileFunctions(ctx context.Context, md5 string) ([]FunctionSummary, error) {
	raw, err := parseHash(md5)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT encode(fn.checksum, 'hex'), fn.name, fn.length, fn.score,
       (SELECT COUNT(*) FROM functions p WHERE p.checksum=fn.checksum),
       fn.updated_at
FROM functions fn
JOIN databases db ON db.id=fn.database_id
JOIN files fi ON fi.id=db.file_id
WHERE fi.checksum=$1
ORDER BY fn.updated_at DESC LIMIT 10000`, raw)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FunctionSummary
	for rows.Next() {
		var f FunctionSummary
		var updated time.Time
		if err := rows.Scan(&f.Hash, &f.Name, &f.Length, &f.Score, &f.Popularity, &updated); err != nil {
			return nil, err
		}
		f.UpdatedAt = formatTime(updated)
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *Store) FilesWithFunction(ctx context.Context, hash string) ([]string, error) {
	raw, err := parseHash(hash)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT DISTINCT encode(fi.checksum, 'hex')
FROM files fi
JOIN databases db ON db.file_id=fi.id
JOIN functions fn ON fn.database_id=db.id
WHERE fn.checksum=$1
ORDER BY encode(fi.checksum, 'hex')`, raw)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var md5 string
		if err := rows.Scan(&md5); err != nil {
			return nil, err
		}
		out = append(out, md5)
	}
	return out, rows.Err()
}

func parseHash(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if len(value) != 32 {
		return nil, fmt.Errorf("hash must contain exactly 32 hexadecimal characters")
	}
	raw, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("invalid hexadecimal hash: %w", err)
	}
	return raw, nil
}

func formatTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339)
}
