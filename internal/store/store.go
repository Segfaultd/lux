package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
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
	Functions      int64 `json:"functions"`
	Versions       int64 `json:"versions"`
	Files          int64 `json:"files"`
	Users          int64 `json:"users"`
	Accounts       int64 `json:"accounts"`
	Databases      int64 `json:"databases"`
	Pushes         int64 `json:"pushes"`
	HistoryRecords int64 `json:"history_records"`
}

type UserStats struct {
	Username       string `json:"username"`
	Functions      int64  `json:"functions"`
	Pushes         int64  `json:"pushes"`
	HistoryRecords int64  `json:"history_records"`
	Databases      int64  `json:"databases"`
	Files          int64  `json:"files"`
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
	ProjectID int64              `json:"project_id"`
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
	Username  string             `json:"username"`
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
	LicenseNumber    []byte
	LicenseData      []byte
	Hostname         string
	AccountID        int64
	Username         string
	AccountLicenseID string
	AccountEmail     string
	Protocol         uint32
}

type AuthAccount struct {
	ID               int64  `json:"id"`
	Username         string `json:"username"`
	Email            string `json:"email"`
	LicenseID        string `json:"license_id"`
	IsAdmin          bool   `json:"is_admin"`
	CanDeleteHistory bool   `json:"can_delete_history"`
	Enabled          bool   `json:"enabled"`
	PasswordSet      bool   `json:"password_set"`
	CreatedAt        string `json:"created_at"`
	UpdatedAt        string `json:"updated_at"`
	LastLoginAt      string `json:"last_login_at,omitempty"`
}

type AuthAccountProfile struct {
	Email            string
	LicenseID        string
	IsAdmin          bool
	CanDeleteHistory bool
}

type AuthAccountRecord struct {
	AuthAccount
	PasswordHash []byte
}

var (
	ErrAuthAccountExists   = errors.New("authentication account already exists")
	ErrAuthAccountNotFound = errors.New("authentication account not found")
	ErrLastAuthAccount     = errors.New("cannot remove or disable the last enabled authentication account")
)

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
CREATE TABLE IF NOT EXISTS auth_accounts (
  id BIGSERIAL PRIMARY KEY,
  username TEXT NOT NULL,
  password_hash BYTEA,
  email TEXT NOT NULL DEFAULT '',
  license_id TEXT NOT NULL DEFAULT '',
  is_admin BOOLEAN NOT NULL DEFAULT FALSE,
  can_delete_history BOOLEAN NOT NULL DEFAULT FALSE,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_login_at TIMESTAMPTZ
);
ALTER TABLE auth_accounts ADD COLUMN IF NOT EXISTS email TEXT NOT NULL DEFAULT '';
ALTER TABLE auth_accounts ADD COLUMN IF NOT EXISTS license_id TEXT NOT NULL DEFAULT '';
ALTER TABLE auth_accounts ADD COLUMN IF NOT EXISTS is_admin BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE auth_accounts ADD COLUMN IF NOT EXISTS can_delete_history BOOLEAN NOT NULL DEFAULT FALSE;
CREATE TABLE IF NOT EXISTS schema_migrations (
  name TEXT PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM schema_migrations WHERE name='official-user-flags') THEN
    IF EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema=current_schema() AND table_name='auth_accounts' AND column_name='role'
    ) THEN
      EXECUTE 'UPDATE auth_accounts SET is_admin=(role=''admin''), can_delete_history=(role=''admin'')';
    END IF;
    INSERT INTO schema_migrations(name) VALUES ('official-user-flags');
  END IF;
END $$;
CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_accounts_username ON auth_accounts ((lower(username)));
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
  auth_account_id BIGINT REFERENCES auth_accounts(id) ON DELETE SET NULL,
  auth_username TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
ALTER TABLE databases ADD COLUMN IF NOT EXISTS auth_account_id BIGINT REFERENCES auth_accounts(id) ON DELETE SET NULL;
ALTER TABLE databases ADD COLUMN IF NOT EXISTS auth_username TEXT NOT NULL DEFAULT '';
ALTER TABLE databases DROP CONSTRAINT IF EXISTS databases_file_id_user_id_idb_path_key;
CREATE UNIQUE INDEX IF NOT EXISTS idx_databases_identity ON databases (file_id, user_id, idb_path, auth_username);
CREATE TABLE IF NOT EXISTS functions (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  length INTEGER NOT NULL,
  database_id BIGINT NOT NULL REFERENCES databases(id) ON DELETE CASCADE,
  checksum BYTEA NOT NULL,
  metadata BYTEA NOT NULL,
  score INTEGER NOT NULL DEFAULT 0,
  ea64 NUMERIC(20, 0) NOT NULL DEFAULT 18446744073709551615,
  pushed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (checksum, database_id)
);
ALTER TABLE functions ADD COLUMN IF NOT EXISTS ea64 NUMERIC(20, 0) NOT NULL DEFAULT 18446744073709551615;
CREATE INDEX IF NOT EXISTS idx_functions_best ON functions(checksum, score DESC, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_functions_database ON functions(database_id);
CREATE TABLE IF NOT EXISTS function_frequencies (
  checksum BYTEA PRIMARY KEY,
  frequency BIGINT NOT NULL DEFAULT 0 CHECK (frequency >= 0)
);
CREATE INDEX IF NOT EXISTS idx_databases_file ON databases(file_id);
CREATE TABLE IF NOT EXISTS pushes (
  id BIGSERIAL PRIMARY KEY,
  database_id BIGINT NOT NULL REFERENCES databases(id) ON DELETE CASCADE,
  protocol_version INTEGER NOT NULL DEFAULT 0,
  source TEXT NOT NULL DEFAULT 'native',
  username TEXT NOT NULL DEFAULT '',
  license_id TEXT NOT NULL DEFAULT '',
  license_name TEXT NOT NULL DEFAULT '',
  license_email TEXT NOT NULL DEFAULT '',
  hostname TEXT NOT NULL DEFAULT '',
  idb_path TEXT NOT NULL DEFAULT '',
  file_path TEXT NOT NULL DEFAULT '',
  file_md5 BYTEA NOT NULL DEFAULT '\x',
  submitted_functions INTEGER NOT NULL DEFAULT 0,
  changed_functions INTEGER NOT NULL DEFAULT 0,
  pushed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
ALTER TABLE pushes ADD COLUMN IF NOT EXISTS username TEXT NOT NULL DEFAULT '';
ALTER TABLE pushes ADD COLUMN IF NOT EXISTS license_id TEXT NOT NULL DEFAULT '';
ALTER TABLE pushes ADD COLUMN IF NOT EXISTS license_name TEXT NOT NULL DEFAULT '';
ALTER TABLE pushes ADD COLUMN IF NOT EXISTS license_email TEXT NOT NULL DEFAULT '';
ALTER TABLE pushes ADD COLUMN IF NOT EXISTS hostname TEXT NOT NULL DEFAULT '';
ALTER TABLE pushes ADD COLUMN IF NOT EXISTS idb_path TEXT NOT NULL DEFAULT '';
ALTER TABLE pushes ADD COLUMN IF NOT EXISTS file_path TEXT NOT NULL DEFAULT '';
ALTER TABLE pushes ADD COLUMN IF NOT EXISTS file_md5 BYTEA NOT NULL DEFAULT '\x';
CREATE INDEX IF NOT EXISTS idx_pushes_database ON pushes(database_id, pushed_at DESC, id DESC);
CREATE TABLE IF NOT EXISTS function_changes (
  id BIGSERIAL PRIMARY KEY,
  push_id BIGINT NOT NULL REFERENCES pushes(id) ON DELETE CASCADE,
  function_id BIGINT NOT NULL REFERENCES functions(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  length INTEGER NOT NULL,
  metadata BYTEA NOT NULL,
  score INTEGER NOT NULL DEFAULT 0,
  accepted BOOLEAN NOT NULL DEFAULT FALSE,
  operation TEXT NOT NULL DEFAULT 'update',
  changed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
ALTER TABLE function_changes ADD COLUMN IF NOT EXISTS accepted BOOLEAN NOT NULL DEFAULT FALSE;
CREATE INDEX IF NOT EXISTS idx_function_changes_function ON function_changes(function_id, changed_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_function_changes_push ON function_changes(push_id);
CREATE INDEX IF NOT EXISTS idx_function_changes_accepted ON function_changes(accepted, score DESC, id);
INSERT INTO pushes (
  database_id, source, username, license_id, license_name, license_email,
  hostname, idb_path, file_path, file_md5,
  submitted_functions, changed_functions, pushed_at
)
SELECT db.id, 'backfill', COALESCE(NULLIF(db.auth_username, ''), a.username, ''),
       COALESCE(a.license_id, ''), COALESCE(a.username, ''), COALESCE(a.email, ''),
       u.hostname, db.idb_path, db.file_path, fi.checksum,
       COUNT(fn.id), COUNT(fn.id), MIN(fn.pushed_at)
FROM databases db
JOIN functions fn ON fn.database_id=db.id
JOIN users u ON u.id=db.user_id
JOIN files fi ON fi.id=db.file_id
LEFT JOIN auth_accounts a ON a.id=db.auth_account_id
WHERE NOT EXISTS (SELECT 1 FROM pushes p WHERE p.database_id=db.id)
GROUP BY db.id, a.username, a.license_id, a.email, u.hostname, fi.checksum;
UPDATE pushes p SET
  username=COALESCE(NULLIF(db.auth_username, ''), a.username, ''),
  license_id=COALESCE(NULLIF(p.license_id, ''), a.license_id, ''),
  license_name=COALESCE(NULLIF(p.license_name, ''), a.username, ''),
  license_email=COALESCE(NULLIF(p.license_email, ''), a.email, ''),
  hostname=u.hostname,
  idb_path=db.idb_path,
  file_path=db.file_path,
  file_md5=fi.checksum
FROM databases db
JOIN users u ON u.id=db.user_id
JOIN files fi ON fi.id=db.file_id
LEFT JOIN auth_accounts a ON a.id=db.auth_account_id
WHERE p.database_id=db.id AND p.file_md5='\x';
UPDATE pushes p SET
  license_id=COALESCE(a.license_id, ''),
  license_name=COALESCE(a.username, p.username),
  license_email=COALESCE(a.email, '')
FROM databases db
LEFT JOIN auth_accounts a ON a.id=db.auth_account_id
WHERE p.database_id=db.id
  AND p.license_id='' AND p.license_name='' AND p.license_email='';
INSERT INTO function_changes (push_id, function_id, name, length, metadata, score, operation, changed_at)
SELECT p.id, fn.id, fn.name, fn.length, fn.metadata, fn.score, 'backfill', fn.updated_at
FROM functions fn
JOIN databases db ON db.id=fn.database_id
JOIN LATERAL (
  SELECT id FROM pushes WHERE database_id=db.id ORDER BY id LIMIT 1
) p ON TRUE
WHERE NOT EXISTS (SELECT 1 FROM function_changes fc WHERE fc.function_id=fn.id);
WITH ranked AS (
  SELECT fc.id,
         ROW_NUMBER() OVER (PARTITION BY fn.checksum ORDER BY fc.score DESC, fc.id ASC) AS rank_no
  FROM function_changes fc
  JOIN functions fn ON fn.id=fc.function_id
), pending AS (
  SELECT ranked.*
  FROM ranked
  WHERE NOT EXISTS (
    SELECT 1 FROM schema_migrations WHERE name='official-metadata-selection'
  )
)
UPDATE function_changes fc
SET accepted=(pending.rank_no=1)
FROM pending
WHERE fc.id=pending.id;
INSERT INTO schema_migrations(name) VALUES ('official-metadata-selection')
ON CONFLICT (name) DO NOTHING;
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
		{&out.Accounts, "SELECT COUNT(*) FROM auth_accounts"},
		{&out.Databases, "SELECT COUNT(*) FROM databases"},
		{&out.Pushes, "SELECT COUNT(*) FROM pushes"},
		{&out.HistoryRecords, "SELECT COUNT(*) FROM function_changes"},
	}
	for _, q := range queries {
		if err := s.db.QueryRowContext(ctx, q.sql).Scan(q.dest); err != nil {
			return Stats{}, err
		}
	}
	return out, nil
}

func (s *Store) StatsForUsers(ctx context.Context, usernames []string) ([]UserStats, error) {
	const query = `
SELECT
  (SELECT COUNT(DISTINCT fn.checksum)
   FROM functions fn
   JOIN databases db ON db.id=fn.database_id
   WHERE lower(db.auth_username)=lower($1)),
  (SELECT COUNT(*) FROM pushes p WHERE lower(p.username)=lower($1)),
  (SELECT COUNT(*)
   FROM function_changes fc
   JOIN pushes p ON p.id=fc.push_id
   WHERE lower(p.username)=lower($1)),
  (SELECT COUNT(*) FROM databases db WHERE lower(db.auth_username)=lower($1)),
  (SELECT COUNT(DISTINCT db.file_id)
   FROM databases db WHERE lower(db.auth_username)=lower($1))`
	stats := make([]UserStats, 0, len(usernames))
	for _, username := range usernames {
		current := UserStats{Username: username}
		if err := s.db.QueryRowContext(ctx, query, username).Scan(
			&current.Functions, &current.Pushes, &current.HistoryRecords,
			&current.Databases, &current.Files,
		); err != nil {
			return nil, err
		}
		stats = append(stats, current)
	}
	return stats, nil
}

func (s *Store) Pull(ctx context.Context, hashes [][]byte) ([]*protocol.PullResultFunction, error) {
	return s.PullWithFlags(ctx, hashes, 0)
}

func (s *Store) PullWithFlags(
	ctx context.Context, hashes [][]byte, flags uint32,
) ([]*protocol.PullResultFunction, error) {
	const query = `
SELECT fc.name, fc.length, fc.metadata
FROM function_changes fc
JOIN functions fn ON fn.id=fc.function_id
WHERE fn.checksum = $1
ORDER BY fc.accepted DESC, fc.score DESC, fc.id ASC
LIMIT 1`
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()
	out := make([]*protocol.PullResultFunction, len(hashes))
	frequencies := make(map[string]uint32)
	for i, hash := range hashes {
		var f protocol.PullResultFunction
		if err := stmt.QueryRowContext(ctx, hash).Scan(&f.Name, &f.Length, &f.Metadata); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			return nil, err
		}
		key := string(hash)
		frequency, exists := frequencies[key]
		if !exists {
			var stored int64
			if flags&protocol.PullSeenFile != 0 {
				err = tx.QueryRowContext(ctx, `
SELECT COALESCE((SELECT frequency FROM function_frequencies WHERE checksum=$1), 0)`,
					hash).Scan(&stored)
			} else {
				err = tx.QueryRowContext(ctx, `
INSERT INTO function_frequencies (checksum, frequency) VALUES ($1, 1)
ON CONFLICT (checksum) DO UPDATE
SET frequency=function_frequencies.frequency+1
RETURNING frequency`, hash).Scan(&stored)
			}
			if err != nil {
				return nil, err
			}
			if stored > math.MaxUint32 {
				frequency = math.MaxUint32
			} else {
				frequency = uint32(stored)
			}
			frequencies[key] = frequency
		}
		f.Popularity = frequency
		out[i] = &f
	}
	if err := tx.Commit(); err != nil {
		return nil, err
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
INSERT INTO databases (file_path, idb_path, file_id, user_id, auth_account_id, auth_username) VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (file_id, user_id, idb_path, auth_username) DO UPDATE SET
  file_path=excluded.file_path,
  auth_account_id=excluded.auth_account_id,
  auth_username=excluded.auth_username
RETURNING id`, request.FilePath, request.IDBPath, fileID, userID, nullableID(identity.AccountID), identity.Username)
	if err != nil {
		return nil, err
	}
	pushID, err := upsertID(ctx, tx, `
INSERT INTO pushes (
  database_id, protocol_version, source, username,
  license_id, license_name, license_email,
  hostname, idb_path, file_path, file_md5,
  submitted_functions
)
VALUES ($1, $2, 'native', $3, $4, $5, $6, $7, $8, $9, $10, $11)
RETURNING id`, databaseID, identity.Protocol, identity.Username,
		identity.AccountLicenseID, identity.Username, identity.AccountEmail, identity.Hostname,
		request.IDBPath, request.FilePath, request.MD5[:], len(request.Funcs))
	if err != nil {
		return nil, err
	}

	status := make([]uint32, len(request.Funcs))
	var changed int
	for i, f := range request.Funcs {
		if f.Metadata == nil {
			f.Metadata = []byte{}
		}
		if _, err := tx.ExecContext(ctx,
			"SELECT pg_advisory_xact_lock(hashtextextended(encode($1::bytea, 'hex'), 0))",
			f.Hash); err != nil {
			return nil, err
		}
		var currentAcceptedScore uint32
		currentErr := tx.QueryRowContext(ctx, `
SELECT fc.score
FROM function_changes fc
JOIN functions fn ON fn.id=fc.function_id
WHERE fn.checksum=$1
ORDER BY fc.accepted DESC, fc.score DESC, fc.id ASC
LIMIT 1`, f.Hash).Scan(&currentAcceptedScore)
		hasCurrent := currentErr == nil
		if currentErr != nil && !errors.Is(currentErr, sql.ErrNoRows) {
			return nil, currentErr
		}
		if !hasCurrent {
			status[i] = 1
		}
		address := uint64(math.MaxUint64)
		hasAddress := i < len(request.Addresses)
		if hasAddress {
			address = request.Addresses[i]
		}
		addressText := strconv.FormatUint(address, 10)
		var functionID int64
		var currentName string
		var currentLength uint32
		var currentMetadata []byte
		var currentAddress string
		err := tx.QueryRowContext(ctx, `
SELECT id, name, length, metadata, ea64::text
FROM functions WHERE checksum=$1 AND database_id=$2`, f.Hash, databaseID).
			Scan(&functionID, &currentName, &currentLength, &currentMetadata, &currentAddress)
		isNew := errors.Is(err, sql.ErrNoRows)
		if err != nil && !isNew {
			return nil, err
		}
		if !isNew && !hasAddress {
			addressText = currentAddress
		}
		isChanged := isNew || currentName != f.Name || currentLength != f.Length || !bytes.Equal(currentMetadata, f.Metadata)
		if !isChanged {
			if currentAddress != addressText {
				if _, err := tx.ExecContext(ctx,
					"UPDATE functions SET ea64=$1::numeric WHERE id=$2",
					addressText, functionID); err != nil {
					return nil, err
				}
			}
			continue
		}
		score := metadata.Score(f.Metadata)
		accept := !hasCurrent || score > currentAcceptedScore
		switch request.Flags & protocol.PushModeMask {
		case protocol.PushOverride:
			accept = true
		case protocol.PushDoNotOverride:
			accept = !hasCurrent
		case protocol.PushMerge:
			// Server-side metadata merging is intentionally conservative until
			// IDA score fixtures cover the metadata merge operation.
		}
		if isNew {
			functionID, err = upsertID(ctx, tx, `
INSERT INTO functions (name, length, database_id, checksum, metadata, score, ea64)
VALUES ($1, $2, $3, $4, $5, $6, $7::numeric)
RETURNING id`, f.Name, f.Length, databaseID, f.Hash, f.Metadata, score, addressText)
		} else {
			_, err = tx.ExecContext(ctx, `
UPDATE functions
SET name=$1, length=$2, metadata=$3, score=$4, ea64=$5::numeric,
    updated_at=CURRENT_TIMESTAMP
WHERE id=$6`, f.Name, f.Length, f.Metadata, score, addressText, functionID)
		}
		if err != nil {
			return nil, err
		}
		if accept {
			if _, err := tx.ExecContext(ctx, `
UPDATE function_changes fc
SET accepted=FALSE
FROM functions fn
WHERE fn.id=fc.function_id AND fn.checksum=$1 AND fc.accepted`, f.Hash); err != nil {
				return nil, err
			}
		}
		operation := "update"
		if isNew {
			operation = "create"
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO function_changes (
  push_id, function_id, name, length, metadata, score, accepted, operation
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			pushID, functionID, f.Name, f.Length, f.Metadata, score, accept, operation); err != nil {
			return nil, err
		}
		changed++
	}
	if _, err := tx.ExecContext(ctx,
		"UPDATE pushes SET changed_functions=$1 WHERE id=$2", changed, pushID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return status, nil
}

func (s *Store) PopularFunctions(
	ctx context.Context, limit uint32,
) ([]protocol.PopularFunction, error) {
	if limit == 0 {
		limit = 10
	}
	if limit > 1000 {
		limit = 1000
	}
	rows, err := s.db.QueryContext(ctx, `
WITH ranked AS (
  SELECT fc.name, fc.length, fc.metadata, fn.checksum,
         LEAST(COALESCE(freq.frequency, 0), 4294967295) AS frequency,
         u.hostname, db.file_path, fi.checksum AS file_md5, fn.ea64::text AS ea64,
         fc.changed_at,
         ROW_NUMBER() OVER (
           PARTITION BY fn.checksum
           ORDER BY fc.accepted DESC, fc.score DESC, fc.id ASC
         ) AS rank_no
  FROM function_changes fc
  JOIN functions fn ON fn.id=fc.function_id
  JOIN databases db ON db.id=fn.database_id
  JOIN users u ON u.id=db.user_id
  JOIN files fi ON fi.id=db.file_id
  LEFT JOIN function_frequencies freq ON freq.checksum=fn.checksum
)
SELECT name, length, metadata, checksum, frequency, hostname, file_path, file_md5, ea64
FROM ranked
WHERE rank_no=1
ORDER BY frequency DESC, changed_at DESC, name
LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var functions []protocol.PopularFunction
	for rows.Next() {
		var function protocol.PopularFunction
		var fileMD5 []byte
		var addressText string
		if err := rows.Scan(
			&function.Name, &function.Length, &function.Metadata, &function.Pattern,
			&function.Frequency, &function.Hostname, &function.FilePath,
			&fileMD5, &addressText,
		); err != nil {
			return nil, err
		}
		function.PatternType = 1
		copy(function.FileMD5[:], fileMD5)
		function.Address, err = strconv.ParseUint(addressText, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("decode function address: %w", err)
		}
		functions = append(functions, function)
	}
	return functions, rows.Err()
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
		"DELETE FROM function_frequencies WHERE NOT EXISTS (SELECT 1 FROM functions WHERE checksum=function_frequencies.checksum)",
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
SELECT fc.name, fc.metadata, EXTRACT(EPOCH FROM fc.changed_at)::BIGINT
FROM function_changes fc
JOIN functions fn ON fn.id=fc.function_id
WHERE fn.checksum=$1
ORDER BY fc.changed_at DESC, fc.id DESC LIMIT $2`, hash, limit)
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
  SELECT fn.checksum, fc.name, fc.length, fc.score, fc.changed_at,
         LEAST(COALESCE(freq.frequency, 0), 4294967295) AS popularity,
         ROW_NUMBER() OVER (
           PARTITION BY fn.checksum
           ORDER BY fc.accepted DESC, fc.score DESC, fc.id ASC
         ) AS rank_no
  FROM function_changes fc
  JOIN functions fn ON fn.id=fc.function_id
  LEFT JOIN function_frequencies freq ON freq.checksum=fn.checksum
)
SELECT encode(checksum, 'hex'), name, length, score, popularity, changed_at
FROM ranked
WHERE rank_no=1 AND (lower(name) LIKE $1 OR encode(checksum, 'hex') LIKE $2)
ORDER BY changed_at DESC, name
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
SELECT fn.id, db.id, encode(fn.checksum, 'hex'), fn.name, fn.length, fn.score, fn.metadata,
       encode(fi.checksum, 'hex'), db.file_path, db.idb_path, u.hostname,
       COALESCE(NULLIF(db.auth_username, ''), a.username, ''),
       fn.pushed_at, fn.updated_at
FROM functions fn
JOIN databases db ON db.id=fn.database_id
JOIN files fi ON fi.id=db.file_id
JOIN users u ON u.id=db.user_id
LEFT JOIN auth_accounts a ON a.id=db.auth_account_id
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
		if err := rows.Scan(&f.ID, &f.ProjectID, &f.Hash, &f.Name, &f.Length, &f.Score, &md,
			&f.FileMD5, &f.FilePath, &f.IDBPath, &f.Hostname, &f.Username, &pushedAt, &updatedAt); err != nil {
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

func nullableID(id int64) any {
	if id == 0 {
		return nil
	}
	return id
}
