package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"reflect"
	"strings"
	"time"

	"github.com/segfaultd/lux/internal/metadata"
)

type PushFilter struct {
	Search    string
	Username  string
	ProjectID int64
	From      *time.Time
	To        *time.Time
}

type HistoryFilter struct {
	Search    string
	Username  string
	Hash      string
	ProjectID int64
	PushID    int64
	From      *time.Time
	To        *time.Time
}

type PushSummary struct {
	ID                 int64  `json:"id"`
	ProjectID          int64  `json:"project_id"`
	ProtocolVersion    uint32 `json:"protocol_version"`
	Source             string `json:"source"`
	Username           string `json:"username"`
	Hostname           string `json:"hostname"`
	IDBPath            string `json:"idb_path"`
	FilePath           string `json:"file_path"`
	FileMD5            string `json:"file_md5"`
	SubmittedFunctions uint32 `json:"submitted_functions"`
	ChangedFunctions   uint32 `json:"changed_functions"`
	PushedAt           string `json:"pushed_at"`
}

type PushDetail struct {
	PushSummary
	Changes []HistoryChange `json:"changes"`
}

type HistoryChange struct {
	ID         int64              `json:"id"`
	PushID     int64              `json:"push_id"`
	FunctionID int64              `json:"function_id"`
	ProjectID  int64              `json:"project_id"`
	Hash       string             `json:"hash"`
	Name       string             `json:"name"`
	Length     uint32             `json:"length"`
	Score      uint32             `json:"score"`
	Metadata   string             `json:"metadata"`
	Comments   []metadata.Comment `json:"comments"`
	Operation  string             `json:"operation"`
	Username   string             `json:"username"`
	Hostname   string             `json:"hostname"`
	IDBPath    string             `json:"idb_path"`
	FilePath   string             `json:"file_path"`
	FileMD5    string             `json:"file_md5"`
	ChangedAt  string             `json:"changed_at"`
}

type FieldDiff struct {
	Field  string `json:"field"`
	Before any    `json:"before"`
	After  any    `json:"after"`
}

type HistoryDiff struct {
	Change           HistoryChange      `json:"change"`
	Previous         *HistoryChange     `json:"previous,omitempty"`
	Metadata         metadata.Document  `json:"metadata_document"`
	PreviousMetadata *metadata.Document `json:"previous_metadata_document,omitempty"`
	Fields           []FieldDiff        `json:"fields"`
}

type HistoryDeleteResult struct {
	Found          bool  `json:"found"`
	DeletedChanges int64 `json:"deleted_changes"`
}

func (s *Store) ListPushes(ctx context.Context, filter PushFilter, limit, offset int) ([]PushSummary, error) {
	limit, offset = normalizePagination(limit, offset)
	needle := "%" + strings.ToLower(filter.Search) + "%"
	rows, err := s.db.QueryContext(ctx, `
SELECT id, database_id, protocol_version, source, username, hostname, idb_path,
       file_path, encode(file_md5, 'hex'), submitted_functions, changed_functions, pushed_at
FROM pushes
WHERE ($1='' OR lower(username) LIKE $2 OR lower(hostname) LIKE $2
       OR lower(idb_path) LIKE $2 OR lower(file_path) LIKE $2
       OR encode(file_md5, 'hex') LIKE $2)
  AND ($3='' OR lower(username)=lower($3))
  AND ($4=0 OR database_id=$4)
  AND ($5::timestamptz IS NULL OR pushed_at >= $5)
  AND ($6::timestamptz IS NULL OR pushed_at <= $6)
ORDER BY pushed_at DESC, id DESC
LIMIT $7 OFFSET $8`,
		filter.Search, needle, filter.Username, filter.ProjectID,
		nullableTime(filter.From), nullableTime(filter.To), limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PushSummary
	for rows.Next() {
		push, err := scanPush(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, push)
	}
	return out, rows.Err()
}

func (s *Store) PushRecord(ctx context.Context, id int64) (PushDetail, error) {
	push, err := scanPush(s.db.QueryRowContext(ctx, `
SELECT id, database_id, protocol_version, source, username, hostname, idb_path,
       file_path, encode(file_md5, 'hex'), submitted_functions, changed_functions, pushed_at
FROM pushes WHERE id=$1`, id))
	if err != nil {
		return PushDetail{}, err
	}
	rows, err := s.db.QueryContext(ctx, historySelect+`
WHERE p.id=$1
ORDER BY fc.changed_at DESC, fc.id DESC`, id)
	if err != nil {
		return PushDetail{}, err
	}
	defer rows.Close()
	var changes []HistoryChange
	for rows.Next() {
		change, err := scanHistoryChange(rows)
		if err != nil {
			return PushDetail{}, err
		}
		changes = append(changes, change)
	}
	if err := rows.Err(); err != nil {
		return PushDetail{}, err
	}
	if changes == nil {
		changes = []HistoryChange{}
	}
	return PushDetail{PushSummary: push, Changes: changes}, nil
}

func (s *Store) ListHistory(ctx context.Context, filter HistoryFilter, limit, offset int) ([]HistoryChange, error) {
	limit, offset = normalizePagination(limit, offset)
	needle := "%" + strings.ToLower(filter.Search) + "%"
	hashNeedle := strings.ToLower(strings.TrimSpace(filter.Hash))
	rows, err := s.db.QueryContext(ctx, historySelect+`
WHERE ($1='' OR lower(fc.name) LIKE $2 OR encode(fn.checksum, 'hex') LIKE $2
       OR lower(p.username) LIKE $2 OR lower(p.idb_path) LIKE $2
       OR lower(p.file_path) LIKE $2)
  AND ($3='' OR lower(p.username)=lower($3))
  AND ($4='' OR encode(fn.checksum, 'hex')=$4)
  AND ($5=0 OR p.database_id=$5)
  AND ($6=0 OR p.id=$6)
  AND ($7::timestamptz IS NULL OR fc.changed_at >= $7)
  AND ($8::timestamptz IS NULL OR fc.changed_at <= $8)
ORDER BY fc.changed_at DESC, fc.id DESC
LIMIT $9 OFFSET $10`,
		filter.Search, needle, filter.Username, hashNeedle, filter.ProjectID, filter.PushID,
		nullableTime(filter.From), nullableTime(filter.To), limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HistoryChange
	for rows.Next() {
		change, err := scanHistoryChange(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, change)
	}
	return out, rows.Err()
}

func (s *Store) FunctionChange(ctx context.Context, id int64) (HistoryChange, error) {
	return scanHistoryChange(s.db.QueryRowContext(ctx, historySelect+" WHERE fc.id=$1", id))
}

func (s *Store) FunctionChangeDiff(ctx context.Context, id int64) (HistoryDiff, error) {
	change, err := s.FunctionChange(ctx, id)
	if err != nil {
		return HistoryDiff{}, err
	}
	previous, err := scanHistoryChange(s.db.QueryRowContext(ctx, historySelect+`
WHERE fc.function_id=$1 AND (fc.changed_at, fc.id) < (
  SELECT changed_at, id FROM function_changes WHERE id=$2
)
ORDER BY fc.changed_at DESC, fc.id DESC LIMIT 1`, change.FunctionID, id))
	var previousPtr *HistoryChange
	if err == nil {
		previousPtr = &previous
	} else if err != sql.ErrNoRows {
		return HistoryDiff{}, err
	}
	changeMetadata := inspectMetadataHex(change.Metadata)
	var previousMetadata *metadata.Document
	if previousPtr != nil {
		decoded := inspectMetadataHex(previousPtr.Metadata)
		previousMetadata = &decoded
	}
	return HistoryDiff{
		Change:           change,
		Previous:         previousPtr,
		Metadata:         changeMetadata,
		PreviousMetadata: previousMetadata,
		Fields:           diffChanges(previousPtr, change),
	}, nil
}

func (s *Store) RestoreFunctionChange(ctx context.Context, id int64) (HistoryChange, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return HistoryChange{}, err
	}
	defer tx.Rollback()
	var functionID, projectID int64
	var name string
	var length uint32
	var rawMetadata []byte
	var score uint32
	if err := tx.QueryRowContext(ctx, `
SELECT fc.function_id, fn.database_id, fc.name, fc.length, fc.metadata, fc.score
FROM function_changes fc
JOIN functions fn ON fn.id=fc.function_id
WHERE fc.id=$1`, id).Scan(&functionID, &projectID, &name, &length, &rawMetadata, &score); err != nil {
		return HistoryChange{}, err
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE functions SET name=$1, length=$2, metadata=$3, score=$4, updated_at=CURRENT_TIMESTAMP
WHERE id=$5`, name, length, rawMetadata, score, functionID); err != nil {
		return HistoryChange{}, err
	}
	pushID, err := insertAdminPushTx(ctx, tx, projectID, "restore")
	if err != nil {
		return HistoryChange{}, err
	}
	var changeID int64
	if err := tx.QueryRowContext(ctx, `
INSERT INTO function_changes (push_id, function_id, name, length, metadata, score, operation)
VALUES ($1, $2, $3, $4, $5, $6, 'restore')
RETURNING id`, pushID, functionID, name, length, rawMetadata, score).Scan(&changeID); err != nil {
		return HistoryChange{}, err
	}
	if err := tx.Commit(); err != nil {
		return HistoryChange{}, err
	}
	return s.FunctionChange(ctx, changeID)
}

func (s *Store) DeleteFunctionChange(ctx context.Context, id int64) (HistoryDeleteResult, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return HistoryDeleteResult{}, err
	}
	defer tx.Rollback()
	var functionID int64
	if err := tx.QueryRowContext(ctx,
		"SELECT function_id FROM function_changes WHERE id=$1", id).Scan(&functionID); err != nil {
		if err == sql.ErrNoRows {
			return HistoryDeleteResult{Found: false}, nil
		}
		return HistoryDeleteResult{}, err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM function_changes WHERE id=$1", id); err != nil {
		return HistoryDeleteResult{}, err
	}
	if err := reconcileFunctionTx(ctx, tx, functionID); err != nil {
		return HistoryDeleteResult{}, err
	}
	if err := cleanupOrphans(ctx, tx); err != nil {
		return HistoryDeleteResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return HistoryDeleteResult{}, err
	}
	return HistoryDeleteResult{Found: true, DeletedChanges: 1}, nil
}

func (s *Store) DeletePush(ctx context.Context, id int64) (HistoryDeleteResult, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return HistoryDeleteResult{}, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx,
		"SELECT DISTINCT function_id FROM function_changes WHERE push_id=$1", id)
	if err != nil {
		return HistoryDeleteResult{}, err
	}
	var functionIDs []int64
	for rows.Next() {
		var functionID int64
		if err := rows.Scan(&functionID); err != nil {
			rows.Close()
			return HistoryDeleteResult{}, err
		}
		functionIDs = append(functionIDs, functionID)
	}
	if err := rows.Close(); err != nil {
		return HistoryDeleteResult{}, err
	}
	if err := rows.Err(); err != nil {
		return HistoryDeleteResult{}, err
	}
	var changes int64
	if err := tx.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM function_changes WHERE push_id=$1", id).Scan(&changes); err != nil {
		return HistoryDeleteResult{}, err
	}
	result, err := tx.ExecContext(ctx, "DELETE FROM pushes WHERE id=$1", id)
	if err != nil {
		return HistoryDeleteResult{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return HistoryDeleteResult{}, err
	}
	if affected == 0 {
		return HistoryDeleteResult{Found: false}, nil
	}
	for _, functionID := range functionIDs {
		if err := reconcileFunctionTx(ctx, tx, functionID); err != nil {
			return HistoryDeleteResult{}, err
		}
	}
	if err := cleanupOrphans(ctx, tx); err != nil {
		return HistoryDeleteResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return HistoryDeleteResult{}, err
	}
	return HistoryDeleteResult{Found: true, DeletedChanges: changes}, nil
}

const historySelect = `
SELECT fc.id, fc.push_id, fc.function_id, p.database_id, encode(fn.checksum, 'hex'),
       fc.name, fc.length, fc.score, fc.metadata, fc.operation,
       p.username, p.hostname, p.idb_path, p.file_path, encode(p.file_md5, 'hex'), fc.changed_at
FROM function_changes fc
JOIN functions fn ON fn.id=fc.function_id
JOIN pushes p ON p.id=fc.push_id`

func scanPush(row scanner) (PushSummary, error) {
	var push PushSummary
	var pushedAt time.Time
	err := row.Scan(&push.ID, &push.ProjectID, &push.ProtocolVersion, &push.Source,
		&push.Username, &push.Hostname, &push.IDBPath, &push.FilePath, &push.FileMD5,
		&push.SubmittedFunctions, &push.ChangedFunctions, &pushedAt)
	if err != nil {
		return PushSummary{}, err
	}
	push.PushedAt = formatTime(pushedAt)
	return push, nil
}

func scanHistoryChange(row scanner) (HistoryChange, error) {
	var change HistoryChange
	var rawMetadata []byte
	var changedAt time.Time
	err := row.Scan(&change.ID, &change.PushID, &change.FunctionID, &change.ProjectID,
		&change.Hash, &change.Name, &change.Length, &change.Score, &rawMetadata,
		&change.Operation, &change.Username, &change.Hostname, &change.IDBPath,
		&change.FilePath, &change.FileMD5, &changedAt)
	if err != nil {
		return HistoryChange{}, err
	}
	change.Metadata = hex.EncodeToString(rawMetadata)
	change.Comments = metadata.ParseBestEffort(rawMetadata)
	change.ChangedAt = formatTime(changedAt)
	return change, nil
}

func insertAdminPushTx(ctx context.Context, tx *sql.Tx, projectID int64, source string) (int64, error) {
	return upsertID(ctx, tx, `
INSERT INTO pushes (
  database_id, source, username, hostname, idb_path, file_path, file_md5,
  submitted_functions, changed_functions
)
SELECT db.id, $2, COALESCE(NULLIF(db.auth_username, ''), a.username, ''),
       u.hostname, db.idb_path, db.file_path, fi.checksum, 1, 1
FROM databases db
JOIN users u ON u.id=db.user_id
JOIN files fi ON fi.id=db.file_id
LEFT JOIN auth_accounts a ON a.id=db.auth_account_id
WHERE db.id=$1
RETURNING id`, projectID, source)
}

func reconcileFunctionTx(ctx context.Context, tx *sql.Tx, functionID int64) error {
	var name string
	var length uint32
	var rawMetadata []byte
	var score uint32
	err := tx.QueryRowContext(ctx, `
SELECT name, length, metadata, score
FROM function_changes WHERE function_id=$1
ORDER BY changed_at DESC, id DESC LIMIT 1`, functionID).
		Scan(&name, &length, &rawMetadata, &score)
	if err == sql.ErrNoRows {
		_, err = tx.ExecContext(ctx, "DELETE FROM functions WHERE id=$1", functionID)
		return err
	}
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
UPDATE functions SET name=$1, length=$2, metadata=$3, score=$4, updated_at=CURRENT_TIMESTAMP
WHERE id=$5`, name, length, rawMetadata, score, functionID)
	return err
}

func diffChanges(previous *HistoryChange, change HistoryChange) []FieldDiff {
	var out []FieldDiff
	if previous == nil {
		out = []FieldDiff{
			{Field: "name", After: change.Name},
			{Field: "length", After: change.Length},
			{Field: "score", After: change.Score},
			{Field: "metadata.raw", After: change.Metadata},
			{Field: "comments", After: change.Comments},
		}
		for _, field := range semanticFieldsFromHex(change.Metadata) {
			out = append(out, FieldDiff{Field: field.Field, After: field.Value})
		}
		return out
	}
	if previous.Name != change.Name {
		out = append(out, FieldDiff{Field: "name", Before: previous.Name, After: change.Name})
	}
	if previous.Length != change.Length {
		out = append(out, FieldDiff{Field: "length", Before: previous.Length, After: change.Length})
	}
	if previous.Score != change.Score {
		out = append(out, FieldDiff{Field: "score", Before: previous.Score, After: change.Score})
	}
	if previous.Metadata != change.Metadata {
		out = append(out, FieldDiff{
			Field: "metadata.raw", Before: previous.Metadata, After: change.Metadata,
		})
		before, beforeErr := hex.DecodeString(previous.Metadata)
		after, afterErr := hex.DecodeString(change.Metadata)
		if beforeErr == nil && afterErr == nil {
			for _, difference := range metadata.SemanticDiff(before, after) {
				out = append(out, FieldDiff{
					Field:  difference.Field,
					Before: difference.Before,
					After:  difference.After,
				})
			}
		}
	}
	if !reflect.DeepEqual(previous.Comments, change.Comments) {
		out = append(out, FieldDiff{Field: "comments", Before: previous.Comments, After: change.Comments})
	}
	return out
}

func inspectMetadataHex(value string) metadata.Document {
	raw, err := hex.DecodeString(value)
	if err != nil {
		return metadata.Document{Error: err.Error()}
	}
	return metadata.Inspect(raw)
}

func semanticFieldsFromHex(value string) []metadata.SemanticField {
	raw, err := hex.DecodeString(value)
	if err != nil {
		return []metadata.SemanticField{{
			Field: "metadata.parse_error",
			Value: map[string]any{"error": err.Error()},
		}}
	}
	return metadata.SemanticFields(raw)
}

func normalizePagination(limit, offset int) (int, int) {
	if limit < 1 || limit > 500 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

func nullableTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return *value
}
