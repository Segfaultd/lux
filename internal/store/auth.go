package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/segfaultd/lux/internal/access"
)

type rowScanner interface {
	Scan(dest ...any) error
}

func (s *Store) CountAuthAccounts(ctx context.Context) (int64, error) {
	var count int64
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM auth_accounts").Scan(&count)
	return count, err
}

func (s *Store) CreateAuthAccount(ctx context.Context, username string, passwordHash []byte) (AuthAccount, error) {
	return s.CreateAuthAccountWithRole(ctx, username, passwordHash, access.RoleContributor)
}

func (s *Store) CreateAuthAccountWithRole(
	ctx context.Context, username string, passwordHash []byte, role access.Role,
) (AuthAccount, error) {
	row := s.db.QueryRowContext(ctx, `
INSERT INTO auth_accounts (username, password_hash, role)
VALUES ($1, $2, $3)
ON CONFLICT ((lower(username))) DO NOTHING
RETURNING id, username, role, enabled, password_hash IS NOT NULL, created_at, updated_at, last_login_at`,
		username, passwordHash, role)
	account, err := scanAuthAccount(row)
	if errors.Is(err, sql.ErrNoRows) {
		return AuthAccount{}, ErrAuthAccountExists
	}
	return account, err
}

func (s *Store) AuthAccountByUsername(ctx context.Context, username string) (AuthAccountRecord, error) {
	var record AuthAccountRecord
	var createdAt, updatedAt time.Time
	var lastLoginAt sql.NullTime
	err := s.db.QueryRowContext(ctx, `
SELECT id, username, role, enabled, password_hash IS NOT NULL, created_at, updated_at, last_login_at, password_hash
FROM auth_accounts
WHERE lower(username)=lower($1)`, username).Scan(
		&record.ID, &record.Username, &record.Role, &record.Enabled, &record.PasswordSet,
		&createdAt, &updatedAt, &lastLoginAt, &record.PasswordHash)
	if errors.Is(err, sql.ErrNoRows) {
		return AuthAccountRecord{}, ErrAuthAccountNotFound
	}
	if err != nil {
		return AuthAccountRecord{}, err
	}
	setAuthAccountTimes(&record.AuthAccount, createdAt, updatedAt, lastLoginAt)
	return record, nil
}

func (s *Store) ListAuthAccounts(ctx context.Context) ([]AuthAccount, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, username, role, enabled, password_hash IS NOT NULL, created_at, updated_at, last_login_at
FROM auth_accounts
ORDER BY lower(username), id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var accounts []AuthAccount
	for rows.Next() {
		account, err := scanAuthAccount(rows)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, account)
	}
	return accounts, rows.Err()
}

func (s *Store) UpdateAuthAccountPassword(ctx context.Context, username string, passwordHash []byte) (AuthAccount, error) {
	account, err := scanAuthAccount(s.db.QueryRowContext(ctx, `
UPDATE auth_accounts
SET password_hash=$2, updated_at=CURRENT_TIMESTAMP
WHERE lower(username)=lower($1)
RETURNING id, username, role, enabled, password_hash IS NOT NULL, created_at, updated_at, last_login_at`,
		username, passwordHash))
	if errors.Is(err, sql.ErrNoRows) {
		return AuthAccount{}, ErrAuthAccountNotFound
	}
	return account, err
}

func (s *Store) UpdateAuthAccountEnabled(ctx context.Context, username string, enabled bool) (AuthAccount, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AuthAccount{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "LOCK TABLE auth_accounts IN SHARE ROW EXCLUSIVE MODE"); err != nil {
		return AuthAccount{}, err
	}
	var currentlyEnabled bool
	err = tx.QueryRowContext(ctx,
		"SELECT enabled FROM auth_accounts WHERE lower(username)=lower($1)", username).Scan(&currentlyEnabled)
	if errors.Is(err, sql.ErrNoRows) {
		return AuthAccount{}, ErrAuthAccountNotFound
	}
	if err != nil {
		return AuthAccount{}, err
	}
	if currentlyEnabled && !enabled {
		var enabledCount int64
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM auth_accounts WHERE enabled").Scan(&enabledCount); err != nil {
			return AuthAccount{}, err
		}
		if enabledCount <= 1 {
			return AuthAccount{}, ErrLastAuthAccount
		}
	}
	account, err := scanAuthAccount(tx.QueryRowContext(ctx, `
UPDATE auth_accounts
SET enabled=$2, updated_at=CURRENT_TIMESTAMP
WHERE lower(username)=lower($1)
RETURNING id, username, role, enabled, password_hash IS NOT NULL, created_at, updated_at, last_login_at`,
		username, enabled))
	if err != nil {
		return AuthAccount{}, err
	}
	if err := tx.Commit(); err != nil {
		return AuthAccount{}, err
	}
	return account, nil
}

func (s *Store) UpdateAuthAccountRole(ctx context.Context, username string, role access.Role) (AuthAccount, error) {
	account, err := scanAuthAccount(s.db.QueryRowContext(ctx, `
UPDATE auth_accounts
SET role=$2, updated_at=CURRENT_TIMESTAMP
WHERE lower(username)=lower($1)
RETURNING id, username, role, enabled, password_hash IS NOT NULL, created_at, updated_at, last_login_at`,
		username, role))
	if errors.Is(err, sql.ErrNoRows) {
		return AuthAccount{}, ErrAuthAccountNotFound
	}
	return account, err
}

func (s *Store) DeleteAuthAccount(ctx context.Context, username string) (AuthAccount, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AuthAccount{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "LOCK TABLE auth_accounts IN SHARE ROW EXCLUSIVE MODE"); err != nil {
		return AuthAccount{}, err
	}
	var enabled bool
	err = tx.QueryRowContext(ctx,
		"SELECT enabled FROM auth_accounts WHERE lower(username)=lower($1)", username).Scan(&enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return AuthAccount{}, ErrAuthAccountNotFound
	}
	if err != nil {
		return AuthAccount{}, err
	}
	if enabled {
		var enabledCount int64
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM auth_accounts WHERE enabled").Scan(&enabledCount); err != nil {
			return AuthAccount{}, err
		}
		if enabledCount <= 1 {
			return AuthAccount{}, ErrLastAuthAccount
		}
	}
	account, err := scanAuthAccount(tx.QueryRowContext(ctx, `
DELETE FROM auth_accounts
WHERE lower(username)=lower($1)
RETURNING id, username, role, enabled, password_hash IS NOT NULL, created_at, updated_at, last_login_at`, username))
	if err != nil {
		return AuthAccount{}, err
	}
	if err := tx.Commit(); err != nil {
		return AuthAccount{}, err
	}
	return account, nil
}

func (s *Store) RecordAuthAccountLogin(ctx context.Context, id int64) error {
	result, err := s.db.ExecContext(ctx, `
UPDATE auth_accounts
SET last_login_at=CURRENT_TIMESTAMP
WHERE id=$1`, id)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrAuthAccountNotFound
	}
	return nil
}

func scanAuthAccount(row rowScanner) (AuthAccount, error) {
	var account AuthAccount
	var createdAt, updatedAt time.Time
	var lastLoginAt sql.NullTime
	err := row.Scan(&account.ID, &account.Username, &account.Role, &account.Enabled, &account.PasswordSet,
		&createdAt, &updatedAt, &lastLoginAt)
	if err != nil {
		return AuthAccount{}, err
	}
	setAuthAccountTimes(&account, createdAt, updatedAt, lastLoginAt)
	return account, nil
}

func setAuthAccountTimes(account *AuthAccount, createdAt, updatedAt time.Time, lastLoginAt sql.NullTime) {
	account.CreatedAt = formatTime(createdAt)
	account.UpdatedAt = formatTime(updatedAt)
	if lastLoginAt.Valid {
		account.LastLoginAt = formatTime(lastLoginAt.Time)
	}
}
