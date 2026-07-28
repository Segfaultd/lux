package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/segfaultd/lux/internal/testdb"
)

func TestLegacyRolesMigrateToOfficialUserFlags(t *testing.T) {
	connectionURL := testdb.URL(t)
	legacy, err := sql.Open("pgx", connectionURL)
	if err != nil {
		t.Fatal(err)
	}
	_, err = legacy.Exec(`
CREATE TABLE auth_accounts (
  id BIGSERIAL PRIMARY KEY,
  username TEXT NOT NULL,
  password_hash BYTEA,
  role TEXT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_login_at TIMESTAMPTZ
);
INSERT INTO auth_accounts (username, role) VALUES ('administrator', 'admin'), ('analyst', 'contributor')`)
	if err != nil {
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}

	database, err := Open(connectionURL)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	admin, err := database.AuthAccountByUsername(context.Background(), "administrator")
	if err != nil || !admin.IsAdmin || !admin.CanDeleteHistory {
		t.Fatalf("migrated administrator %#v: %v", admin, err)
	}
	regular, err := database.AuthAccountByUsername(context.Background(), "analyst")
	if err != nil || regular.IsAdmin || regular.CanDeleteHistory {
		t.Fatalf("migrated regular account %#v: %v", regular, err)
	}
}

func TestAuthAccountPersistenceLifecycle(t *testing.T) {
	database, err := Open(testdb.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	ctx := context.Background()

	if count, err := database.CountAuthAccounts(ctx); err != nil || count != 0 {
		t.Fatalf("initial account count %d: %v", count, err)
	}
	if accounts, err := database.ListAuthAccounts(ctx); err != nil || len(accounts) != 0 {
		t.Fatalf("initial accounts %#v: %v", accounts, err)
	}
	alice, err := database.CreateAuthAccount(ctx, "Alice", []byte("hash-one"))
	if err != nil {
		t.Fatal(err)
	}
	if !alice.Enabled || !alice.PasswordSet || alice.IsAdmin || alice.CanDeleteHistory ||
		alice.CreatedAt == "" || alice.UpdatedAt == "" {
		t.Fatalf("unexpected created account: %#v", alice)
	}
	if _, err := database.CreateAuthAccount(ctx, "alice", []byte("hash-two")); !errors.Is(err, ErrAuthAccountExists) {
		t.Fatalf("duplicate account returned %v", err)
	}
	record, err := database.AuthAccountByUsername(ctx, "ALICE")
	if err != nil || string(record.PasswordHash) != "hash-one" {
		t.Fatalf("account record %#v: %v", record, err)
	}
	if _, err := database.AuthAccountByUsername(ctx, "missing"); !errors.Is(err, ErrAuthAccountNotFound) {
		t.Fatalf("missing account returned %v", err)
	}
	if err := database.RecordAuthAccountLogin(ctx, alice.ID); err != nil {
		t.Fatal(err)
	}
	if err := database.RecordAuthAccountLogin(ctx, 999999); !errors.Is(err, ErrAuthAccountNotFound) {
		t.Fatalf("missing login record returned %v", err)
	}
	record, err = database.AuthAccountByUsername(ctx, "alice")
	if err != nil || record.LastLoginAt == "" {
		t.Fatalf("last login was not stored: %#v, %v", record, err)
	}
	updated, err := database.UpdateAuthAccountPassword(ctx, "alice", []byte("new-hash"))
	if err != nil || !updated.PasswordSet {
		t.Fatalf("password update %#v: %v", updated, err)
	}
	if _, err := database.UpdateAuthAccountPassword(ctx, "missing", []byte("hash")); !errors.Is(err, ErrAuthAccountNotFound) {
		t.Fatalf("missing password update returned %v", err)
	}
	email := "alice@example.test"
	licenseID := "AB-1234-CDEF-90"
	isAdmin := true
	canDelete := true
	updated, err = database.UpdateAuthAccountProfile(
		ctx, "alice", &email, &licenseID, &isAdmin, &canDelete)
	if err != nil || !updated.IsAdmin || !updated.CanDeleteHistory ||
		updated.Email != email || updated.LicenseID != licenseID {
		t.Fatalf("profile update %#v: %v", updated, err)
	}
	if _, err := database.UpdateAuthAccountProfile(
		ctx, "missing", nil, nil, &isAdmin, nil,
	); !errors.Is(err, ErrAuthAccountNotFound) {
		t.Fatalf("missing profile update returned %v", err)
	}
	if _, err := database.UpdateAuthAccountEnabled(ctx, "missing", false); !errors.Is(err, ErrAuthAccountNotFound) {
		t.Fatalf("missing enabled update returned %v", err)
	}
	if _, err := database.UpdateAuthAccountEnabled(ctx, "alice", false); !errors.Is(err, ErrLastAuthAccount) {
		t.Fatalf("disabled last account returned %v", err)
	}

	bob, err := database.CreateAuthAccount(ctx, "bob", nil)
	if err != nil || bob.PasswordSet {
		t.Fatalf("passwordless account %#v: %v", bob, err)
	}
	bob, err = database.UpdateAuthAccountEnabled(ctx, "bob", false)
	if err != nil || bob.Enabled {
		t.Fatalf("disable bob %#v: %v", bob, err)
	}
	bob, err = database.UpdateAuthAccountEnabled(ctx, "bob", false)
	if err != nil || bob.Enabled {
		t.Fatalf("repeat disable bob %#v: %v", bob, err)
	}
	bob, err = database.UpdateAuthAccountEnabled(ctx, "bob", true)
	if err != nil || !bob.Enabled {
		t.Fatalf("enable bob %#v: %v", bob, err)
	}
	bob, err = database.UpdateAuthAccountEnabled(ctx, "bob", false)
	if err != nil || bob.Enabled {
		t.Fatalf("disable bob again %#v: %v", bob, err)
	}
	if _, err := database.DeleteAuthAccount(ctx, "missing"); !errors.Is(err, ErrAuthAccountNotFound) {
		t.Fatalf("missing delete returned %v", err)
	}
	if _, err := database.DeleteAuthAccount(ctx, "bob"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.DeleteAuthAccount(ctx, "alice"); !errors.Is(err, ErrLastAuthAccount) {
		t.Fatalf("delete last account returned %v", err)
	}
	if _, err := database.CreateAuthAccount(ctx, "bob", []byte("hash")); err != nil {
		t.Fatal(err)
	}
	if _, err := database.DeleteAuthAccount(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	accounts, err := database.ListAuthAccounts(ctx)
	if err != nil || len(accounts) != 1 || accounts[0].Username != "bob" {
		t.Fatalf("final accounts %#v: %v", accounts, err)
	}
}

func TestAuthAccountClosedDatabaseErrors(t *testing.T) {
	database, err := Open(testdb.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	calls := []struct {
		name string
		call func() error
	}{
		{"count", func() error { _, err := database.CountAuthAccounts(ctx); return err }},
		{"create", func() error { _, err := database.CreateAuthAccount(ctx, "user", []byte("hash")); return err }},
		{"get", func() error { _, err := database.AuthAccountByUsername(ctx, "user"); return err }},
		{"list", func() error { _, err := database.ListAuthAccounts(ctx); return err }},
		{"password", func() error { _, err := database.UpdateAuthAccountPassword(ctx, "user", []byte("hash")); return err }},
		{"enabled", func() error { _, err := database.UpdateAuthAccountEnabled(ctx, "user", false); return err }},
		{"profile", func() error {
			value := true
			_, err := database.UpdateAuthAccountProfile(ctx, "user", nil, nil, &value, nil)
			return err
		}},
		{"delete", func() error { _, err := database.DeleteAuthAccount(ctx, "user"); return err }},
		{"login", func() error { return database.RecordAuthAccountLogin(ctx, 1) }},
	}
	for _, test := range calls {
		t.Run(test.name, func(t *testing.T) {
			if err := test.call(); err == nil {
				t.Fatal("expected closed database error")
			}
		})
	}
}
