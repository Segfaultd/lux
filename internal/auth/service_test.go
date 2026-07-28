package auth

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/segfaultd/lux/internal/access"
	"github.com/segfaultd/lux/internal/store"
	"github.com/segfaultd/lux/internal/testdb"
)

func TestDynamicAccountLifecycleAndAuthentication(t *testing.T) {
	database, err := store.Open(testdb.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	service := New(database)
	ctx := context.Background()

	if accounts, err := service.List(ctx); err != nil || len(accounts) != 0 {
		t.Fatalf("initial accounts %#v: %v", accounts, err)
	}
	if err := service.Bootstrap(ctx, "guest", ""); err != nil {
		t.Fatal(err)
	}
	if err := service.Bootstrap(ctx, "ignored", "ignored-password"); err != nil {
		t.Fatal(err)
	}
	principal, err := service.Authenticate(ctx, " GUEST ", "any-password")
	if err != nil || principal.Username != "guest" || principal.ID == 0 ||
		principal.Role != access.RoleAdmin || !principal.Can(access.CapabilityManage) {
		t.Fatalf("bootstrap authentication: %#v, %v", principal, err)
	}

	account, err := service.Create(ctx, "Analyst", "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if !account.Enabled || !account.PasswordSet || account.Role != access.RoleContributor {
		t.Fatalf("unexpected account: %#v", account)
	}
	if _, err := service.Create(ctx, "analyst", "another password"); !errors.Is(err, store.ErrAuthAccountExists) {
		t.Fatalf("duplicate account error: %v", err)
	}
	principal, err = service.Authenticate(ctx, "ANALYST", "correct horse")
	if err != nil || principal.ID != account.ID || principal.Username != "Analyst" {
		t.Fatalf("managed authentication: %#v, %v", principal, err)
	}
	for _, attempt := range []struct {
		username string
		password string
	}{
		{"Analyst", "wrong password"},
		{"missing", "correct horse"},
		{"bad/name", "correct horse"},
	} {
		if _, err := service.Authenticate(ctx, attempt.username, attempt.password); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("authentication %q returned %v", attempt.username, err)
		}
	}

	if _, err := service.SetPassword(ctx, "Analyst", "rotated password"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Authenticate(ctx, "Analyst", "correct horse"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("old password returned %v", err)
	}
	if _, err := service.Authenticate(ctx, "Analyst", "rotated password"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.SetEnabled(ctx, "Analyst", false); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Authenticate(ctx, "Analyst", "rotated password"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("disabled account returned %v", err)
	}
	if _, err := service.SetEnabled(ctx, "Analyst", true); err != nil {
		t.Fatal(err)
	}
	account, err = service.SetRole(ctx, "Analyst", access.RoleReader)
	if err != nil || account.Role != access.RoleReader {
		t.Fatalf("set role: %#v, %v", account, err)
	}
	principal, err = service.Authenticate(ctx, "Analyst", "rotated password")
	if err != nil || principal.Role != access.RoleReader ||
		principal.Can(access.CapabilityPush) || !principal.Can(access.CapabilityPull) {
		t.Fatalf("reader principal: %#v, %v", principal, err)
	}

	accounts, err := service.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 2 || accounts[1].LastLoginAt == "" {
		t.Fatalf("unexpected accounts: %#v", accounts)
	}
	if _, err := service.Delete(ctx, "Analyst"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Delete(ctx, "guest"); !errors.Is(err, store.ErrLastAuthAccount) {
		t.Fatalf("delete last account returned %v", err)
	}
	if _, err := service.SetEnabled(ctx, "guest", false); !errors.Is(err, store.ErrLastAuthAccount) {
		t.Fatalf("disable last account returned %v", err)
	}
}

func TestAccountValidationAndDatabaseErrors(t *testing.T) {
	database, err := store.Open(testdb.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	service := New(database)
	ctx := context.Background()

	if err := service.Bootstrap(ctx, "", ""); !errors.Is(err, ErrInvalidUsername) {
		t.Fatalf("invalid bootstrap username returned %v", err)
	}
	for _, username := range []string{"", "bad/name", "bad\\name", "bad\nname", strings.Repeat("x", 129)} {
		if _, err := service.Create(ctx, username, "valid password"); !errors.Is(err, ErrInvalidUsername) {
			t.Fatalf("username %q returned %v", username, err)
		}
	}
	for _, password := range []string{"short", strings.Repeat("x", 73)} {
		if _, err := service.Create(ctx, "valid", password); !errors.Is(err, ErrInvalidPassword) {
			t.Fatalf("password length %d returned %v", len(password), err)
		}
	}
	if err := service.Bootstrap(ctx, "guest", strings.Repeat("x", 73)); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("oversized bootstrap password returned %v", err)
	}
	if err := service.Bootstrap(ctx, "guest", "short"); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("short bootstrap password returned %v", err)
	}
	if _, err := service.SetPassword(ctx, "missing", "valid password"); !errors.Is(err, store.ErrAuthAccountNotFound) {
		t.Fatalf("missing password update returned %v", err)
	}
	if _, err := service.SetPassword(ctx, "bad/name", "valid password"); !errors.Is(err, ErrInvalidUsername) {
		t.Fatalf("invalid password username returned %v", err)
	}
	if _, err := service.SetEnabled(ctx, "missing", true); !errors.Is(err, store.ErrAuthAccountNotFound) {
		t.Fatalf("missing enable returned %v", err)
	}
	if _, err := service.SetEnabled(ctx, "bad/name", true); !errors.Is(err, ErrInvalidUsername) {
		t.Fatalf("invalid enable username returned %v", err)
	}
	if _, err := service.SetRole(ctx, "missing", access.RoleReader); !errors.Is(err, store.ErrAuthAccountNotFound) {
		t.Fatalf("missing role update returned %v", err)
	}
	if _, err := service.SetRole(ctx, "valid", access.Role("owner")); !errors.Is(err, access.ErrInvalidRole) {
		t.Fatalf("invalid role update returned %v", err)
	}
	if _, err := service.SetRole(ctx, "bad/name", access.RoleReader); !errors.Is(err, ErrInvalidUsername) {
		t.Fatalf("invalid role username returned %v", err)
	}
	if _, err := service.CreateWithRole(ctx, "owner", "valid password", access.Role("owner")); !errors.Is(err, access.ErrInvalidRole) {
		t.Fatalf("invalid create role returned %v", err)
	}
	if _, err := service.Delete(ctx, "missing"); !errors.Is(err, store.ErrAuthAccountNotFound) {
		t.Fatalf("missing delete returned %v", err)
	}
	if _, err := service.Delete(ctx, "bad/name"); !errors.Is(err, ErrInvalidUsername) {
		t.Fatalf("invalid delete username returned %v", err)
	}

	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if err := service.Bootstrap(ctx, "guest", ""); err == nil {
		t.Fatal("bootstrap unexpectedly succeeded against closed database")
	}
	if _, err := service.Authenticate(ctx, "guest", "password"); err == nil {
		t.Fatal("authentication unexpectedly succeeded against closed database")
	}
	if _, err := service.List(ctx); err == nil {
		t.Fatal("list unexpectedly succeeded against closed database")
	}
}

func TestBootstrapWithPassword(t *testing.T) {
	database, err := store.Open(testdb.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	service := New(database)
	ctx := context.Background()
	if err := service.Bootstrap(ctx, "secure", "secure password"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Authenticate(ctx, "secure", "secure password"); err != nil {
		t.Fatal(err)
	}
}
