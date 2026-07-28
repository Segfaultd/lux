package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/segfaultd/lux/internal/access"
	"github.com/segfaultd/lux/internal/store"
	"golang.org/x/crypto/bcrypt"
)

const (
	maxUsernameBytes = 128
	minPasswordBytes = 8
	maxPasswordBytes = 72
)

var (
	ErrInvalidUsername    = errors.New("username must be 1-128 characters without control characters or slashes")
	ErrInvalidPassword    = errors.New("password must be 8-72 bytes")
	ErrInvalidCredentials = errors.New("invalid username or password")
	dummyPasswordHash     = mustHashDummyPassword()
)

type Principal struct {
	ID       int64
	Username string
	Role     access.Role
}

func (p Principal) Can(capability access.Capability) bool {
	return p.Role.Can(capability)
}

type Service struct {
	store *store.Store
}

func New(database *store.Store) *Service {
	return &Service{store: database}
}

func (s *Service) Bootstrap(ctx context.Context, username, password string) error {
	count, err := s.store.CountAuthAccounts(ctx)
	if err != nil {
		return err
	}
	if count != 0 {
		return nil
	}
	username, err = normalizeUsername(username)
	if err != nil {
		return err
	}
	var passwordHash []byte
	if password != "" {
		passwordHash, err = hashManagedPassword(password)
		if err != nil {
			return err
		}
	}
	_, err = s.store.CreateAuthAccountWithRole(ctx, username, passwordHash, access.RoleAdmin)
	if errors.Is(err, store.ErrAuthAccountExists) {
		return nil
	}
	return err
}

func (s *Service) Authenticate(ctx context.Context, username, password string) (Principal, error) {
	normalized, err := normalizeUsername(username)
	if err != nil {
		_ = bcrypt.CompareHashAndPassword(dummyPasswordHash, []byte(password))
		return Principal{}, ErrInvalidCredentials
	}
	record, err := s.store.AuthAccountByUsername(ctx, normalized)
	if errors.Is(err, store.ErrAuthAccountNotFound) {
		_ = bcrypt.CompareHashAndPassword(dummyPasswordHash, []byte(password))
		return Principal{}, ErrInvalidCredentials
	}
	if err != nil {
		return Principal{}, err
	}

	passwordValid := !record.PasswordSet
	if record.PasswordSet {
		passwordValid = bcrypt.CompareHashAndPassword(record.PasswordHash, []byte(password)) == nil
	}
	if !record.Enabled || !passwordValid {
		return Principal{}, ErrInvalidCredentials
	}
	if err := s.store.RecordAuthAccountLogin(ctx, record.ID); err != nil {
		return Principal{}, err
	}
	return Principal{ID: record.ID, Username: record.Username, Role: record.Role}, nil
}

func (s *Service) List(ctx context.Context) ([]store.AuthAccount, error) {
	accounts, err := s.store.ListAuthAccounts(ctx)
	if accounts == nil && err == nil {
		accounts = []store.AuthAccount{}
	}
	return accounts, err
}

func (s *Service) Create(ctx context.Context, username, password string) (store.AuthAccount, error) {
	return s.CreateWithRole(ctx, username, password, access.RoleContributor)
}

func (s *Service) CreateWithRole(
	ctx context.Context, username, password string, role access.Role,
) (store.AuthAccount, error) {
	username, err := normalizeUsername(username)
	if err != nil {
		return store.AuthAccount{}, err
	}
	role, err = access.ParseRole(string(role))
	if err != nil {
		return store.AuthAccount{}, err
	}
	passwordHash, err := hashManagedPassword(password)
	if err != nil {
		return store.AuthAccount{}, err
	}
	return s.store.CreateAuthAccountWithRole(ctx, username, passwordHash, role)
}

func (s *Service) SetPassword(ctx context.Context, username, password string) (store.AuthAccount, error) {
	username, err := normalizeUsername(username)
	if err != nil {
		return store.AuthAccount{}, err
	}
	passwordHash, err := hashManagedPassword(password)
	if err != nil {
		return store.AuthAccount{}, err
	}
	return s.store.UpdateAuthAccountPassword(ctx, username, passwordHash)
}

func (s *Service) SetEnabled(ctx context.Context, username string, enabled bool) (store.AuthAccount, error) {
	username, err := normalizeUsername(username)
	if err != nil {
		return store.AuthAccount{}, err
	}
	return s.store.UpdateAuthAccountEnabled(ctx, username, enabled)
}

func (s *Service) SetRole(ctx context.Context, username string, role access.Role) (store.AuthAccount, error) {
	username, err := normalizeUsername(username)
	if err != nil {
		return store.AuthAccount{}, err
	}
	role, err = access.ParseRole(string(role))
	if err != nil {
		return store.AuthAccount{}, err
	}
	return s.store.UpdateAuthAccountRole(ctx, username, role)
}

func (s *Service) Delete(ctx context.Context, username string) (store.AuthAccount, error) {
	username, err := normalizeUsername(username)
	if err != nil {
		return store.AuthAccount{}, err
	}
	return s.store.DeleteAuthAccount(ctx, username)
}

func normalizeUsername(username string) (string, error) {
	username = strings.TrimSpace(username)
	if username == "" || len(username) > maxUsernameBytes || !utf8.ValidString(username) {
		return "", ErrInvalidUsername
	}
	for _, r := range username {
		if unicode.IsControl(r) || r == '/' || r == '\\' {
			return "", ErrInvalidUsername
		}
	}
	return username, nil
}

func hashManagedPassword(password string) ([]byte, error) {
	if len(password) < minPasswordBytes || len(password) > maxPasswordBytes {
		return nil, ErrInvalidPassword
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}
	return hash, nil
}

func mustHashDummyPassword() []byte {
	hash, err := bcrypt.GenerateFromPassword([]byte("lux-invalid-account"), bcrypt.DefaultCost)
	if err != nil {
		panic(fmt.Sprintf("initialize dummy password hash: %v", err))
	}
	return hash
}
