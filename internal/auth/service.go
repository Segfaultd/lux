package auth

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/segfaultd/lux/internal/access"
	"github.com/segfaultd/lux/internal/store"
	"golang.org/x/crypto/bcrypt"
)

const (
	maxUsernameBytes = 128
	maxEmailBytes    = 320
	minPasswordBytes = 8
	maxPasswordBytes = 72
)

var (
	ErrInvalidUsername    = errors.New("username must be 1-128 characters without control characters or slashes")
	ErrInvalidEmail       = errors.New("email must be at most 320 characters without control characters")
	ErrInvalidLicenseID   = errors.New("license ID must use the XX-XXXX-XXXX-XX hexadecimal format")
	ErrInvalidPassword    = errors.New("password must be 8-72 bytes")
	ErrInvalidCredentials = errors.New("invalid username or password")
	dummyPasswordHash     = mustHashDummyPassword()
	licenseIDPattern      = regexp.MustCompile(`^[0-9A-F]{2}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{2}$`)
)

type Principal struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	LicenseID string `json:"license_id"`
	access.Permissions
}

func (p Principal) Can(capability access.Capability) bool {
	return p.Permissions.Can(capability)
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
	_, err = s.store.CreateAuthAccountWithProfile(ctx, username, passwordHash, store.AuthAccountProfile{
		IsAdmin:          true,
		CanDeleteHistory: true,
	})
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

	passwordValid := record.PasswordSet &&
		bcrypt.CompareHashAndPassword(record.PasswordHash, []byte(password)) == nil
	if !record.Enabled || !passwordValid {
		return Principal{}, ErrInvalidCredentials
	}
	if err := s.store.RecordAuthAccountLogin(ctx, record.ID); err != nil {
		return Principal{}, err
	}
	return Principal{
		ID: record.ID, Username: record.Username, Email: record.Email, LicenseID: record.LicenseID,
		Permissions: access.Permissions{
			IsAdmin: record.IsAdmin, CanDeleteHistory: record.CanDeleteHistory,
		},
	}, nil
}

func (s *Service) List(ctx context.Context) ([]store.AuthAccount, error) {
	accounts, err := s.store.ListAuthAccounts(ctx)
	if accounts == nil && err == nil {
		accounts = []store.AuthAccount{}
	}
	return accounts, err
}

func (s *Service) Create(ctx context.Context, username, password string) (store.AuthAccount, error) {
	return s.CreateWithProfile(ctx, username, password, store.AuthAccountProfile{})
}

func (s *Service) CreateWithProfile(
	ctx context.Context, username, password string, profile store.AuthAccountProfile,
) (store.AuthAccount, error) {
	username, err := normalizeUsername(username)
	if err != nil {
		return store.AuthAccount{}, err
	}
	profile.Email, err = normalizeEmail(profile.Email)
	if err != nil {
		return store.AuthAccount{}, err
	}
	profile.LicenseID, err = normalizeLicenseID(profile.LicenseID)
	if err != nil {
		return store.AuthAccount{}, err
	}
	var passwordHash []byte
	if password != "" {
		passwordHash, err = hashManagedPassword(password)
		if err != nil {
			return store.AuthAccount{}, err
		}
	}
	return s.store.CreateAuthAccountWithProfile(ctx, username, passwordHash, profile)
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

func (s *Service) SetProfile(
	ctx context.Context,
	username string,
	email *string,
	licenseID *string,
	isAdmin *bool,
	canDeleteHistory *bool,
) (store.AuthAccount, error) {
	username, err := normalizeUsername(username)
	if err != nil {
		return store.AuthAccount{}, err
	}
	if email != nil {
		normalized, normalizeErr := normalizeEmail(*email)
		if normalizeErr != nil {
			return store.AuthAccount{}, normalizeErr
		}
		email = &normalized
	}
	if licenseID != nil {
		normalized, normalizeErr := normalizeLicenseID(*licenseID)
		if normalizeErr != nil {
			return store.AuthAccount{}, normalizeErr
		}
		licenseID = &normalized
	}
	return s.store.UpdateAuthAccountProfile(
		ctx, username, email, licenseID, isAdmin, canDeleteHistory)
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

func normalizeEmail(email string) (string, error) {
	email = strings.TrimSpace(email)
	if len(email) > maxEmailBytes || !utf8.ValidString(email) {
		return "", ErrInvalidEmail
	}
	for _, r := range email {
		if unicode.IsControl(r) {
			return "", ErrInvalidEmail
		}
	}
	return email, nil
}

func normalizeLicenseID(licenseID string) (string, error) {
	licenseID = strings.ToUpper(strings.TrimSpace(licenseID))
	if licenseID != "" && !licenseIDPattern.MatchString(licenseID) {
		return "", ErrInvalidLicenseID
	}
	return licenseID, nil
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
