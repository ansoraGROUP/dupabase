package platform

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

type CredentialService struct {
	db      *pgxpool.Pool
	baseURL string
}

func NewCredentialService(db *pgxpool.Pool, databaseURL string) *CredentialService {
	// Parse DATABASE_URL to extract host/port for user display
	parsed, _ := url.Parse(databaseURL)
	base := fmt.Sprintf("%s:%s", parsed.Hostname(), parsed.Port())

	return &CredentialService{db: db, baseURL: base}
}

type RevealRequest struct {
	PlatformPassword string `json:"platform_password"`
}

type CredentialResponse struct {
	PgUsername string `json:"pg_username"`
	PgPassword string `json:"pg_password"`
	PgHost     string `json:"pg_host"`
	PgPort     string `json:"pg_port"`
}

// RevealCredentials decrypts and returns the user's PostgreSQL credentials.
func (s *CredentialService) RevealCredentials(ctx context.Context, userID string, req RevealRequest) (*CredentialResponse, int, error) {
	if req.PlatformPassword == "" {
		return nil, http.StatusBadRequest, fmt.Errorf("platform_password is required")
	}

	// Verify platform password
	var passwordHash string
	err := s.db.QueryRow(ctx, `
		SELECT password_hash FROM platform.users WHERE id = $1
	`, userID).Scan(&passwordHash)
	if err != nil {
		return nil, http.StatusNotFound, fmt.Errorf("user not found")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.PlatformPassword)); err != nil {
		return nil, http.StatusUnauthorized, fmt.Errorf("invalid password")
	}

	// Get encrypted PG password
	var pgUsername, pgPasswordEncrypted string
	err = s.db.QueryRow(ctx, `
		SELECT pg_username, pg_password_encrypted
		FROM platform.pg_users WHERE user_id = $1
	`, userID).Scan(&pgUsername, &pgPasswordEncrypted)
	if err != nil {
		return nil, http.StatusNotFound, fmt.Errorf("pg credentials not found")
	}

	// Decrypt PG password
	pgPassword, err := DecryptPgPassword(pgPasswordEncrypted, req.PlatformPassword)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("decrypt failed: %w", err)
	}

	parsed, _ := url.Parse("postgresql://" + s.baseURL)

	return &CredentialResponse{
		PgUsername: pgUsername,
		PgPassword: pgPassword,
		PgHost:     parsed.Hostname(),
		PgPort:     parsed.Port(),
	}, http.StatusOK, nil
}
