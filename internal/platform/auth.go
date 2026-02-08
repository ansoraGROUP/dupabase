package platform

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

// pgUsernameRegex validates generated PG usernames (u_ + 12 hex chars)
var pgUsernameRegex = regexp.MustCompile(`^u_[a-f0-9]{12}$`)

// quoteLiteral safely quotes a string for use as a PostgreSQL literal.
// Uses the dollar-quoting escape style to prevent injection.
func quoteLiteral(s string) string {
	// Use E'' syntax with proper escaping for maximum safety
	escaped := strings.ReplaceAll(s, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `'`, `''`)
	return "E'" + escaped + "'"
}

type AuthService struct {
	db            *pgxpool.Pool
	jwtSecret     []byte
	jwtExpiry     time.Duration
	loginAttempts map[string]*loginAttempt
	attemptsMu    sync.Mutex
}

type loginAttempt struct {
	count    int
	lockedAt time.Time
}

func NewAuthService(db *pgxpool.Pool, jwtSecret string, jwtExpiry int) *AuthService {
	return &AuthService{
		db:            db,
		jwtSecret:     []byte(jwtSecret),
		jwtExpiry:     time.Duration(jwtExpiry) * time.Second,
		loginAttempts: make(map[string]*loginAttempt),
	}
}

type RegisterRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name,omitempty"`
	InviteCode  string `json:"invite_code,omitempty"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type AuthResponse struct {
	Token string       `json:"token"`
	User  PlatformUser `json:"user"`
}

type PlatformUser struct {
	ID          string    `json:"id"`
	Email       string    `json:"email"`
	DisplayName *string   `json:"display_name"`
	PgUsername  string    `json:"pg_username,omitempty"`
	IsAdmin     bool      `json:"is_admin"`
	CreatedAt   time.Time `json:"created_at"`
}

type PlatformClaims struct {
	Email string `json:"email"`
	Type  string `json:"type"`
	jwt.RegisteredClaims
}

// Register creates a new platform user and their PostgreSQL role.
func (s *AuthService) Register(ctx context.Context, req RegisterRequest) (*AuthResponse, int, error) {
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" || req.Password == "" {
		return nil, http.StatusBadRequest, fmt.Errorf("email and password are required")
	}
	if len(req.Password) < 8 {
		return nil, http.StatusBadRequest, fmt.Errorf("password must be at least 8 characters")
	}

	// Check registration mode
	mode := s.GetRegistrationMode(ctx)
	if mode == "disabled" {
		return nil, http.StatusForbidden, fmt.Errorf("registration is disabled")
	}

	// Validate invite code if invite-only mode
	var inviteID *string
	if mode == "invite" {
		if req.InviteCode == "" {
			return nil, http.StatusBadRequest, fmt.Errorf("invite code is required")
		}
		var id string
		var usedBy *string
		var expiresAt time.Time
		err := s.db.QueryRow(ctx, `
			SELECT id, used_by, expires_at FROM platform.invites WHERE code = $1
		`, req.InviteCode).Scan(&id, &usedBy, &expiresAt)
		if err != nil {
			return nil, http.StatusBadRequest, fmt.Errorf("invalid invite code")
		}
		if usedBy != nil {
			return nil, http.StatusBadRequest, fmt.Errorf("invite code already used")
		}
		if time.Now().After(expiresAt) {
			return nil, http.StatusBadRequest, fmt.Errorf("invite code expired")
		}
		inviteID = &id
	}

	// Check if email already exists
	var exists bool
	err := s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM platform.users WHERE email = $1)`, email).Scan(&exists)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("check email: %w", err)
	}
	if exists {
		return nil, http.StatusConflict, fmt.Errorf("email already registered")
	}

	// Hash platform password
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("hash password: %w", err)
	}

	// Generate PG username and password
	randBytes := make([]byte, 6)
	if _, err := rand.Read(randBytes); err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("generate random: %w", err)
	}
	pgUsername := "u_" + hex.EncodeToString(randBytes)

	pgPassword, err := GenerateRandomPassword(32)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("generate pg password: %w", err)
	}

	// Hash PG password for storage
	pgHash, err := bcrypt.GenerateFromPassword([]byte(pgPassword), 12)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("hash pg password: %w", err)
	}

	// Encrypt PG password with user's platform password
	pgEncrypted, err := EncryptPgPassword(pgPassword, req.Password)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("encrypt pg password: %w", err)
	}

	// Begin transaction
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	// Insert platform user
	var userID string
	var createdAt time.Time
	displayName := &req.DisplayName
	if req.DisplayName == "" {
		displayName = nil
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO platform.users (email, password_hash, display_name)
		VALUES ($1, $2, $3)
		RETURNING id, created_at
	`, email, string(hash), displayName).Scan(&userID, &createdAt)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("insert user: %w", err)
	}

	// Create PostgreSQL role with LOGIN and CONNECTION LIMIT (no CREATEDB for tenant isolation)
	// pgUsername is safe (generated as "u_" + hex, validated below)
	if !pgUsernameRegex.MatchString(pgUsername) {
		return nil, http.StatusInternalServerError, fmt.Errorf("invalid pg username format")
	}
	_, err = tx.Exec(ctx, fmt.Sprintf(`CREATE ROLE "%s" LOGIN CONNECTION LIMIT 10`, pgUsername))
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("create pg role: %w", err)
	}
	// Set password separately via ALTER ROLE using format string with escaped password
	// This is safe because pgPassword is randomly generated (alphanumeric only)
	_, err = tx.Exec(ctx, fmt.Sprintf(`ALTER ROLE "%s" PASSWORD %s`, pgUsername, quoteLiteral(pgPassword)))
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("create pg role: %w", err)
	}
	_, err = tx.Exec(ctx, fmt.Sprintf(`ALTER ROLE "%s" SET statement_timeout = '30s'`, pgUsername))
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("set statement timeout: %w", err)
	}

	// Insert pg_user mapping
	_, err = tx.Exec(ctx, `
		INSERT INTO platform.pg_users (user_id, pg_username, pg_password_hash, pg_password_encrypted)
		VALUES ($1, $2, $3, $4)
	`, userID, pgUsername, string(pgHash), pgEncrypted)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("insert pg user: %w", err)
	}

	// Mark invite as used if applicable
	if inviteID != nil {
		_, err = tx.Exec(ctx, `
			UPDATE platform.invites SET used_by = $1, used_at = NOW() WHERE id = $2
		`, userID, *inviteID)
		if err != nil {
			return nil, http.StatusInternalServerError, fmt.Errorf("mark invite used: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("commit: %w", err)
	}

	// Generate JWT
	token, err := s.generateToken(userID, email)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("generate token: %w", err)
	}

	return &AuthResponse{
		Token: token,
		User: PlatformUser{
			ID:          userID,
			Email:       email,
			DisplayName: displayName,
			PgUsername:  pgUsername,
			IsAdmin:     false,
			CreatedAt:   createdAt,
		},
	}, http.StatusCreated, nil
}

// dummyHash is a pre-computed bcrypt hash used for timing-safe login.
// When user is not found, we still run bcrypt comparison to prevent timing attacks.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("timing-safe-dummy-password-placeholder"), 12)

// Login authenticates a platform user and returns a JWT.
func (s *AuthService) Login(ctx context.Context, req LoginRequest) (*AuthResponse, int, error) {
	email := strings.ToLower(strings.TrimSpace(req.Email))

	// Check lockout
	s.attemptsMu.Lock()
	attempt := s.loginAttempts[email]
	if attempt != nil && attempt.count >= 5 {
		if time.Since(attempt.lockedAt) < 15*time.Minute {
			s.attemptsMu.Unlock()
			bcrypt.CompareHashAndPassword(dummyHash, []byte(req.Password)) // timing-safe
			return nil, http.StatusTooManyRequests, fmt.Errorf("account temporarily locked, try again later")
		}
		// Lock expired, reset
		delete(s.loginAttempts, email)
	}
	s.attemptsMu.Unlock()

	var userID, passwordHash string
	var displayName *string
	var createdAt time.Time
	var isAdmin bool

	err := s.db.QueryRow(ctx, `
		SELECT id, password_hash, display_name, created_at, is_admin
		FROM platform.users WHERE email = $1
	`, email).Scan(&userID, &passwordHash, &displayName, &createdAt, &isAdmin)
	if err != nil {
		// Timing-safe: always run bcrypt even if user doesn't exist
		bcrypt.CompareHashAndPassword(dummyHash, []byte(req.Password))
		return nil, http.StatusUnauthorized, fmt.Errorf("invalid credentials")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)); err != nil {
		s.attemptsMu.Lock()
		a := s.loginAttempts[email]
		if a == nil {
			a = &loginAttempt{}
			s.loginAttempts[email] = a
		}
		a.count++
		if a.count >= 5 {
			a.lockedAt = time.Now()
		}
		s.attemptsMu.Unlock()
		return nil, http.StatusUnauthorized, fmt.Errorf("invalid credentials")
	}

	// Clear login attempts on successful login
	s.attemptsMu.Lock()
	delete(s.loginAttempts, email)
	s.attemptsMu.Unlock()

	// Get pg_username
	var pgUsername string
	err = s.db.QueryRow(ctx, `
		SELECT pg_username FROM platform.pg_users WHERE user_id = $1
	`, userID).Scan(&pgUsername)
	if err != nil {
		pgUsername = ""
	}

	token, err := s.generateToken(userID, email)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("generate token: %w", err)
	}

	return &AuthResponse{
		Token: token,
		User: PlatformUser{
			ID:          userID,
			Email:       email,
			DisplayName: displayName,
			PgUsername:  pgUsername,
			IsAdmin:     isAdmin,
			CreatedAt:   createdAt,
		},
	}, http.StatusOK, nil
}

// GetUser returns the current platform user from a JWT.
func (s *AuthService) GetUser(ctx context.Context, userID string) (*PlatformUser, error) {
	var user PlatformUser
	err := s.db.QueryRow(ctx, `
		SELECT u.id, u.email, u.display_name, u.created_at, u.is_admin, COALESCE(p.pg_username, '')
		FROM platform.users u
		LEFT JOIN platform.pg_users p ON p.user_id = u.id
		WHERE u.id = $1
	`, userID).Scan(&user.ID, &user.Email, &user.DisplayName, &user.CreatedAt, &user.IsAdmin, &user.PgUsername)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// GetRegistrationMode returns the current platform registration mode.
func (s *AuthService) GetRegistrationMode(ctx context.Context) string {
	var mode string
	err := s.db.QueryRow(ctx, `SELECT value FROM platform.settings WHERE key = 'registration_mode'`).Scan(&mode)
	if err != nil {
		return "open"
	}
	return mode
}

// IsAdmin checks if a user is an admin.
func (s *AuthService) IsAdmin(ctx context.Context, userID string) bool {
	var isAdmin bool
	err := s.db.QueryRow(ctx, `SELECT is_admin FROM platform.users WHERE id = $1`, userID).Scan(&isAdmin)
	if err != nil {
		return false
	}
	return isAdmin
}

// EnsureAdmin creates the admin user from env vars if it doesn't exist.
func (s *AuthService) EnsureAdmin(ctx context.Context, email, password string) error {
	email = strings.ToLower(strings.TrimSpace(email))

	// Check if already exists
	var existingID string
	err := s.db.QueryRow(ctx, `SELECT id FROM platform.users WHERE email = $1`, email).Scan(&existingID)
	if err == nil {
		// User exists, ensure is_admin = true
		_, err = s.db.Exec(ctx, `UPDATE platform.users SET is_admin = TRUE WHERE id = $1`, existingID)
		return err
	}

	// Create admin user via normal Register flow
	_, _, regErr := s.registerInternal(ctx, RegisterRequest{Email: email, Password: password}, true)
	return regErr
}

// registerInternal creates a user, optionally as admin. Bypasses registration mode checks.
func (s *AuthService) registerInternal(ctx context.Context, req RegisterRequest, asAdmin bool) (*AuthResponse, int, error) {
	email := strings.ToLower(strings.TrimSpace(req.Email))

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("hash password: %w", err)
	}

	randBytes := make([]byte, 6)
	if _, err := rand.Read(randBytes); err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("generate random: %w", err)
	}
	pgUsername := "u_" + hex.EncodeToString(randBytes)

	pgPassword, err := GenerateRandomPassword(32)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("generate pg password: %w", err)
	}

	pgHash, err := bcrypt.GenerateFromPassword([]byte(pgPassword), 12)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("hash pg password: %w", err)
	}

	pgEncrypted, err := EncryptPgPassword(pgPassword, req.Password)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("encrypt pg password: %w", err)
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	var userID string
	var createdAt time.Time
	err = tx.QueryRow(ctx, `
		INSERT INTO platform.users (email, password_hash, is_admin)
		VALUES ($1, $2, $3)
		RETURNING id, created_at
	`, email, string(hash), asAdmin).Scan(&userID, &createdAt)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("insert user: %w", err)
	}

	if !pgUsernameRegex.MatchString(pgUsername) {
		return nil, http.StatusInternalServerError, fmt.Errorf("invalid pg username format")
	}
	_, err = tx.Exec(ctx, fmt.Sprintf(`CREATE ROLE "%s" LOGIN CONNECTION LIMIT 10`, pgUsername))
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("create pg role: %w", err)
	}
	_, err = tx.Exec(ctx, fmt.Sprintf(`ALTER ROLE "%s" PASSWORD %s`, pgUsername, quoteLiteral(pgPassword)))
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("set pg password: %w", err)
	}
	_, err = tx.Exec(ctx, fmt.Sprintf(`ALTER ROLE "%s" SET statement_timeout = '30s'`, pgUsername))
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("set statement timeout: %w", err)
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO platform.pg_users (user_id, pg_username, pg_password_hash, pg_password_encrypted)
		VALUES ($1, $2, $3, $4)
	`, userID, pgUsername, string(pgHash), pgEncrypted)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("insert pg user: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("commit: %w", err)
	}

	token, err := s.generateToken(userID, email)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("generate token: %w", err)
	}

	return &AuthResponse{
		Token: token,
		User: PlatformUser{
			ID:        userID,
			Email:     email,
			PgUsername: pgUsername,
			IsAdmin:   asAdmin,
			CreatedAt: createdAt,
		},
	}, http.StatusCreated, nil
}

// ValidateToken verifies a platform JWT and returns the claims.
func (s *AuthService) ValidateToken(tokenString string) (*PlatformClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &PlatformClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return s.jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*PlatformClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// ChangePassword updates the platform password and re-encrypts the PG password.
func (s *AuthService) ChangePassword(ctx context.Context, userID string, req ChangePasswordRequest) (int, error) {
	if req.CurrentPassword == "" || req.NewPassword == "" {
		return http.StatusBadRequest, fmt.Errorf("current_password and new_password are required")
	}
	if len(req.NewPassword) < 8 {
		return http.StatusBadRequest, fmt.Errorf("new password must be at least 8 characters")
	}

	// Get current password hash
	var passwordHash string
	err := s.db.QueryRow(ctx, `SELECT password_hash FROM platform.users WHERE id = $1`, userID).Scan(&passwordHash)
	if err != nil {
		return http.StatusNotFound, fmt.Errorf("user not found")
	}

	// Verify current password
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.CurrentPassword)); err != nil {
		return http.StatusUnauthorized, fmt.Errorf("current password is incorrect")
	}

	// Hash new password
	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), 12)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("hash password: %w", err)
	}

	// Decrypt PG password with current password, re-encrypt with new password
	var pgEncrypted string
	err = s.db.QueryRow(ctx, `SELECT pg_password_encrypted FROM platform.pg_users WHERE user_id = $1`, userID).Scan(&pgEncrypted)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("get pg credentials: %w", err)
	}

	pgPassword, err := DecryptPgPassword(pgEncrypted, req.CurrentPassword)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("decrypt pg password: %w", err)
	}

	newPgEncrypted, err := EncryptPgPassword(pgPassword, req.NewPassword)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("re-encrypt pg password: %w", err)
	}

	// Update both in a transaction
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `UPDATE platform.users SET password_hash = $1, updated_at = NOW() WHERE id = $2`, string(newHash), userID)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("update password: %w", err)
	}

	_, err = tx.Exec(ctx, `UPDATE platform.pg_users SET pg_password_encrypted = $1 WHERE user_id = $2`, newPgEncrypted, userID)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("update pg encryption: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return http.StatusInternalServerError, fmt.Errorf("commit: %w", err)
	}

	return http.StatusOK, nil
}

func (s *AuthService) generateToken(userID, email string) (string, error) {
	now := time.Now()
	claims := PlatformClaims{
		Email: email,
		Type:  "platform",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.jwtExpiry)),
			Issuer:    "dupabase",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtSecret)
}
