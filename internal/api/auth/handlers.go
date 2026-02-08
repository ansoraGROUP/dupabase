package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ansoraGROUP/dupabase/internal/database"
	"github.com/ansoraGROUP/dupabase/internal/middleware"
	"golang.org/x/crypto/bcrypt"
)

// dummyProjectHash is used for timing-safe login — prevents user enumeration via timing.
var dummyProjectHash, _ = bcrypt.GenerateFromPassword([]byte("timing-safe-dummy-placeholder"), 12)

// Handler implements GoTrue-compatible auth endpoints.
type Handler struct{}

func NewHandler() *Handler {
	return &Handler{}
}

// ---------- Request/Response types ----------

type signupRequest struct {
	Email    string                 `json:"email"`
	Password string                 `json:"password"`
	Data     map[string]interface{} `json:"data,omitempty"`
	Phone    string                 `json:"phone,omitempty"`
}

type tokenRequest struct {
	Email        string `json:"email"`
	Password     string `json:"password"`
	RefreshToken string `json:"refresh_token"`
	Phone        string `json:"phone,omitempty"`
}

type updateUserRequest struct {
	Email    string                 `json:"email,omitempty"`
	Password string                 `json:"password,omitempty"`
	Data     map[string]interface{} `json:"data,omitempty"`
}

type logoutRequest struct {
	Scope string `json:"scope,omitempty"` // "global" or "local" (default)
}

type userResponse struct {
	ID               string                 `json:"id"`
	Aud              string                 `json:"aud"`
	Role             string                 `json:"role"`
	Email            string                 `json:"email"`
	EmailConfirmedAt *string                `json:"email_confirmed_at"`
	Phone            string                 `json:"phone"`
	PhoneConfirmedAt *string                `json:"phone_confirmed_at,omitempty"`
	ConfirmedAt      *string                `json:"confirmed_at"`
	LastSignInAt     *string                `json:"last_sign_in_at"`
	AppMetadata      map[string]interface{} `json:"app_metadata"`
	UserMetadata     map[string]interface{} `json:"user_metadata"`
	Identities       []identityResponse     `json:"identities"`
	CreatedAt        string                 `json:"created_at"`
	UpdatedAt        string                 `json:"updated_at"`
}

type identityResponse struct {
	IdentityID   string                 `json:"identity_id"`
	ID           string                 `json:"id"`
	UserID       string                 `json:"user_id"`
	IdentityData map[string]interface{} `json:"identity_data"`
	Provider     string                 `json:"provider"`
	LastSignInAt *string                `json:"last_sign_in_at"`
	CreatedAt    string                 `json:"created_at"`
	UpdatedAt    string                 `json:"updated_at"`
}

type sessionResponse struct {
	AccessToken  string       `json:"access_token"`
	TokenType    string       `json:"token_type"`
	ExpiresIn    int          `json:"expires_in"`
	ExpiresAt    int64        `json:"expires_at"`
	RefreshToken string       `json:"refresh_token"`
	User         userResponse `json:"user"`
}

// ---------- Handlers ----------

// Signup handles POST /auth/v1/signup
func (h *Handler) Signup(w http.ResponseWriter, r *http.Request) {
	project := middleware.GetProject(r)
	pool := middleware.GetProjectSQL(r)
	if project == nil || pool == nil {
		writeError(w, http.StatusInternalServerError, "missing project context")
		return
	}

	if !project.EnableSignup {
		writeError(w, http.StatusForbidden, "signups are disabled for this project")
		return
	}

	var req signupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password are required")
		return
	}
	if len(req.Password) < project.PasswordMinLen {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("password must be at least %d characters", project.PasswordMinLen))
		return
	}

	// Hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	userMetadata := req.Data
	if userMetadata == nil {
		userMetadata = map[string]interface{}{}
	}
	appMetadata := map[string]interface{}{"provider": "email", "providers": []string{"email"}}
	userMetaJSON, _ := json.Marshal(userMetadata)
	appMetaJSON, _ := json.Marshal(appMetadata)

	now := time.Now()
	var emailConfirmedAt *time.Time
	if project.Autoconfirm {
		emailConfirmedAt = &now
	}

	ctx := r.Context()

	// Insert user
	var userID string
	var createdAt, updatedAt time.Time
	err = pool.QueryRow(ctx, `
		INSERT INTO auth.users (email, encrypted_password, email_confirmed_at,
			raw_app_meta_data, raw_user_meta_data, aud, role, last_sign_in_at)
		VALUES ($1, $2, $3, $4, $5, 'authenticated', 'authenticated', $6)
		RETURNING id, created_at, updated_at
	`, email, string(hash), emailConfirmedAt, string(appMetaJSON), string(userMetaJSON), now,
	).Scan(&userID, &createdAt, &updatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			writeError(w, http.StatusBadRequest, "User already registered")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to create user")
		return
	}

	// Create identity
	identityData := map[string]interface{}{
		"sub":              userID,
		"email":            email,
		"email_verified":   project.Autoconfirm,
		"phone_verified":   false,
	}
	identityJSON, _ := json.Marshal(identityData)
	var identityID string
	err = pool.QueryRow(ctx, `
		INSERT INTO auth.identities (user_id, provider_id, identity_data, provider, last_sign_in_at)
		VALUES ($1, $2, $3, 'email', $4)
		RETURNING id
	`, userID, userID, string(identityJSON), now).Scan(&identityID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create identity")
		return
	}

	// Create session and return tokens
	session, err := createSession(ctx, pool, project, userID, email, userMetadata, appMetadata, r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create session")
		return
	}

	var emailConfStr *string
	if emailConfirmedAt != nil {
		s := emailConfirmedAt.Format(time.RFC3339)
		emailConfStr = &s
	}
	lastSignIn := now.Format(time.RFC3339)

	resp := sessionResponse{
		AccessToken:  session.accessToken,
		TokenType:    "bearer",
		ExpiresIn:    3600,
		ExpiresAt:    session.expiresAt,
		RefreshToken: session.refreshToken,
		User: userResponse{
			ID:               userID,
			Aud:              "authenticated",
			Role:             "authenticated",
			Email:            email,
			EmailConfirmedAt: emailConfStr,
			Phone:            "",
			ConfirmedAt:      emailConfStr,
			LastSignInAt:     &lastSignIn,
			AppMetadata:      appMetadata,
			UserMetadata:     userMetadata,
			Identities: []identityResponse{{
				IdentityID:   identityID,
				ID:           userID,
				UserID:       userID,
				IdentityData: identityData,
				Provider:     "email",
				LastSignInAt: &lastSignIn,
				CreatedAt:    createdAt.Format(time.RFC3339),
				UpdatedAt:    updatedAt.Format(time.RFC3339),
			}},
			CreatedAt: createdAt.Format(time.RFC3339),
			UpdatedAt: updatedAt.Format(time.RFC3339),
		},
	}

	writeJSON(w, http.StatusOK, resp)
}

// Token handles POST /auth/v1/token?grant_type=...
func (h *Handler) Token(w http.ResponseWriter, r *http.Request) {
	project := middleware.GetProject(r)
	pool := middleware.GetProjectSQL(r)
	if project == nil || pool == nil {
		writeError(w, http.StatusInternalServerError, "missing project context")
		return
	}

	grantType := r.URL.Query().Get("grant_type")
	ctx := r.Context()

	switch grantType {
	case "password":
		h.tokenPassword(ctx, w, r, project, pool)
	case "refresh_token":
		h.tokenRefresh(ctx, w, r, project, pool)
	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported grant_type: %s", grantType))
	}
}

func (h *Handler) tokenPassword(ctx contextType, w http.ResponseWriter, r *http.Request, project *database.ProjectRecord, pool *pgxpool.Pool) {
	var req tokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))

	var userID, passwordHash string
	var emailConfirmedAt *time.Time
	var rawAppMeta, rawUserMeta []byte
	var createdAt, updatedAt time.Time

	err := pool.QueryRow(ctx, `
		SELECT id, encrypted_password, email_confirmed_at,
			raw_app_meta_data, raw_user_meta_data, created_at, updated_at
		FROM auth.users WHERE email = $1 AND deleted_at IS NULL
	`, email).Scan(&userID, &passwordHash, &emailConfirmedAt, &rawAppMeta, &rawUserMeta, &createdAt, &updatedAt)
	if err != nil {
		// Perform dummy bcrypt comparison to prevent user enumeration via timing
		bcrypt.CompareHashAndPassword(dummyProjectHash, []byte(req.Password))
		writeError(w, http.StatusBadRequest, "Invalid login credentials")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid login credentials")
		return
	}

	var appMetadata, userMetadata map[string]interface{}
	json.Unmarshal(rawAppMeta, &appMetadata)
	json.Unmarshal(rawUserMeta, &userMetadata)

	// Update last_sign_in_at
	now := time.Now()
	pool.Exec(ctx, `UPDATE auth.users SET last_sign_in_at = $1, updated_at = $1 WHERE id = $2`, now, userID)

	session, err := createSession(ctx, pool, project, userID, email, userMetadata, appMetadata, r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create session")
		return
	}

	var emailConfStr *string
	if emailConfirmedAt != nil {
		s := emailConfirmedAt.Format(time.RFC3339)
		emailConfStr = &s
	}
	lastSignIn := now.Format(time.RFC3339)

	// Get identities
	identities := fetchIdentities(ctx, pool, userID)

	resp := sessionResponse{
		AccessToken:  session.accessToken,
		TokenType:    "bearer",
		ExpiresIn:    3600,
		ExpiresAt:    session.expiresAt,
		RefreshToken: session.refreshToken,
		User: userResponse{
			ID:               userID,
			Aud:              "authenticated",
			Role:             "authenticated",
			Email:            email,
			EmailConfirmedAt: emailConfStr,
			Phone:            "",
			ConfirmedAt:      emailConfStr,
			LastSignInAt:     &lastSignIn,
			AppMetadata:      appMetadata,
			UserMetadata:     userMetadata,
			Identities:       identities,
			CreatedAt:        createdAt.Format(time.RFC3339),
			UpdatedAt:        updatedAt.Format(time.RFC3339),
		},
	}

	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) tokenRefresh(ctx contextType, w http.ResponseWriter, r *http.Request, project *database.ProjectRecord, pool *pgxpool.Pool) {
	var req tokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "refresh_token is required")
		return
	}

	// Look up the refresh token (enforce expiration)
	var tokenID int64
	var userID, sessionID string
	var revoked bool
	err := pool.QueryRow(ctx, `
		SELECT id, user_id, session_id, revoked
		FROM auth.refresh_tokens
		WHERE token = $1 AND (expires_at IS NULL OR expires_at > NOW())
	`, req.RefreshToken).Scan(&tokenID, &userID, &sessionID, &revoked)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid refresh token")
		return
	}
	if revoked {
		// Revoke all tokens in this family (rotation attack detection)
		if _, err := pool.Exec(ctx, `UPDATE auth.refresh_tokens SET revoked = true WHERE session_id = $1`, sessionID); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to revoke compromised tokens")
			return
		}
		writeError(w, http.StatusBadRequest, "Token has been revoked")
		return
	}

	// Revoke old token
	if _, err := pool.Exec(ctx, `UPDATE auth.refresh_tokens SET revoked = true, updated_at = NOW() WHERE id = $1`, tokenID); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to revoke old token")
		return
	}

	// Get user data
	var email string
	var emailConfirmedAt *time.Time
	var rawAppMeta, rawUserMeta []byte
	var createdAt, updatedAt time.Time
	err = pool.QueryRow(ctx, `
		SELECT email, email_confirmed_at, raw_app_meta_data, raw_user_meta_data, created_at, updated_at
		FROM auth.users WHERE id = $1 AND deleted_at IS NULL
	`, userID).Scan(&email, &emailConfirmedAt, &rawAppMeta, &rawUserMeta, &createdAt, &updatedAt)
	if err != nil {
		writeError(w, http.StatusBadRequest, "User not found")
		return
	}

	var appMetadata, userMetadata map[string]interface{}
	json.Unmarshal(rawAppMeta, &appMetadata)
	json.Unmarshal(rawUserMeta, &userMetadata)

	// Generate new tokens
	now := time.Now()
	accessToken, expiresAt, err := generateUserJWT(project.JWTSecret, project.SiteURL, userID, email, userMetadata, appMetadata, sessionID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	newRefreshToken, err := generateRefreshToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate refresh token")
		return
	}

	// Store new refresh token
	_, err = pool.Exec(ctx, `
		INSERT INTO auth.refresh_tokens (token, user_id, session_id, parent)
		VALUES ($1, $2, $3, $4)
	`, newRefreshToken, userID, sessionID, req.RefreshToken)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to store refresh token")
		return
	}

	// Update session
	if _, err := pool.Exec(ctx, `UPDATE auth.sessions SET refreshed_at = $1, updated_at = $1 WHERE id = $2`, now, sessionID); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update session")
		return
	}

	var emailConfStr *string
	if emailConfirmedAt != nil {
		s := emailConfirmedAt.Format(time.RFC3339)
		emailConfStr = &s
	}

	identities := fetchIdentities(ctx, pool, userID)

	resp := sessionResponse{
		AccessToken:  accessToken,
		TokenType:    "bearer",
		ExpiresIn:    3600,
		ExpiresAt:    expiresAt,
		RefreshToken: newRefreshToken,
		User: userResponse{
			ID:               userID,
			Aud:              "authenticated",
			Role:             "authenticated",
			Email:            email,
			EmailConfirmedAt: emailConfStr,
			Phone:            "",
			ConfirmedAt:      emailConfStr,
			AppMetadata:      appMetadata,
			UserMetadata:     userMetadata,
			Identities:       identities,
			CreatedAt:        createdAt.Format(time.RFC3339),
			UpdatedAt:        updatedAt.Format(time.RFC3339),
		},
	}

	writeJSON(w, http.StatusOK, resp)
}

// GetUser handles GET /auth/v1/user
func (h *Handler) GetUser(w http.ResponseWriter, r *http.Request) {
	project := middleware.GetProject(r)
	pool := middleware.GetProjectSQL(r)
	if project == nil || pool == nil {
		writeError(w, http.StatusInternalServerError, "missing project context")
		return
	}

	// Get user from Authorization header (user JWT, not apikey)
	userID, err := extractUserFromAuth(r, project.JWTSecret)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	ctx := r.Context()
	user, err := fetchUser(ctx, pool, userID)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	writeJSON(w, http.StatusOK, user)
}

// UpdateUser handles PUT /auth/v1/user
func (h *Handler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	project := middleware.GetProject(r)
	pool := middleware.GetProjectSQL(r)
	if project == nil || pool == nil {
		writeError(w, http.StatusInternalServerError, "missing project context")
		return
	}

	userID, err := extractUserFromAuth(r, project.JWTSecret)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	var req updateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	ctx := r.Context()

	if req.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to hash password")
			return
		}
		pool.Exec(ctx, `UPDATE auth.users SET encrypted_password = $1, updated_at = NOW() WHERE id = $2`, string(hash), userID)
	}

	if req.Data != nil {
		metaJSON, _ := json.Marshal(req.Data)
		pool.Exec(ctx, `UPDATE auth.users SET raw_user_meta_data = $1, updated_at = NOW() WHERE id = $2`, string(metaJSON), userID)
	}

	if req.Email != "" {
		newEmail := strings.ToLower(strings.TrimSpace(req.Email))
		// Verify no other user has this email
		var exists bool
		pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.users WHERE email = $1 AND id != $2)`, newEmail, userID).Scan(&exists)
		if exists {
			writeError(w, http.StatusBadRequest, "email already in use")
			return
		}
		pool.Exec(ctx, `UPDATE auth.users SET email = $1, updated_at = NOW() WHERE id = $2`, newEmail, userID)
	}

	user, err := fetchUser(ctx, pool, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to fetch updated user")
		return
	}

	writeJSON(w, http.StatusOK, user)
}

// Logout handles POST /auth/v1/logout
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	project := middleware.GetProject(r)
	pool := middleware.GetProjectSQL(r)
	if project == nil || pool == nil {
		writeError(w, http.StatusInternalServerError, "missing project context")
		return
	}

	userID, err := extractUserFromAuth(r, project.JWTSecret)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	var req logoutRequest
	json.NewDecoder(r.Body).Decode(&req)

	ctx := r.Context()

	if req.Scope == "global" {
		// Revoke all sessions
		pool.Exec(ctx, `DELETE FROM auth.sessions WHERE user_id = $1`, userID)
		pool.Exec(ctx, `UPDATE auth.refresh_tokens SET revoked = true WHERE user_id = $1`, userID)
	} else {
		// Revoke current session only
		sessionID, _ := extractSessionFromAuth(r, project.JWTSecret)
		if sessionID != "" {
			pool.Exec(ctx, `DELETE FROM auth.sessions WHERE id = $1`, sessionID)
			pool.Exec(ctx, `UPDATE auth.refresh_tokens SET revoked = true WHERE session_id = $1`, sessionID)
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

// ---------- Internal helpers ----------

type contextType = context.Context

type sessionData struct {
	accessToken  string
	refreshToken string
	expiresAt    int64
}

func createSession(ctx contextType, pool *pgxpool.Pool, project *database.ProjectRecord, userID, email string, userMeta, appMeta map[string]interface{}, r *http.Request) (*sessionData, error) {
	// Create session record
	var sessionID string
	userAgent := r.Header.Get("User-Agent")
	ip := r.RemoteAddr
	err := pool.QueryRow(ctx, `
		INSERT INTO auth.sessions (user_id, user_agent, ip, aal)
		VALUES ($1, $2, $3, 'aal1')
		RETURNING id
	`, userID, userAgent, ip).Scan(&sessionID)
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	// Generate access token
	accessToken, expiresAt, err := generateUserJWT(project.JWTSecret, project.SiteURL, userID, email, userMeta, appMeta, sessionID)
	if err != nil {
		return nil, fmt.Errorf("generate jwt: %w", err)
	}

	// Generate refresh token
	refreshToken, err := generateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}

	// Store refresh token
	_, err = pool.Exec(ctx, `
		INSERT INTO auth.refresh_tokens (token, user_id, session_id)
		VALUES ($1, $2, $3)
	`, refreshToken, userID, sessionID)
	if err != nil {
		return nil, fmt.Errorf("store refresh token: %w", err)
	}

	return &sessionData{
		accessToken:  accessToken,
		refreshToken: refreshToken,
		expiresAt:    expiresAt,
	}, nil
}

func generateUserJWT(jwtSecret, siteURL, userID, email string, userMeta, appMeta map[string]interface{}, sessionID string) (string, int64, error) {
	now := time.Now()
	expiresAt := now.Add(1 * time.Hour).Unix()

	claims := jwt.MapClaims{
		"aud":           "authenticated",
		"exp":           expiresAt,
		"iat":           now.Unix(),
		"iss":           siteURL + "/auth/v1",
		"sub":           userID,
		"email":         email,
		"phone":         "",
		"app_metadata":  appMeta,
		"user_metadata": userMeta,
		"role":          "authenticated",
		"aal":           "aal1",
		"amr":           []map[string]interface{}{{"method": "password", "timestamp": now.Unix()}},
		"session_id":    sessionID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(jwtSecret))
	return signed, expiresAt, err
}

func generateRefreshToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func extractUserFromAuth(r *http.Request, jwtSecret string) (string, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", fmt.Errorf("missing authorization")
	}
	tokenStr := strings.TrimPrefix(auth, "Bearer ")

	// Check if the token is same as apikey (unauthenticated)
	apikey := r.Header.Get("apikey")
	if tokenStr == apikey {
		return "", fmt.Errorf("not a user token")
	}

	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(jwtSecret), nil
	})
	if err != nil || !token.Valid {
		return "", fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("invalid claims")
	}

	sub, _ := claims["sub"].(string)
	if sub == "" {
		return "", fmt.Errorf("missing sub claim")
	}

	return sub, nil
}

func extractSessionFromAuth(r *http.Request, jwtSecret string) (string, error) {
	auth := r.Header.Get("Authorization")
	tokenStr := strings.TrimPrefix(auth, "Bearer ")

	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(jwtSecret), nil
	})
	if err != nil || !token.Valid {
		return "", err
	}

	claims, _ := token.Claims.(jwt.MapClaims)
	sid, _ := claims["session_id"].(string)
	return sid, nil
}

func fetchUser(ctx contextType, pool *pgxpool.Pool, userID string) (*userResponse, error) {
	var email string
	var emailConfirmedAt *time.Time
	var lastSignInAt *time.Time
	var rawAppMeta, rawUserMeta []byte
	var createdAt, updatedAt time.Time
	var phone *string

	err := pool.QueryRow(ctx, `
		SELECT email, email_confirmed_at, last_sign_in_at,
			raw_app_meta_data, raw_user_meta_data, created_at, updated_at, phone
		FROM auth.users WHERE id = $1 AND deleted_at IS NULL
	`, userID).Scan(&email, &emailConfirmedAt, &lastSignInAt, &rawAppMeta, &rawUserMeta, &createdAt, &updatedAt, &phone)
	if err != nil {
		return nil, err
	}

	var appMeta, userMeta map[string]interface{}
	json.Unmarshal(rawAppMeta, &appMeta)
	json.Unmarshal(rawUserMeta, &userMeta)

	var emailConfStr, lastSignStr, confirmedStr *string
	if emailConfirmedAt != nil {
		s := emailConfirmedAt.Format(time.RFC3339)
		emailConfStr = &s
		confirmedStr = &s
	}
	if lastSignInAt != nil {
		s := lastSignInAt.Format(time.RFC3339)
		lastSignStr = &s
	}

	identities := fetchIdentities(ctx, pool, userID)

	phoneStr := ""
	if phone != nil {
		phoneStr = *phone
	}

	return &userResponse{
		ID:               userID,
		Aud:              "authenticated",
		Role:             "authenticated",
		Email:            email,
		EmailConfirmedAt: emailConfStr,
		Phone:            phoneStr,
		ConfirmedAt:      confirmedStr,
		LastSignInAt:     lastSignStr,
		AppMetadata:      appMeta,
		UserMetadata:     userMeta,
		Identities:       identities,
		CreatedAt:        createdAt.Format(time.RFC3339),
		UpdatedAt:        updatedAt.Format(time.RFC3339),
	}, nil
}

func fetchIdentities(ctx contextType, pool *pgxpool.Pool, userID string) []identityResponse {
	rows, err := pool.Query(ctx, `
		SELECT id, provider_id, identity_data, provider, last_sign_in_at, created_at, updated_at
		FROM auth.identities WHERE user_id = $1
	`, userID)
	if err != nil {
		return []identityResponse{}
	}
	defer rows.Close()

	var identities []identityResponse
	for rows.Next() {
		var id, providerID, provider string
		var identityData []byte
		var lastSignIn *time.Time
		var createdAt, updatedAt time.Time

		if err := rows.Scan(&id, &providerID, &identityData, &provider, &lastSignIn, &createdAt, &updatedAt); err != nil {
			continue
		}

		var data map[string]interface{}
		json.Unmarshal(identityData, &data)

		var lastSignStr *string
		if lastSignIn != nil {
			s := lastSignIn.Format(time.RFC3339)
			lastSignStr = &s
		}

		identities = append(identities, identityResponse{
			IdentityID:   id,
			ID:           providerID,
			UserID:       userID,
			IdentityData: data,
			Provider:     provider,
			LastSignInAt: lastSignStr,
			CreatedAt:    createdAt.Format(time.RFC3339),
			UpdatedAt:    updatedAt.Format(time.RFC3339),
		})
	}

	if identities == nil {
		identities = []identityResponse{}
	}
	return identities
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]interface{}{
		"error":             message,
		"error_description": message,
	})
}
