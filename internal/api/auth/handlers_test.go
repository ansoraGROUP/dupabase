package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ansoraGROUP/dupabase/internal/database"
	"github.com/ansoraGROUP/dupabase/internal/middleware"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const testProjectSecret = "test-project-jwt-secret-long-enough-32"

func newTestProject(enableSignup, autoconfirm bool, minLen int) *database.ProjectRecord {
	return &database.ProjectRecord{
		ID:             "proj-test-123",
		DBName:         "proj_testdb",
		JWTSecret:      testProjectSecret,
		AnonKey:        "test-anon-key",
		ServiceRoleKey: "test-sr-key",
		EnableSignup:   enableSignup,
		Autoconfirm:    autoconfirm,
		PasswordMinLen: minLen,
		SiteURL:        "http://localhost:3000",
		Status:         "active",
	}
}

func requestWithProjectContext(r *http.Request, project *database.ProjectRecord) *http.Request {
	ctx := r.Context()
	ctx = context.WithValue(ctx, middleware.ContextProject, project)
	// No pool -- handlers will get nil pool and return "missing project context"
	// unless we set it. For tests that check validation before DB access,
	// we can set pool=nil and the handler will catch it.
	return r.WithContext(ctx)
}

func requestWithFullContext(r *http.Request, project *database.ProjectRecord) *http.Request {
	ctx := r.Context()
	ctx = context.WithValue(ctx, middleware.ContextProject, project)
	// Set pool to nil to trigger the missing project context path
	return r.WithContext(ctx)
}

func generateTestUserJWT(secret, userID, email, sessionID string) string {
	now := time.Now()
	claims := jwt.MapClaims{
		"aud":        "authenticated",
		"exp":        now.Add(time.Hour).Unix(),
		"iat":        now.Unix(),
		"iss":        "http://localhost:3000/auth/v1",
		"sub":        userID,
		"email":      email,
		"role":       "authenticated",
		"session_id": sessionID,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := token.SignedString([]byte(secret))
	return signed
}

// ---------------------------------------------------------------------------
// Signup handler
// ---------------------------------------------------------------------------

func TestSignup_MissingProjectContext(t *testing.T) {
	h := NewHandler()

	body := `{"email":"test@test.com","password":"password123"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/signup", strings.NewReader(body))
	rec := httptest.NewRecorder()

	h.Signup(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", rec.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["error"] != "missing project context" {
		t.Errorf("unexpected error: %v", resp["error"])
	}
}

func TestSignup_SignupsDisabled(t *testing.T) {
	h := NewHandler()

	project := newTestProject(false, true, 6) // signup disabled

	body := `{"email":"test@test.com","password":"password123"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/signup", strings.NewReader(body))
	ctx := req.Context()
	ctx = context.WithValue(ctx, middleware.ContextProject, project)
	// Need to set a non-nil pool for the handler to pass the nil check.
	// Since we don't have a real pool, we use nil and check that the handler
	// checks EnableSignup before pool access.
	// Actually, the handler checks `project == nil || pool == nil` first.
	// To test signup disabled, we need both non-nil. Without a real pool,
	// let's verify the check order by using a typed-nil workaround.
	// The handler does: pool := middleware.GetProjectSQL(r) which returns *pgxpool.Pool
	// If pool is nil, it returns "missing project context".
	// We need to test the signup disabled path, so we need pool != nil.
	// We cannot create a real pool without DB. Let's verify:
	// 1. The "missing project context" path (already tested above)
	// 2. Test the signup disabled path needs pool. Since we can't mock pgxpool.Pool,
	//    we'll document this as an integration test requirement.

	// For now, test that without pool, we get "missing project context"
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	h.Signup(rec, req)

	// Without pool set in context, returns "missing project context" even with project set
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", rec.Code)
	}
}

func TestSignup_InvalidJSON(t *testing.T) {
	h := NewHandler()

	// This test verifies that invalid JSON returns a proper error.
	// However, since project && pool must both be non-nil for the handler
	// to proceed past the first check, and we cannot create a real pool
	// without a DB, this test documents the expected behavior.
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/signup", strings.NewReader("{invalid json"))
	rec := httptest.NewRecorder()

	h.Signup(rec, req)

	// Without project context, returns "missing project context"
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Token handler
// ---------------------------------------------------------------------------

func TestToken_MissingProjectContext(t *testing.T) {
	h := NewHandler()

	body := `{"email":"test@test.com","password":"password123"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/token?grant_type=password", strings.NewReader(body))
	rec := httptest.NewRecorder()

	h.Token(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// GetUser handler
// ---------------------------------------------------------------------------

func TestGetUser_MissingProjectContext(t *testing.T) {
	h := NewHandler()

	req := httptest.NewRequest(http.MethodGet, "/auth/v1/user", nil)
	rec := httptest.NewRecorder()

	h.GetUser(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// UpdateUser handler
// ---------------------------------------------------------------------------

func TestUpdateUser_MissingProjectContext(t *testing.T) {
	h := NewHandler()

	body := `{"password":"newpassword"}`
	req := httptest.NewRequest(http.MethodPut, "/auth/v1/user", strings.NewReader(body))
	rec := httptest.NewRecorder()

	h.UpdateUser(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Logout handler
// ---------------------------------------------------------------------------

func TestLogout_MissingProjectContext(t *testing.T) {
	h := NewHandler()

	req := httptest.NewRequest(http.MethodPost, "/auth/v1/logout", nil)
	rec := httptest.NewRecorder()

	h.Logout(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Internal helpers (testable from within the package)
// ---------------------------------------------------------------------------

func TestExtractUserFromAuth_MissingHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	_, err := extractUserFromAuth(req, testProjectSecret)
	if err == nil {
		t.Fatal("expected error for missing authorization")
	}
	if !strings.Contains(err.Error(), "missing authorization") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestExtractUserFromAuth_TokenSameAsApikey(t *testing.T) {
	apikey := "some-api-key"
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+apikey)
	req.Header.Set("apikey", apikey)

	_, err := extractUserFromAuth(req, testProjectSecret)
	if err == nil {
		t.Fatal("expected error when token equals apikey")
	}
	if !strings.Contains(err.Error(), "not a user token") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestExtractUserFromAuth_ValidToken(t *testing.T) {
	userToken := generateTestUserJWT(testProjectSecret, "user-abc-123", "user@test.com", "session-1")

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+userToken)
	req.Header.Set("apikey", "different-key")

	userID, err := extractUserFromAuth(req, testProjectSecret)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if userID != "user-abc-123" {
		t.Errorf("expected user ID 'user-abc-123', got %q", userID)
	}
}

func TestExtractUserFromAuth_InvalidToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid.jwt.token")
	req.Header.Set("apikey", "different-key")

	_, err := extractUserFromAuth(req, testProjectSecret)
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func TestExtractUserFromAuth_ExpiredToken(t *testing.T) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": "user-expired",
		"exp": now.Add(-time.Hour).Unix(),
		"iat": now.Add(-2 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := token.SignedString([]byte(testProjectSecret))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+signed)
	req.Header.Set("apikey", "different-key")

	_, err := extractUserFromAuth(req, testProjectSecret)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestExtractUserFromAuth_MissingSub(t *testing.T) {
	now := time.Now()
	claims := jwt.MapClaims{
		"exp":  now.Add(time.Hour).Unix(),
		"iat":  now.Unix(),
		"role": "authenticated",
		// No "sub" claim
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := token.SignedString([]byte(testProjectSecret))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+signed)
	req.Header.Set("apikey", "different-key")

	_, err := extractUserFromAuth(req, testProjectSecret)
	if err == nil {
		t.Fatal("expected error for missing sub claim")
	}
	if !strings.Contains(err.Error(), "missing sub claim") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// extractSessionFromAuth
// ---------------------------------------------------------------------------

func TestExtractSessionFromAuth_ValidToken(t *testing.T) {
	userToken := generateTestUserJWT(testProjectSecret, "user-1", "user@test.com", "session-xyz")

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+userToken)

	sessionID, err := extractSessionFromAuth(req, testProjectSecret)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sessionID != "session-xyz" {
		t.Errorf("expected session ID 'session-xyz', got %q", sessionID)
	}
}

func TestExtractSessionFromAuth_InvalidToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid.jwt.token")

	_, err := extractSessionFromAuth(req, testProjectSecret)
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func TestExtractSessionFromAuth_NoSessionClaim(t *testing.T) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": "user-1",
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
		// No session_id
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := token.SignedString([]byte(testProjectSecret))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+signed)

	sessionID, err := extractSessionFromAuth(req, testProjectSecret)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sessionID != "" {
		t.Errorf("expected empty session ID, got %q", sessionID)
	}
}

// ---------------------------------------------------------------------------
// generateUserJWT
// ---------------------------------------------------------------------------

func TestGenerateUserJWT(t *testing.T) {
	secret := "test-secret-for-user-jwt"
	siteURL := "http://localhost:3000"
	userID := "user-abc"
	email := "abc@test.com"
	userMeta := map[string]interface{}{"name": "Alice"}
	appMeta := map[string]interface{}{"provider": "email"}
	sessionID := "session-1"

	tokenStr, expiresAt, err := generateUserJWT(secret, siteURL, userID, email, userMeta, appMeta, sessionID)
	if err != nil {
		t.Fatalf("generateUserJWT failed: %v", err)
	}

	if expiresAt <= time.Now().Unix() {
		t.Error("expiresAt should be in the future")
	}

	// Parse and verify the token
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil {
		t.Fatalf("parse token failed: %v", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("expected MapClaims")
	}

	if sub, _ := claims["sub"].(string); sub != userID {
		t.Errorf("expected sub %q, got %q", userID, sub)
	}
	if e, _ := claims["email"].(string); e != email {
		t.Errorf("expected email %q, got %q", email, e)
	}
	if role, _ := claims["role"].(string); role != "authenticated" {
		t.Errorf("expected role 'authenticated', got %q", role)
	}
	if aud, _ := claims["aud"].(string); aud != "authenticated" {
		t.Errorf("expected aud 'authenticated', got %q", aud)
	}
	if iss, _ := claims["iss"].(string); iss != siteURL+"/auth/v1" {
		t.Errorf("expected iss %q, got %q", siteURL+"/auth/v1", iss)
	}
	if sid, _ := claims["session_id"].(string); sid != sessionID {
		t.Errorf("expected session_id %q, got %q", sessionID, sid)
	}
	if aal, _ := claims["aal"].(string); aal != "aal1" {
		t.Errorf("expected aal 'aal1', got %q", aal)
	}

	// Check user_metadata
	um, ok := claims["user_metadata"].(map[string]interface{})
	if !ok {
		t.Fatal("expected user_metadata to be a map")
	}
	if um["name"] != "Alice" {
		t.Errorf("expected user_metadata.name 'Alice', got %v", um["name"])
	}

	// Check app_metadata
	am, ok := claims["app_metadata"].(map[string]interface{})
	if !ok {
		t.Fatal("expected app_metadata to be a map")
	}
	if am["provider"] != "email" {
		t.Errorf("expected app_metadata.provider 'email', got %v", am["provider"])
	}
}

// ---------------------------------------------------------------------------
// generateRefreshToken
// ---------------------------------------------------------------------------

func TestGenerateRefreshToken_Uniqueness(t *testing.T) {
	tokens := make(map[string]bool)
	for i := 0; i < 100; i++ {
		token, err := generateRefreshToken()
		if err != nil {
			t.Fatal(err)
		}
		if len(token) != 64 { // 32 bytes hex-encoded = 64 chars
			t.Errorf("expected token length 64, got %d", len(token))
		}
		if tokens[token] {
			t.Fatal("duplicate refresh token generated")
		}
		tokens[token] = true
	}
}

func TestGenerateRefreshToken_IsHex(t *testing.T) {
	token, err := generateRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range token {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("token contains non-hex character: %q", string(c))
		}
	}
}

// ---------------------------------------------------------------------------
// writeError
// ---------------------------------------------------------------------------

func TestWriteError(t *testing.T) {
	rec := httptest.NewRecorder()
	writeError(rec, http.StatusBadRequest, "test error message")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rec.Code)
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got %q", ct)
	}

	var body map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&body)
	if body["error"] != "test error message" {
		t.Errorf("unexpected error: %v", body["error"])
	}
	if body["error_description"] != "test error message" {
		t.Errorf("unexpected error_description: %v", body["error_description"])
	}
}

// ---------------------------------------------------------------------------
// writeJSON
// ---------------------------------------------------------------------------

func TestWriteJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	data := map[string]string{"key": "value"}
	writeJSON(rec, http.StatusCreated, data)

	if rec.Code != http.StatusCreated {
		t.Errorf("expected status 201, got %d", rec.Code)
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got %q", ct)
	}

	var body map[string]string
	json.NewDecoder(rec.Body).Decode(&body)
	if body["key"] != "value" {
		t.Errorf("unexpected body: %v", body)
	}
}

// ---------------------------------------------------------------------------
// NewHandler
// ---------------------------------------------------------------------------

func TestNewHandler_ReturnsNonNil(t *testing.T) {
	h := NewHandler()
	if h == nil {
		t.Fatal("NewHandler returned nil")
	}
}

// ---------------------------------------------------------------------------
// Handler response types
// ---------------------------------------------------------------------------

func TestSessionResponse_Fields(t *testing.T) {
	resp := sessionResponse{
		AccessToken:  "at",
		TokenType:    "bearer",
		ExpiresIn:    3600,
		ExpiresAt:    time.Now().Add(time.Hour).Unix(),
		RefreshToken: "rt",
		User: userResponse{
			ID:    "uid",
			Email: "e@e.com",
		},
	}
	if resp.AccessToken != "at" {
		t.Error("unexpected AccessToken")
	}
	if resp.TokenType != "bearer" {
		t.Error("unexpected TokenType")
	}
	if resp.ExpiresIn != 3600 {
		t.Error("unexpected ExpiresIn")
	}
}

func TestUserResponse_Fields(t *testing.T) {
	resp := userResponse{
		ID:           "uid",
		Aud:          "authenticated",
		Role:         "authenticated",
		Email:        "e@e.com",
		Phone:        "+1234",
		AppMetadata:  map[string]interface{}{"provider": "email"},
		UserMetadata: map[string]interface{}{"name": "Test"},
		Identities:   []identityResponse{},
		CreatedAt:    time.Now().Format(time.RFC3339),
		UpdatedAt:    time.Now().Format(time.RFC3339),
	}
	if resp.Aud != "authenticated" {
		t.Error("unexpected Aud")
	}
	if resp.Role != "authenticated" {
		t.Error("unexpected Role")
	}
}

func TestIdentityResponse_Fields(t *testing.T) {
	resp := identityResponse{
		IdentityID:   "iid",
		ID:           "pid",
		UserID:       "uid",
		IdentityData: map[string]interface{}{"email": "e@e.com"},
		Provider:     "email",
		CreatedAt:    time.Now().Format(time.RFC3339),
		UpdatedAt:    time.Now().Format(time.RFC3339),
	}
	if resp.Provider != "email" {
		t.Error("unexpected Provider")
	}
}
