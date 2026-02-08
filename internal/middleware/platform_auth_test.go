package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ansoraGROUP/dupabase/internal/platform"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const testPlatformSecret = "test-platform-secret-long-enough-32chars!"

func newTestPlatformAuthService() *platform.AuthService {
	return platform.NewAuthService(nil, testPlatformSecret, 3600)
}

func generateTestPlatformToken(secret, userID, email, tokenType string, expiry time.Duration) string {
	now := time.Now()
	claims := platform.PlatformClaims{
		Email: email,
		Type:  tokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(expiry)),
			Issuer:    "dupabase",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := token.SignedString([]byte(secret))
	return signed
}

// ---------------------------------------------------------------------------
// PlatformAuth.Middleware
// ---------------------------------------------------------------------------

func TestPlatformAuth_ValidToken(t *testing.T) {
	authSvc := newTestPlatformAuthService()
	mw := NewPlatformAuth(authSvc)

	token := generateTestPlatformToken(testPlatformSecret, "user-123", "test@example.com", "platform", time.Hour)

	// Inner handler that verifies context values
	var gotUserID, gotEmail string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUserID = GetUserID(r)
		gotEmail, _ = r.Context().Value(ContextEmail).(string)
		w.WriteHeader(http.StatusOK)
	})

	handler := mw.Middleware(inner)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
	if gotUserID != "user-123" {
		t.Errorf("expected user ID 'user-123', got %q", gotUserID)
	}
	if gotEmail != "test@example.com" {
		t.Errorf("expected email 'test@example.com', got %q", gotEmail)
	}
}

func TestPlatformAuth_MissingAuthorizationHeader(t *testing.T) {
	authSvc := newTestPlatformAuthService()
	mw := NewPlatformAuth(authSvc)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler should not be called")
	})

	handler := mw.Middleware(inner)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}

	var body map[string]string
	json.NewDecoder(rec.Body).Decode(&body)
	if body["error"] != "missing authorization header" {
		t.Errorf("unexpected error message: %q", body["error"])
	}
}

func TestPlatformAuth_InvalidAuthorizationFormat(t *testing.T) {
	authSvc := newTestPlatformAuthService()
	mw := NewPlatformAuth(authSvc)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler should not be called")
	})

	handler := mw.Middleware(inner)

	tests := []struct {
		name   string
		header string
	}{
		{"no_bearer_prefix", "Token abc123"},
		{"basic_auth", "Basic dXNlcjpwYXNz"},
		{"just_token", "some-token-without-bearer"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Header.Set("Authorization", tt.header)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Errorf("expected status 401, got %d", rec.Code)
			}

			var body map[string]string
			json.NewDecoder(rec.Body).Decode(&body)
			if body["error"] != "invalid authorization format" {
				t.Errorf("unexpected error: %q", body["error"])
			}
		})
	}
}

func TestPlatformAuth_ExpiredToken(t *testing.T) {
	authSvc := newTestPlatformAuthService()
	mw := NewPlatformAuth(authSvc)

	token := generateTestPlatformToken(testPlatformSecret, "user-123", "test@example.com", "platform", -time.Hour)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler should not be called")
	})

	handler := mw.Middleware(inner)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}

	var body map[string]string
	json.NewDecoder(rec.Body).Decode(&body)
	if body["error"] != "invalid or expired token" {
		t.Errorf("unexpected error: %q", body["error"])
	}
}

func TestPlatformAuth_WrongSecret(t *testing.T) {
	authSvc := newTestPlatformAuthService()
	mw := NewPlatformAuth(authSvc)

	token := generateTestPlatformToken("completely-different-secret-32chars!!", "user-123", "test@example.com", "platform", time.Hour)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler should not be called")
	})

	handler := mw.Middleware(inner)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}
}

func TestPlatformAuth_WrongTokenType(t *testing.T) {
	authSvc := newTestPlatformAuthService()
	mw := NewPlatformAuth(authSvc)

	// Token with type "user" instead of "platform"
	token := generateTestPlatformToken(testPlatformSecret, "user-123", "test@example.com", "user", time.Hour)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler should not be called")
	})

	handler := mw.Middleware(inner)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}

	var body map[string]string
	json.NewDecoder(rec.Body).Decode(&body)
	if body["error"] != "invalid token type" {
		t.Errorf("unexpected error: %q", body["error"])
	}
}

func TestPlatformAuth_MalformedToken(t *testing.T) {
	authSvc := newTestPlatformAuthService()
	mw := NewPlatformAuth(authSvc)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler should not be called")
	})

	handler := mw.Middleware(inner)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer not-a-valid-jwt")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// GetUserID helper
// ---------------------------------------------------------------------------

func TestGetUserID_EmptyContext(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	userID := GetUserID(req)
	if userID != "" {
		t.Errorf("expected empty user ID, got %q", userID)
	}
}

// ---------------------------------------------------------------------------
// setContextValue and context extraction
// ---------------------------------------------------------------------------

func TestSetContextValue_RoundTrip(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	ctx := setContextValue(req.Context(), ContextUserID, "user-abc")
	ctx = setContextValue(ctx, ContextEmail, "abc@test.com")
	req = req.WithContext(ctx)

	if got := GetUserID(req); got != "user-abc" {
		t.Errorf("expected user ID 'user-abc', got %q", got)
	}
	if got, _ := req.Context().Value(ContextEmail).(string); got != "abc@test.com" {
		t.Errorf("expected email 'abc@test.com', got %q", got)
	}
}

// ---------------------------------------------------------------------------
// Verify middleware passes through for valid requests
// ---------------------------------------------------------------------------

func TestPlatformAuth_PassesThroughCorrectly(t *testing.T) {
	authSvc := newTestPlatformAuthService()
	mw := NewPlatformAuth(authSvc)

	token := generateTestPlatformToken(testPlatformSecret, "uid-xyz", "xyz@test.com", "platform", time.Hour)

	callCount := 0
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	handler := mw.Middleware(inner)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if callCount != 1 {
		t.Errorf("expected inner handler called once, got %d", callCount)
	}
	if rec.Body.String() != "ok" {
		t.Errorf("unexpected body: %q", rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Content-Type on error responses
// ---------------------------------------------------------------------------

func TestPlatformAuth_ErrorResponseContentType(t *testing.T) {
	authSvc := newTestPlatformAuthService()
	mw := NewPlatformAuth(authSvc)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not be called")
	})

	handler := mw.Middleware(inner)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got %q", ct)
	}
}
