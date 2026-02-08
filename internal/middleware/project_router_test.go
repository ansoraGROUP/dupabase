package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ansoraGROUP/dupabase/internal/database"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func generateProjectAPIKey(secret, projectID, role string) string {
	now := time.Now()
	claims := jwt.MapClaims{
		"role":       role,
		"iss":        "supabase",
		"project_id": projectID,
		"iat":        now.Unix(),
		"exp":        now.Add(10 * 365 * 24 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := token.SignedString([]byte(secret))
	return signed
}

func generateExpiredAPIKey(secret, projectID, role string) string {
	now := time.Now()
	claims := jwt.MapClaims{
		"role":       role,
		"iss":        "supabase",
		"project_id": projectID,
		"iat":        now.Add(-2 * time.Hour).Unix(),
		"exp":        now.Add(-1 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := token.SignedString([]byte(secret))
	return signed
}

func generateAPIKeyWithoutProjectID(secret, role string) string {
	now := time.Now()
	claims := jwt.MapClaims{
		"role": role,
		"iss":  "supabase",
		"iat":  now.Unix(),
		"exp":  now.Add(10 * 365 * 24 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := token.SignedString([]byte(secret))
	return signed
}

// ---------------------------------------------------------------------------
// Context helper tests
// ---------------------------------------------------------------------------

func TestGetProject_NilContext(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	project := GetProject(req)
	if project != nil {
		t.Error("expected nil project from empty context")
	}
}

func TestGetProjectSQL_NilContext(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	pool := GetProjectSQL(req)
	if pool != nil {
		t.Error("expected nil pool from empty context")
	}
}

func TestGetAPIKeyRole_EmptyContext(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	role := GetAPIKeyRole(req)
	if role != "" {
		t.Errorf("expected empty role, got %q", role)
	}
}

func TestGetAPIKeyClaims_EmptyContext(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	claims := GetAPIKeyClaims(req)
	if claims != nil {
		t.Error("expected nil claims from empty context")
	}
}

// ---------------------------------------------------------------------------
// Context round-trip
// ---------------------------------------------------------------------------

func TestContextRoundTrip_Project(t *testing.T) {
	project := &database.ProjectRecord{
		ID:     "proj-1",
		DBName: "testdb",
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	ctx := context.WithValue(req.Context(), ContextProject, project)
	req = req.WithContext(ctx)

	got := GetProject(req)
	if got == nil {
		t.Fatal("expected non-nil project")
	}
	if got.ID != "proj-1" {
		t.Errorf("expected ID 'proj-1', got %q", got.ID)
	}
}

func TestContextRoundTrip_ProjectSQL(t *testing.T) {
	// We set a typed nil *pgxpool.Pool to verify the type assertion works
	var pool *pgxpool.Pool
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	ctx := context.WithValue(req.Context(), ContextProjectSQL, pool)
	req = req.WithContext(ctx)

	got := GetProjectSQL(req)
	if got != nil {
		t.Error("expected nil pool (typed nil)")
	}
}

func TestContextRoundTrip_APIKeyRole(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	ctx := context.WithValue(req.Context(), ContextAPIKeyRole, "service_role")
	req = req.WithContext(ctx)

	got := GetAPIKeyRole(req)
	if got != "service_role" {
		t.Errorf("expected 'service_role', got %q", got)
	}
}

func TestContextRoundTrip_APIKeyClaims(t *testing.T) {
	claims := jwt.MapClaims{
		"role":       "anon",
		"project_id": "proj-1",
	}
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	ctx := context.WithValue(req.Context(), ContextAPIKeyClaims, claims)
	req = req.WithContext(ctx)

	got := GetAPIKeyClaims(req)
	if got == nil {
		t.Fatal("expected non-nil claims")
	}
	if role, _ := got["role"].(string); role != "anon" {
		t.Errorf("expected role 'anon', got %q", role)
	}
}

// ---------------------------------------------------------------------------
// ProjectRouter.Middleware -- tests that do NOT need a PoolManager with DB
// These test the apikey parsing before any DB call.
// ---------------------------------------------------------------------------

func TestProjectRouter_MissingApikeyHeader(t *testing.T) {
	// NewProjectRouter with nil pool manager since we will not reach DB calls
	router := NewProjectRouter(nil)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler should not be called")
	})

	handler := router.Middleware(inner)

	req := httptest.NewRequest(http.MethodGet, "/rest/v1/todos", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}

	var body map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&body)
	if body["code"] != "PGRST301" {
		t.Errorf("expected code PGRST301, got %v", body["code"])
	}
	if body["message"] != "Missing apikey header" {
		t.Errorf("unexpected message: %v", body["message"])
	}
}

func TestProjectRouter_InvalidAPIKeyFormat(t *testing.T) {
	router := NewProjectRouter(nil)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler should not be called")
	})

	handler := router.Middleware(inner)

	req := httptest.NewRequest(http.MethodGet, "/rest/v1/todos", nil)
	req.Header.Set("apikey", "not-a-valid-jwt")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}

	var body map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&body)
	if body["message"] != "Invalid API key format" {
		t.Errorf("unexpected message: %v", body["message"])
	}
}

func TestProjectRouter_MissingProjectIDClaim(t *testing.T) {
	router := NewProjectRouter(nil)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler should not be called")
	})

	handler := router.Middleware(inner)

	// Generate a valid JWT but without project_id claim
	apikey := generateAPIKeyWithoutProjectID("test-secret", "anon")

	req := httptest.NewRequest(http.MethodGet, "/rest/v1/todos", nil)
	req.Header.Set("apikey", apikey)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}

	var body map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&body)
	if body["message"] != "API key missing project_id claim" {
		t.Errorf("unexpected message: %v", body["message"])
	}
}

func TestProjectRouter_ErrorResponseContentType(t *testing.T) {
	router := NewProjectRouter(nil)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not be called")
	})

	handler := router.Middleware(inner)

	req := httptest.NewRequest(http.MethodGet, "/rest/v1/todos", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got %q", ct)
	}
}

// ---------------------------------------------------------------------------
// Context keys are distinct
// ---------------------------------------------------------------------------

func TestContextKeys_AreDistinct(t *testing.T) {
	if ContextProject == ContextProjectSQL {
		t.Error("ContextProject and ContextProjectSQL should be distinct")
	}
	if ContextProject == ContextAPIKeyClaims {
		t.Error("ContextProject and ContextAPIKeyClaims should be distinct")
	}
	if ContextProject == ContextAPIKeyRole {
		t.Error("ContextProject and ContextAPIKeyRole should be distinct")
	}
	if ContextProjectSQL == ContextAPIKeyClaims {
		t.Error("ContextProjectSQL and ContextAPIKeyClaims should be distinct")
	}
	if ContextProjectSQL == ContextAPIKeyRole {
		t.Error("ContextProjectSQL and ContextAPIKeyRole should be distinct")
	}
	if ContextAPIKeyClaims == ContextAPIKeyRole {
		t.Error("ContextAPIKeyClaims and ContextAPIKeyRole should be distinct")
	}
}

// ---------------------------------------------------------------------------
// helpers_test
// ---------------------------------------------------------------------------

func TestWriteJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusTeapot, map[string]string{"hello": "world"})

	if rec.Code != http.StatusTeapot {
		t.Errorf("expected status %d, got %d", http.StatusTeapot, rec.Code)
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got %q", ct)
	}

	var body map[string]string
	json.NewDecoder(rec.Body).Decode(&body)
	if body["hello"] != "world" {
		t.Errorf("unexpected body: %v", body)
	}
}
