package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ---------------------------------------------------------------------------
// Health endpoint response format
// ---------------------------------------------------------------------------

func TestHealthEndpointHeaders(t *testing.T) {
	// Test that a health-like handler returns Content-Type: application/json
	// We test the expected header behavior without needing a DB connection.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
	})

	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got %q", ct)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode body: %v", err)
	}
	if body["status"] != "healthy" {
		t.Errorf("expected status 'healthy', got %q", body["status"])
	}
}

// ---------------------------------------------------------------------------
// Security headers on health endpoint
// ---------------------------------------------------------------------------

func TestHealthEndpoint_SecurityHeaders(t *testing.T) {
	// Verify that security headers middleware wraps even simple handlers
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	handler := securityHeaders(inner, false)

	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Check security headers are present
	headers := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"X-XSS-Protection":       "1; mode=block",
		"Referrer-Policy":        "strict-origin-when-cross-origin",
	}

	for name, expected := range headers {
		got := rec.Header().Get(name)
		if got != expected {
			t.Errorf("header %q: got %q, want %q", name, got, expected)
		}
	}

	// Health is an API route, so CSP should be strict
	csp := rec.Header().Get("Content-Security-Policy")
	if csp != "default-src 'none'; frame-ancestors 'none'" {
		t.Errorf("expected strict CSP for /health, got %q", csp)
	}
}

// ---------------------------------------------------------------------------
// CORS + Security headers combined
// ---------------------------------------------------------------------------

func TestCORSAndSecurityHeadersCombined(t *testing.T) {
	// Temporarily add localhost:3000 to the whitelist for this test.
	origOrigins := corsOrigins
	defer func() { corsOrigins = origOrigins }()
	corsOrigins = map[string]bool{"http://localhost:3000": true}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Apply both middleware layers in the order the real server uses
	handler := securityHeaders(cors(inner), false)

	req := httptest.NewRequest("GET", "/rest/v1/users", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Verify CORS headers
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:3000" {
		t.Errorf("CORS origin: got %q, want 'http://localhost:3000'", got)
	}

	// Verify security headers
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options: got %q, want 'nosniff'", got)
	}

	// Should be a successful response
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Method not allowed
// ---------------------------------------------------------------------------

func TestMethodNotAllowed_Pattern(t *testing.T) {
	// Verify the pattern used by handlers that check method
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.WriteHeader(http.StatusOK)
		case http.MethodPost:
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	methods := []struct {
		method   string
		expected int
	}{
		{"GET", 200},
		{"POST", 201},
		{"PUT", 405},
		{"DELETE", 405},
		{"PATCH", 405},
	}

	for _, tt := range methods {
		t.Run(tt.method, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/test", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, rec.Code)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// JSON error response format
// ---------------------------------------------------------------------------

func TestJSONErrorResponseFormat(t *testing.T) {
	// Verify the standard error response format used by platform handlers
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "validation failed",
		})
	})

	req := httptest.NewRequest("POST", "/platform/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got %q", ct)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	if body["error"] != "validation failed" {
		t.Errorf("unexpected error: %v", body["error"])
	}
}

// ---------------------------------------------------------------------------
// Preflight request does not reach handler
// ---------------------------------------------------------------------------

func TestPreflight_DoesNotReachHandler(t *testing.T) {
	reached := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	})

	handler := cors(inner)

	req := httptest.NewRequest("OPTIONS", "/platform/projects", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if reached {
		t.Error("expected OPTIONS to be intercepted by CORS middleware")
	}
	if rec.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", rec.Code)
	}
}
