package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// ---------------------------------------------------------------------------
// CORS middleware tests (T1)
// ---------------------------------------------------------------------------

func TestCORS(t *testing.T) {
	// Save and restore package-level corsOrigins so tests are isolated.
	origOrigins := corsOrigins
	defer func() { corsOrigins = origOrigins }()
	corsOrigins = map[string]bool{"http://localhost:3000": true}

	dummy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := cors(dummy)

	// Test 1: Allowed origin (localhost:3000) gets reflected with credentials
	t.Run("allowed origin reflected", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		got := rec.Header().Get("Access-Control-Allow-Origin")
		if got != "http://localhost:3000" {
			t.Errorf("expected origin reflected, got %q", got)
		}
	})

	// Test 2: Unknown origin gets wildcard "*" (S8 fix: no longer reflected)
	t.Run("unknown origin gets wildcard", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Origin", "https://evil.com")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		got := rec.Header().Get("Access-Control-Allow-Origin")
		if got != "*" {
			t.Errorf("expected '*' for unknown origin, got %q", got)
		}
	})

	// Test 3: No Origin header => wildcard "*"
	t.Run("no origin gets wildcard", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		got := rec.Header().Get("Access-Control-Allow-Origin")
		if got != "*" {
			t.Errorf("expected '*' for no origin, got %q", got)
		}
	})

	// Test 4: Preflight OPTIONS returns 204
	t.Run("preflight returns 204", func(t *testing.T) {
		req := httptest.NewRequest("OPTIONS", "/", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		req.Header.Set("Access-Control-Request-Method", "POST")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusNoContent {
			t.Errorf("expected 204, got %d", rec.Code)
		}
	})

	// Test 5: Credentials header set for allowed origins
	t.Run("credentials for allowed origin", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		got := rec.Header().Get("Access-Control-Allow-Credentials")
		if got != "true" {
			t.Errorf("expected credentials true for allowed origin, got %q", got)
		}
	})

	// Test 6: No credentials for unknown origin
	t.Run("no credentials for unknown origin", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Origin", "https://evil.com")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		got := rec.Header().Get("Access-Control-Allow-Credentials")
		if got == "true" {
			t.Errorf("should not send credentials for unknown origin")
		}
	})

	// Test 7: Vary header always set
	t.Run("vary header set", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		got := rec.Header().Get("Vary")
		if got != "Origin" {
			t.Errorf("expected Vary: Origin, got %q", got)
		}
	})

	// Test 8: Access-Control-Allow-Methods present
	t.Run("allow methods header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		got := rec.Header().Get("Access-Control-Allow-Methods")
		if got == "" {
			t.Error("expected Access-Control-Allow-Methods to be set")
		}
	})

	// Test 9: Request headers are reflected when Access-Control-Request-Headers is sent
	t.Run("reflect requested headers", func(t *testing.T) {
		req := httptest.NewRequest("OPTIONS", "/", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		req.Header.Set("Access-Control-Request-Headers", "X-Custom-Header, Authorization")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		got := rec.Header().Get("Access-Control-Allow-Headers")
		if got != "X-Custom-Header, Authorization" {
			t.Errorf("expected requested headers reflected, got %q", got)
		}
	})

	// Test 10: Wildcard allow-headers when no request headers specified
	t.Run("wildcard headers when none requested", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		got := rec.Header().Get("Access-Control-Allow-Headers")
		if got != "*" {
			t.Errorf("expected '*' allow-headers, got %q", got)
		}
	})

	// Test 11: Expose-Headers present
	t.Run("expose headers set", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		got := rec.Header().Get("Access-Control-Expose-Headers")
		if got != "Content-Range, X-Total-Count" {
			t.Errorf("expected 'Content-Range, X-Total-Count', got %q", got)
		}
	})

	// Test 12: Max-Age set
	t.Run("max age set", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		got := rec.Header().Get("Access-Control-Max-Age")
		if got != "86400" {
			t.Errorf("expected '86400', got %q", got)
		}
	})

	// Test 13: Non-OPTIONS request passes through to handler
	t.Run("non-options passes through", func(t *testing.T) {
		called := false
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		})
		h := cors(inner)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if !called {
			t.Error("expected inner handler to be called for non-OPTIONS")
		}
	})

	// Test 14: OPTIONS does NOT pass through to handler
	t.Run("options does not pass through", func(t *testing.T) {
		called := false
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		})
		h := cors(inner)

		req := httptest.NewRequest("OPTIONS", "/", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if called {
			t.Error("expected inner handler NOT to be called for OPTIONS")
		}
	})
}

// TestAllowedOrigins verifies that with no ALLOWED_ORIGINS env var, the map is empty.
func TestAllowedOrigins(t *testing.T) {
	t.Setenv("ALLOWED_ORIGINS", "")
	origins := allowedOrigins()

	if len(origins) != 0 {
		t.Errorf("expected empty origins map when ALLOWED_ORIGINS is unset, got %d entries: %v", len(origins), origins)
	}
}

// TestAllowedOrigins_WithEnv verifies ALLOWED_ORIGINS env var is respected.
func TestAllowedOrigins_WithEnv(t *testing.T) {
	t.Setenv("ALLOWED_ORIGINS", "https://example.com, https://app.example.com")
	origins := allowedOrigins()

	if !origins["https://example.com"] {
		t.Error("expected https://example.com in origins")
	}
	if !origins["https://app.example.com"] {
		t.Error("expected https://app.example.com in origins")
	}
	// No hardcoded defaults — only env var origins should be present
	if len(origins) != 2 {
		t.Errorf("expected exactly 2 origins from env var, got %d: %v", len(origins), origins)
	}
}

// ---------------------------------------------------------------------------
// Security headers middleware tests (T2)
// ---------------------------------------------------------------------------

func TestSecurityHeaders(t *testing.T) {
	dummy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := securityHeaders(dummy, false)

	// Test 1: X-Content-Type-Options
	t.Run("nosniff header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("expected nosniff, got %q", got)
		}
	})

	// Test 2: X-Frame-Options
	t.Run("frame deny header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
			t.Errorf("expected DENY, got %q", got)
		}
	})

	// Test 3: X-XSS-Protection
	t.Run("xss protection header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if got := rec.Header().Get("X-XSS-Protection"); got != "1; mode=block" {
			t.Errorf("expected '1; mode=block', got %q", got)
		}
	})

	// Test 4: Referrer-Policy
	t.Run("referrer policy header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if got := rec.Header().Get("Referrer-Policy"); got != "strict-origin-when-cross-origin" {
			t.Errorf("expected strict-origin-when-cross-origin, got %q", got)
		}
	})

	// Test 5: Permissions-Policy
	t.Run("permissions policy header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if got := rec.Header().Get("Permissions-Policy"); got == "" {
			t.Error("expected Permissions-Policy to be set")
		}
	})

	// Test 6: CSP present for API routes (strict)
	t.Run("strict csp for api route", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/platform/projects", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		got := rec.Header().Get("Content-Security-Policy")
		if got != "default-src 'none'; frame-ancestors 'none'" {
			t.Errorf("expected strict CSP for API route, got %q", got)
		}
	})

	// Test 7: CSP present for non-API routes (relaxed)
	t.Run("relaxed csp for dashboard route", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/dashboard", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		got := rec.Header().Get("Content-Security-Policy")
		if got == "default-src 'none'; frame-ancestors 'none'" {
			t.Error("expected relaxed CSP for dashboard route, got strict")
		}
		if got == "" {
			t.Error("expected CSP header to be set")
		}
	})

	// Test 8: HSTS set when trustProxy=true and X-Forwarded-Proto is https (S9 fix)
	t.Run("hsts with trust proxy and forwarded proto https", func(t *testing.T) {
		trustedHandler := securityHeaders(dummy, true)
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Forwarded-Proto", "https")
		rec := httptest.NewRecorder()
		trustedHandler.ServeHTTP(rec, req)

		got := rec.Header().Get("Strict-Transport-Security")
		if got == "" {
			t.Error("expected HSTS header when trustProxy=true and X-Forwarded-Proto=https")
		}
	})

	// Test 9: No HSTS without https
	t.Run("no hsts without https", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		got := rec.Header().Get("Strict-Transport-Security")
		if got != "" {
			t.Errorf("expected no HSTS without https, got %q", got)
		}
	})

	// Test 10b: No HSTS when X-Forwarded-Proto is https but trustProxy is false (S9)
	t.Run("no hsts without trust proxy", func(t *testing.T) {
		// handler was created with trustProxy=false
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Forwarded-Proto", "https")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		got := rec.Header().Get("Strict-Transport-Security")
		if got != "" {
			t.Errorf("expected no HSTS without trustProxy, got %q", got)
		}
	})

	// Test 10: Handler passes through
	t.Run("passes through to next handler", func(t *testing.T) {
		called := false
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		})
		h := securityHeaders(inner, false)

		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if !called {
			t.Error("expected inner handler to be called")
		}
	})
}

// TestIsAPIRoute verifies API route detection.
func TestIsAPIRoute(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/platform/projects", true},
		{"/platform/auth/login", true},
		{"/auth/v1/signup", true},
		{"/auth/v1/token", true},
		{"/rest/v1/users", true},
		{"/rest/v1/rpc/my_func", true},
		{"/health", true},
		{"/", false},
		{"/dashboard", false},
		{"/some/other/path", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := isAPIRoute(tt.path)
			if got != tt.want {
				t.Errorf("isAPIRoute(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
