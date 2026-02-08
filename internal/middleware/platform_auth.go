package middleware

import (
	"net/http"
	"strings"

	"github.com/ansoraGROUP/dupabase/internal/platform"
)

// PlatformAuth is middleware that validates platform JWT tokens.
// It sets "user_id" and "email" in the request context.
type PlatformAuth struct {
	authService *platform.AuthService
}

func NewPlatformAuth(authService *platform.AuthService) *PlatformAuth {
	return &PlatformAuth{authService: authService}
}

type contextKey string

const (
	ContextUserID contextKey = "user_id"
	ContextEmail  contextKey = "email"
)

func (m *PlatformAuth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing authorization header"})
			return
		}

		token := strings.TrimPrefix(auth, "Bearer ")
		if token == auth {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid authorization format"})
			return
		}

		claims, err := m.authService.ValidateToken(token)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid or expired token"})
			return
		}

		if claims.Type != "platform" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token type"})
			return
		}

		// Store in request context
		ctx := r.Context()
		ctx = setContextValue(ctx, ContextUserID, claims.Subject)
		ctx = setContextValue(ctx, ContextEmail, claims.Email)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetUserID extracts the user ID from the request context.
func GetUserID(r *http.Request) string {
	v, _ := r.Context().Value(ContextUserID).(string)
	return v
}
