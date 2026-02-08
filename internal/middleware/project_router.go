package middleware

import (
	"context"
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ansoraGROUP/dupabase/internal/database"
)

type projectContextKey string

const (
	ContextProject    projectContextKey = "project"
	ContextProjectSQL projectContextKey = "project_sql"
	ContextAPIKeyClaims projectContextKey = "apikey_claims"
	ContextAPIKeyRole   projectContextKey = "apikey_role"
)

// ProjectRouter middleware extracts project_id from the apikey JWT,
// looks up the project, verifies the JWT, and injects project context.
type ProjectRouter struct {
	poolManager *database.PoolManager
}

func NewProjectRouter(pm *database.PoolManager) *ProjectRouter {
	return &ProjectRouter{poolManager: pm}
}

func (m *ProjectRouter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apikey := r.Header.Get("apikey")
		if apikey == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
				"code":    "PGRST301",
				"message": "Missing apikey header",
			})
			return
		}

		// Decode JWT without verification to get project_id
		parser := jwt.NewParser(jwt.WithoutClaimsValidation())
		unverified := jwt.MapClaims{}
		_, _, err := parser.ParseUnverified(apikey, unverified)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
				"code":    "PGRST301",
				"message": "Invalid API key format",
			})
			return
		}

		projectID, ok := unverified["project_id"].(string)
		if !ok || projectID == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
				"code":    "PGRST301",
				"message": "API key missing project_id claim",
			})
			return
		}

		// Look up the project
		project, err := m.poolManager.GetProject(r.Context(), projectID)
		if err != nil || project == nil {
			writeJSON(w, http.StatusNotFound, map[string]interface{}{
				"code":    "PGRST301",
				"message": "Project not found or inactive",
			})
			return
		}

		// Now verify the JWT with the project's secret (enforce HMAC algorithm)
		verified, err := jwt.Parse(apikey, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return []byte(project.JWTSecret), nil
		})
		if err != nil || !verified.Valid {
			writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
				"code":    "PGRST301",
				"message": "Invalid API key",
			})
			return
		}

		claims, _ := verified.Claims.(jwt.MapClaims)
		role, _ := claims["role"].(string)
		if role == "" {
			role = "anon"
		}

		// Get database connection pool for this project
		pool, err := m.poolManager.GetPool(r.Context(), projectID)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
				"code":    "PGRST503",
				"message": "Database connection unavailable",
			})
			return
		}

		// Inject into context
		ctx := r.Context()
		ctx = context.WithValue(ctx, ContextProject, project)
		ctx = context.WithValue(ctx, ContextProjectSQL, pool)
		ctx = context.WithValue(ctx, ContextAPIKeyClaims, claims)
		ctx = context.WithValue(ctx, ContextAPIKeyRole, role)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Helper functions to extract project context from requests.

func GetProject(r *http.Request) *database.ProjectRecord {
	p, _ := r.Context().Value(ContextProject).(*database.ProjectRecord)
	return p
}

func GetProjectSQL(r *http.Request) *pgxpool.Pool {
	p, _ := r.Context().Value(ContextProjectSQL).(*pgxpool.Pool)
	return p
}

func GetAPIKeyRole(r *http.Request) string {
	s, _ := r.Context().Value(ContextAPIKeyRole).(string)
	return s
}

func GetAPIKeyClaims(r *http.Request) jwt.MapClaims {
	c, _ := r.Context().Value(ContextAPIKeyClaims).(jwt.MapClaims)
	return c
}
