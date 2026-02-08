package platform

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// AuditService writes security-relevant events to the platform audit log.
type AuditService struct {
	db *pgxpool.Pool
}

func NewAuditService(db *pgxpool.Pool) *AuditService {
	return &AuditService{db: db}
}

// Log records an audit event. Non-blocking — errors are silently ignored
// since audit logging should never break the main flow.
func (a *AuditService) Log(ctx context.Context, userID *string, action, resourceType, resourceID string, r *http.Request, metadata map[string]interface{}) {
	ip := extractClientIP(r)
	ua := r.Header.Get("User-Agent")

	var metaJSON []byte
	if metadata != nil {
		metaJSON, _ = json.Marshal(metadata)
	} else {
		metaJSON = []byte("{}")
	}

	a.db.Exec(ctx, `
		INSERT INTO platform.audit_log (user_id, action, resource_type, resource_id, ip_address, user_agent, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, userID, action, resourceType, resourceID, ip, ua, string(metaJSON))
}

func extractClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.Index(xff, ","); idx > 0 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx > 0 {
		ip = ip[:idx]
	}
	return ip
}
