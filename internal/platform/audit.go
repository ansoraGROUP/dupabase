package platform

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/ansoraGROUP/dupabase/internal/httputil"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AuditService writes security-relevant events to the platform audit log.
type AuditService struct {
	db         *pgxpool.Pool
	trustProxy bool
}

func NewAuditService(db *pgxpool.Pool, trustProxy bool) *AuditService {
	return &AuditService{db: db, trustProxy: trustProxy}
}

// Log records an audit event. Non-blocking — errors are silently ignored
// since audit logging should never break the main flow.
func (a *AuditService) Log(ctx context.Context, userID *string, action, resourceType, resourceID string, r *http.Request, metadata map[string]interface{}) {
	ip := a.extractClientIP(r)
	ua := r.Header.Get("User-Agent")

	var metaJSON []byte
	if metadata != nil {
		metaJSON, _ = json.Marshal(metadata)
	} else {
		metaJSON = []byte("{}")
	}

	if _, err := a.db.Exec(ctx, `
		INSERT INTO platform.audit_log (user_id, action, resource_type, resource_id, ip_address, user_agent, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, userID, action, resourceType, resourceID, ip, ua, string(metaJSON)); err != nil {
		slog.Warn("audit log failed", "error", err, "action", action, "user_id", userID)
	}
}

func (a *AuditService) extractClientIP(r *http.Request) string {
	return httputil.ExtractClientIP(r, a.trustProxy)
}
