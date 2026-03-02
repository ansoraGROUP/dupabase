package platform

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/ansoraGROUP/dupabase/internal/database"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AnalyticsService provides per-project database analytics.
type AnalyticsService struct {
	db          *pgxpool.Pool // platform DB (for project lookups)
	poolManager *database.PoolManager
}

// NewAnalyticsService creates a new AnalyticsService.
func NewAnalyticsService(db *pgxpool.Pool, pm *database.PoolManager) *AnalyticsService {
	return &AnalyticsService{db: db, poolManager: pm}
}

// --- Types ---

// DatabaseAnalytics contains database size and table statistics.
type DatabaseAnalytics struct {
	DBSize     int64        `json:"db_size"`
	TableCount int          `json:"table_count"`
	TotalRows  int64        `json:"total_rows"`
	Tables     []TableStats `json:"tables"`
}

// TableStats contains statistics for a single table.
type TableStats struct {
	Schema    string `json:"schema"`
	Name      string `json:"name"`
	RowCount  int64  `json:"row_count"`
	TotalSize int64  `json:"total_size"`
	IndexSize int64  `json:"index_size"`
}

// ConnectionAnalytics contains connection pool statistics.
type ConnectionAnalytics struct {
	Total       int               `json:"total"`
	Active      int               `json:"active"`
	Idle        int               `json:"idle"`
	IdleInTx    int               `json:"idle_in_transaction"`
	Connections []ConnectionState `json:"connections"`
}

// ConnectionState represents a connection state and its count.
type ConnectionState struct {
	State string `json:"state"`
	Count int    `json:"count"`
}

// QueryAnalytics contains slow query statistics from pg_stat_statements.
type QueryAnalytics struct {
	Available bool         `json:"available"`
	Queries   []QueryStats `json:"queries"`
}

// QueryStats contains statistics for a single query.
type QueryStats struct {
	Query       string  `json:"query"`
	Calls       int64   `json:"calls"`
	TotalTimeMs float64 `json:"total_time_ms"`
	MeanTimeMs  float64 `json:"mean_time_ms"`
	Rows        int64   `json:"rows"`
}

// AuthAnalytics contains authentication statistics.
type AuthAnalytics struct {
	TotalUsers     int64 `json:"total_users"`
	Signups7d      int64 `json:"signups_7d"`
	Signups30d     int64 `json:"signups_30d"`
	ActiveSessions int64 `json:"active_sessions"`
}

// APIUsageAnalytics contains API usage statistics from the audit log.
type APIUsageAnalytics struct {
	DailyUsage []DailyUsage `json:"daily_usage"`
}

// DailyUsage represents a single day's usage for an action.
type DailyUsage struct {
	Day    string `json:"day"`
	Action string `json:"action"`
	Count  int64  `json:"count"`
}

// OverviewAnalytics combines all analytics into a single response.
type OverviewAnalytics struct {
	Database    *DatabaseAnalytics   `json:"database"`
	Connections *ConnectionAnalytics `json:"connections"`
	Auth        *AuthAnalytics       `json:"auth"`
	APIUsage    *APIUsageAnalytics   `json:"api_usage"`
}

// --- Helpers ---

// getProjectDBName looks up the project's db_name from platform.projects.
func (s *AnalyticsService) getProjectDBName(ctx context.Context, projectID string) (string, error) {
	var dbName string
	err := s.db.QueryRow(ctx, `SELECT db_name FROM platform.projects WHERE id = $1 AND status = 'active'`, projectID).Scan(&dbName)
	if err != nil {
		return "", fmt.Errorf("project not found: %w", err)
	}
	return dbName, nil
}

// getProjectPool gets a connection pool for the project via pool manager.
func (s *AnalyticsService) getProjectPool(ctx context.Context, projectID string) (*pgxpool.Pool, error) {
	pool, err := s.poolManager.GetPool(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("get project pool: %w", err)
	}
	return pool, nil
}

// --- Methods ---

// GetDatabaseAnalytics returns database size and table statistics for a project.
func (s *AnalyticsService) GetDatabaseAnalytics(ctx context.Context, projectID string) (*DatabaseAnalytics, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	pool, err := s.getProjectPool(ctx, projectID)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("get project pool: %w", err)
	}

	result := &DatabaseAnalytics{
		Tables: []TableStats{},
	}

	// Get database size
	err = pool.QueryRow(ctx, `SELECT pg_database_size(current_database()) AS db_size`).Scan(&result.DBSize)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("query db size: %w", err)
	}

	// Get table stats
	rows, err := pool.Query(ctx, `
		SELECT schemaname, relname AS table_name,
			n_live_tup AS row_count,
			pg_total_relation_size(quote_ident(schemaname) || '.' || quote_ident(relname)) AS total_size,
			pg_indexes_size(quote_ident(schemaname) || '.' || quote_ident(relname)) AS index_size
		FROM pg_stat_user_tables
		ORDER BY pg_total_relation_size(quote_ident(schemaname) || '.' || quote_ident(relname)) DESC
	`)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("query table stats: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var t TableStats
		if err := rows.Scan(&t.Schema, &t.Name, &t.RowCount, &t.TotalSize, &t.IndexSize); err != nil {
			return nil, http.StatusInternalServerError, fmt.Errorf("scan table stats: %w", err)
		}
		result.Tables = append(result.Tables, t)
		result.TotalRows += t.RowCount
	}
	result.TableCount = len(result.Tables)

	return result, http.StatusOK, nil
}

// GetConnectionAnalytics returns connection statistics for a project.
func (s *AnalyticsService) GetConnectionAnalytics(ctx context.Context, projectID string) (*ConnectionAnalytics, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	dbName, err := s.getProjectDBName(ctx, projectID)
	if err != nil {
		return nil, http.StatusNotFound, fmt.Errorf("project not found")
	}

	result := &ConnectionAnalytics{
		Connections: []ConnectionState{},
	}

	rows, err := s.db.Query(ctx, `
		SELECT state, COUNT(*) as count
		FROM pg_stat_activity
		WHERE datname = $1
		GROUP BY state
	`, dbName)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("query connections: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var cs ConnectionState
		if err := rows.Scan(&cs.State, &cs.Count); err != nil {
			return nil, http.StatusInternalServerError, fmt.Errorf("scan connection state: %w", err)
		}
		result.Connections = append(result.Connections, cs)
		result.Total += cs.Count

		switch cs.State {
		case "active":
			result.Active = cs.Count
		case "idle":
			result.Idle = cs.Count
		case "idle in transaction":
			result.IdleInTx = cs.Count
		}
	}

	return result, http.StatusOK, nil
}

// GetQueryAnalytics returns slow query statistics from pg_stat_statements.
func (s *AnalyticsService) GetQueryAnalytics(ctx context.Context, projectID string) (*QueryAnalytics, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	pool, err := s.getProjectPool(ctx, projectID)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("get project pool: %w", err)
	}

	result := &QueryAnalytics{
		Available: true,
		Queries:   []QueryStats{},
	}

	rows, err := pool.Query(ctx, `
		SELECT query, calls, total_exec_time, mean_exec_time, rows
		FROM pg_stat_statements
		WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
		ORDER BY total_exec_time DESC
		LIMIT 20
	`)
	if err != nil {
		// pg_stat_statements may not be available
		slog.Warn("pg_stat_statements not available", "project_id", projectID, "error", err)
		result.Available = false
		return result, http.StatusOK, nil
	}
	defer rows.Close()

	for rows.Next() {
		var q QueryStats
		if err := rows.Scan(&q.Query, &q.Calls, &q.TotalTimeMs, &q.MeanTimeMs, &q.Rows); err != nil {
			slog.Warn("failed to scan query stats", "project_id", projectID, "error", err)
			result.Available = false
			return result, http.StatusOK, nil
		}
		result.Queries = append(result.Queries, q)
	}

	return result, http.StatusOK, nil
}

// GetAuthAnalytics returns authentication statistics for a project.
func (s *AnalyticsService) GetAuthAnalytics(ctx context.Context, projectID string) (*AuthAnalytics, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	pool, err := s.getProjectPool(ctx, projectID)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("get project pool: %w", err)
	}

	result := &AuthAnalytics{}

	// Total users
	err = pool.QueryRow(ctx, `SELECT COUNT(*) FROM auth.users`).Scan(&result.TotalUsers)
	if err != nil {
		slog.Warn("failed to query auth.users count", "project_id", projectID, "error", err)
		return result, http.StatusOK, nil
	}

	// Signups last 7 days
	err = pool.QueryRow(ctx, `SELECT COUNT(*) FROM auth.users WHERE created_at >= NOW() - INTERVAL '7 days'`).Scan(&result.Signups7d)
	if err != nil {
		slog.Warn("failed to query 7d signups", "project_id", projectID, "error", err)
	}

	// Signups last 30 days
	err = pool.QueryRow(ctx, `SELECT COUNT(*) FROM auth.users WHERE created_at >= NOW() - INTERVAL '30 days'`).Scan(&result.Signups30d)
	if err != nil {
		slog.Warn("failed to query 30d signups", "project_id", projectID, "error", err)
	}

	// Active sessions
	err = pool.QueryRow(ctx, `SELECT COUNT(*) FROM auth.sessions WHERE not_after IS NULL OR not_after > NOW()`).Scan(&result.ActiveSessions)
	if err != nil {
		slog.Warn("failed to query active sessions", "project_id", projectID, "error", err)
	}

	return result, http.StatusOK, nil
}

// GetAPIUsageAnalytics returns API usage statistics from the platform audit log.
func (s *AnalyticsService) GetAPIUsageAnalytics(ctx context.Context, projectID string) (*APIUsageAnalytics, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	result := &APIUsageAnalytics{
		DailyUsage: []DailyUsage{},
	}

	rows, err := s.db.Query(ctx, `
		SELECT DATE(created_at) as day, action, COUNT(*) as count
		FROM platform.audit_log
		WHERE resource_id = $1 AND created_at >= NOW() - INTERVAL '30 days'
		GROUP BY day, action
		ORDER BY day DESC
	`, projectID)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("query api usage: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var du DailyUsage
		var day time.Time
		if err := rows.Scan(&day, &du.Action, &du.Count); err != nil {
			return nil, http.StatusInternalServerError, fmt.Errorf("scan api usage: %w", err)
		}
		du.Day = day.Format("2006-01-02")
		result.DailyUsage = append(result.DailyUsage, du)
	}

	return result, http.StatusOK, nil
}

// GetOverviewAnalytics returns a combined overview of all analytics for a project.
func (s *AnalyticsService) GetOverviewAnalytics(ctx context.Context, projectID string) (*OverviewAnalytics, int, error) {
	result := &OverviewAnalytics{}

	// Collect all analytics, logging warnings for partial failures
	if db, _, err := s.GetDatabaseAnalytics(ctx, projectID); err == nil {
		result.Database = db
	} else {
		slog.Warn("failed to get database analytics", "project_id", projectID, "error", err)
	}

	if conn, _, err := s.GetConnectionAnalytics(ctx, projectID); err == nil {
		result.Connections = conn
	} else {
		slog.Warn("failed to get connection analytics", "project_id", projectID, "error", err)
	}

	if auth, _, err := s.GetAuthAnalytics(ctx, projectID); err == nil {
		result.Auth = auth
	} else {
		slog.Warn("failed to get auth analytics", "project_id", projectID, "error", err)
	}

	if api, _, err := s.GetAPIUsageAnalytics(ctx, projectID); err == nil {
		result.APIUsage = api
	} else {
		slog.Warn("failed to get api usage analytics", "project_id", projectID, "error", err)
	}

	return result, http.StatusOK, nil
}
