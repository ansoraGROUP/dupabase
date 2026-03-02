package platform

import (
	"testing"
)

// ---------------------------------------------------------------------------
// NewAnalyticsService constructor
// ---------------------------------------------------------------------------

func TestNewAnalyticsService_ReturnsNonNil(t *testing.T) {
	svc := NewAnalyticsService(nil, nil)
	if svc == nil {
		t.Fatal("NewAnalyticsService returned nil")
	}
}

func TestNewAnalyticsService_Fields(t *testing.T) {
	svc := NewAnalyticsService(nil, nil)
	if svc.db != nil {
		t.Error("expected nil db")
	}
	if svc.poolManager != nil {
		t.Error("expected nil poolManager")
	}
}

// ---------------------------------------------------------------------------
// DatabaseAnalytics type
// ---------------------------------------------------------------------------

func TestDatabaseAnalytics_ZeroValue(t *testing.T) {
	var da DatabaseAnalytics
	if da.DBSize != 0 {
		t.Errorf("expected DBSize 0, got %d", da.DBSize)
	}
	if da.TableCount != 0 {
		t.Errorf("expected TableCount 0, got %d", da.TableCount)
	}
	if da.TotalRows != 0 {
		t.Errorf("expected TotalRows 0, got %d", da.TotalRows)
	}
	if da.Tables != nil {
		t.Error("expected nil Tables")
	}
}

func TestDatabaseAnalytics_InitializedSlice(t *testing.T) {
	da := DatabaseAnalytics{
		Tables: []TableStats{},
	}
	if da.Tables == nil {
		t.Fatal("Tables should not be nil when initialized")
	}
	if len(da.Tables) != 0 {
		t.Errorf("expected empty Tables, got length %d", len(da.Tables))
	}
}

// ---------------------------------------------------------------------------
// ConnectionAnalytics type
// ---------------------------------------------------------------------------

func TestConnectionAnalytics_ZeroValue(t *testing.T) {
	var ca ConnectionAnalytics
	if ca.Total != 0 {
		t.Errorf("expected Total 0, got %d", ca.Total)
	}
	if ca.Active != 0 {
		t.Errorf("expected Active 0, got %d", ca.Active)
	}
	if ca.Idle != 0 {
		t.Errorf("expected Idle 0, got %d", ca.Idle)
	}
	if ca.IdleInTx != 0 {
		t.Errorf("expected IdleInTx 0, got %d", ca.IdleInTx)
	}
	if ca.Connections != nil {
		t.Error("expected nil Connections")
	}
}

func TestConnectionAnalytics_InitializedSlice(t *testing.T) {
	ca := ConnectionAnalytics{
		Connections: []ConnectionState{},
	}
	if ca.Connections == nil {
		t.Fatal("Connections should not be nil when initialized")
	}
	if len(ca.Connections) != 0 {
		t.Errorf("expected empty Connections, got length %d", len(ca.Connections))
	}
}

// ---------------------------------------------------------------------------
// QueryAnalytics type
// ---------------------------------------------------------------------------

func TestQueryAnalytics_ZeroValue(t *testing.T) {
	var qa QueryAnalytics
	if qa.Available {
		t.Error("expected Available false by default")
	}
	if qa.Queries != nil {
		t.Error("expected nil Queries")
	}
}

func TestQueryAnalytics_InitializedSlice(t *testing.T) {
	qa := QueryAnalytics{
		Available: true,
		Queries:   []QueryStats{},
	}
	if !qa.Available {
		t.Error("expected Available true")
	}
	if qa.Queries == nil {
		t.Fatal("Queries should not be nil when initialized")
	}
	if len(qa.Queries) != 0 {
		t.Errorf("expected empty Queries, got length %d", len(qa.Queries))
	}
}

// ---------------------------------------------------------------------------
// AuthAnalytics type
// ---------------------------------------------------------------------------

func TestAuthAnalytics_ZeroValue(t *testing.T) {
	var aa AuthAnalytics
	if aa.TotalUsers != 0 {
		t.Errorf("expected TotalUsers 0, got %d", aa.TotalUsers)
	}
	if aa.Signups7d != 0 {
		t.Errorf("expected Signups7d 0, got %d", aa.Signups7d)
	}
	if aa.Signups30d != 0 {
		t.Errorf("expected Signups30d 0, got %d", aa.Signups30d)
	}
	if aa.ActiveSessions != 0 {
		t.Errorf("expected ActiveSessions 0, got %d", aa.ActiveSessions)
	}
}

// ---------------------------------------------------------------------------
// OverviewAnalytics type
// ---------------------------------------------------------------------------

func TestOverviewAnalytics_ZeroValue(t *testing.T) {
	var oa OverviewAnalytics
	if oa.Database != nil {
		t.Error("expected nil Database")
	}
	if oa.Connections != nil {
		t.Error("expected nil Connections")
	}
	if oa.Auth != nil {
		t.Error("expected nil Auth")
	}
	if oa.APIUsage != nil {
		t.Error("expected nil APIUsage")
	}
}

func TestOverviewAnalytics_Populated(t *testing.T) {
	oa := OverviewAnalytics{
		Database:    &DatabaseAnalytics{DBSize: 1024, Tables: []TableStats{}},
		Connections: &ConnectionAnalytics{Total: 5, Connections: []ConnectionState{}},
		Auth:        &AuthAnalytics{TotalUsers: 100},
		APIUsage:    &APIUsageAnalytics{DailyUsage: []DailyUsage{}},
	}

	if oa.Database.DBSize != 1024 {
		t.Errorf("expected DBSize 1024, got %d", oa.Database.DBSize)
	}
	if oa.Connections.Total != 5 {
		t.Errorf("expected Total 5, got %d", oa.Connections.Total)
	}
	if oa.Auth.TotalUsers != 100 {
		t.Errorf("expected TotalUsers 100, got %d", oa.Auth.TotalUsers)
	}
	if len(oa.APIUsage.DailyUsage) != 0 {
		t.Errorf("expected empty DailyUsage, got %d", len(oa.APIUsage.DailyUsage))
	}
}

// ---------------------------------------------------------------------------
// TableStats struct field access
// ---------------------------------------------------------------------------

func TestTableStats_FieldAccess(t *testing.T) {
	ts := TableStats{
		Schema:    "public",
		Name:      "users",
		RowCount:  42,
		TotalSize: 8192,
		IndexSize: 2048,
	}

	if ts.Schema != "public" {
		t.Errorf("expected Schema 'public', got %q", ts.Schema)
	}
	if ts.Name != "users" {
		t.Errorf("expected Name 'users', got %q", ts.Name)
	}
	if ts.RowCount != 42 {
		t.Errorf("expected RowCount 42, got %d", ts.RowCount)
	}
	if ts.TotalSize != 8192 {
		t.Errorf("expected TotalSize 8192, got %d", ts.TotalSize)
	}
	if ts.IndexSize != 2048 {
		t.Errorf("expected IndexSize 2048, got %d", ts.IndexSize)
	}
}

// ---------------------------------------------------------------------------
// ConnectionState struct field access
// ---------------------------------------------------------------------------

func TestConnectionState_FieldAccess(t *testing.T) {
	cs := ConnectionState{
		State: "active",
		Count: 3,
	}
	if cs.State != "active" {
		t.Errorf("expected State 'active', got %q", cs.State)
	}
	if cs.Count != 3 {
		t.Errorf("expected Count 3, got %d", cs.Count)
	}
}

// ---------------------------------------------------------------------------
// QueryStats struct field access
// ---------------------------------------------------------------------------

func TestQueryStats_FieldAccess(t *testing.T) {
	qs := QueryStats{
		Query:       "SELECT * FROM users",
		Calls:       100,
		TotalTimeMs: 250.5,
		MeanTimeMs:  2.505,
		Rows:        1000,
	}

	if qs.Query != "SELECT * FROM users" {
		t.Errorf("expected Query 'SELECT * FROM users', got %q", qs.Query)
	}
	if qs.Calls != 100 {
		t.Errorf("expected Calls 100, got %d", qs.Calls)
	}
	if qs.TotalTimeMs != 250.5 {
		t.Errorf("expected TotalTimeMs 250.5, got %f", qs.TotalTimeMs)
	}
	if qs.MeanTimeMs != 2.505 {
		t.Errorf("expected MeanTimeMs 2.505, got %f", qs.MeanTimeMs)
	}
	if qs.Rows != 1000 {
		t.Errorf("expected Rows 1000, got %d", qs.Rows)
	}
}

// ---------------------------------------------------------------------------
// DailyUsage struct field access
// ---------------------------------------------------------------------------

func TestDailyUsage_FieldAccess(t *testing.T) {
	du := DailyUsage{
		Day:    "2026-03-02",
		Action: "rest.select",
		Count:  500,
	}

	if du.Day != "2026-03-02" {
		t.Errorf("expected Day '2026-03-02', got %q", du.Day)
	}
	if du.Action != "rest.select" {
		t.Errorf("expected Action 'rest.select', got %q", du.Action)
	}
	if du.Count != 500 {
		t.Errorf("expected Count 500, got %d", du.Count)
	}
}

// ---------------------------------------------------------------------------
// APIUsageAnalytics type
// ---------------------------------------------------------------------------

func TestAPIUsageAnalytics_InitializedSlice(t *testing.T) {
	api := APIUsageAnalytics{
		DailyUsage: []DailyUsage{},
	}
	if api.DailyUsage == nil {
		t.Fatal("DailyUsage should not be nil when initialized")
	}
	if len(api.DailyUsage) != 0 {
		t.Errorf("expected empty DailyUsage, got length %d", len(api.DailyUsage))
	}
}
