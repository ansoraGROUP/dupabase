package platform

import (
	"testing"
)

// ---------------------------------------------------------------------------
// NewSQLService constructor
// ---------------------------------------------------------------------------

func TestNewSQLService_ReturnsNonNil(t *testing.T) {
	svc := NewSQLService(nil, nil)
	if svc == nil {
		t.Fatal("NewSQLService returned nil")
	}
}

func TestNewSQLService_Fields(t *testing.T) {
	svc := NewSQLService(nil, nil)
	if svc.db != nil {
		t.Error("expected nil db")
	}
	if svc.poolManager != nil {
		t.Error("expected nil poolManager")
	}
}

// ---------------------------------------------------------------------------
// SQLRequest struct
// ---------------------------------------------------------------------------

func TestSQLRequest_Fields(t *testing.T) {
	req := SQLRequest{
		Query:    "SELECT 1",
		ReadOnly: true,
	}
	if req.Query != "SELECT 1" {
		t.Errorf("expected Query 'SELECT 1', got %q", req.Query)
	}
	if !req.ReadOnly {
		t.Error("expected ReadOnly true")
	}
}

func TestSQLRequest_ZeroValue(t *testing.T) {
	var req SQLRequest
	if req.Query != "" {
		t.Errorf("expected empty Query, got %q", req.Query)
	}
	if req.ReadOnly {
		t.Error("expected ReadOnly false by default")
	}
}

// ---------------------------------------------------------------------------
// SQLResponse zero value
// ---------------------------------------------------------------------------

func TestSQLResponse_ZeroValue(t *testing.T) {
	var resp SQLResponse
	if resp.Columns != nil {
		t.Error("expected nil Columns")
	}
	if resp.Rows != nil {
		t.Error("expected nil Rows")
	}
	if resp.RowCount != 0 {
		t.Errorf("expected RowCount 0, got %d", resp.RowCount)
	}
	if resp.ExecutionTime != 0 {
		t.Errorf("expected ExecutionTime 0, got %f", resp.ExecutionTime)
	}
}

func TestSQLResponse_InitializedSlices(t *testing.T) {
	resp := SQLResponse{
		Columns:  []string{},
		Rows:     [][]interface{}{},
		RowCount: 0,
	}
	if resp.Columns == nil {
		t.Fatal("Columns should not be nil when initialized")
	}
	if resp.Rows == nil {
		t.Fatal("Rows should not be nil when initialized")
	}
	if len(resp.Columns) != 0 {
		t.Errorf("expected empty Columns, got length %d", len(resp.Columns))
	}
	if len(resp.Rows) != 0 {
		t.Errorf("expected empty Rows, got length %d", len(resp.Rows))
	}
}

func TestSQLResponse_WithData(t *testing.T) {
	resp := SQLResponse{
		Columns:       []string{"id", "name"},
		Rows:          [][]interface{}{{1, "Alice"}, {2, "Bob"}},
		RowCount:      2,
		ExecutionTime: 1.5,
	}
	if len(resp.Columns) != 2 {
		t.Errorf("expected 2 columns, got %d", len(resp.Columns))
	}
	if resp.Columns[0] != "id" {
		t.Errorf("expected first column 'id', got %q", resp.Columns[0])
	}
	if resp.RowCount != 2 {
		t.Errorf("expected RowCount 2, got %d", resp.RowCount)
	}
	if resp.ExecutionTime != 1.5 {
		t.Errorf("expected ExecutionTime 1.5, got %f", resp.ExecutionTime)
	}
}
