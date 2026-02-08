package database

import (
	"encoding/json"
	"testing"
)

// ---------------------------------------------------------------------------
// JWTClaims type
// ---------------------------------------------------------------------------

func TestJWTClaims_IsMapStringInterface(t *testing.T) {
	claims := JWTClaims{
		"sub":   "user-123",
		"role":  "authenticated",
		"email": "user@test.com",
	}

	// Verify it can be used as map[string]interface{}
	m := map[string]interface{}(claims)
	if m["sub"] != "user-123" {
		t.Errorf("expected sub 'user-123', got %v", m["sub"])
	}
	if m["role"] != "authenticated" {
		t.Errorf("expected role 'authenticated', got %v", m["role"])
	}
}

func TestJWTClaims_MarshalJSON(t *testing.T) {
	claims := JWTClaims{
		"sub":   "user-123",
		"role":  "authenticated",
		"email": "user@test.com",
	}

	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if parsed["sub"] != "user-123" {
		t.Errorf("expected sub 'user-123', got %v", parsed["sub"])
	}
}

func TestJWTClaims_EmptyClaims(t *testing.T) {
	claims := JWTClaims{}

	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	if string(data) != "{}" {
		t.Errorf("expected '{}', got %q", string(data))
	}
}

func TestJWTClaims_NestedValues(t *testing.T) {
	claims := JWTClaims{
		"sub":           "user-123",
		"app_metadata":  map[string]interface{}{"provider": "email"},
		"user_metadata": map[string]interface{}{"name": "Alice"},
	}

	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}

	var parsed map[string]interface{}
	json.Unmarshal(data, &parsed)

	appMeta, ok := parsed["app_metadata"].(map[string]interface{})
	if !ok {
		t.Fatal("expected app_metadata to be a map")
	}
	if appMeta["provider"] != "email" {
		t.Errorf("expected provider 'email', got %v", appMeta["provider"])
	}
}

// ---------------------------------------------------------------------------
// Note: ExecuteWithRLS requires a real pgxpool.Pool and a live database
// connection to test properly. The following tests document what would be
// tested with integration tests.
// ---------------------------------------------------------------------------

// TestExecuteWithRLS_ServiceRoleBypassesRLS documents that when role is
// "service_role", the function should NOT call SET LOCAL ROLE.
// This requires a database integration test.
func TestExecuteWithRLS_ServiceRoleBypassesRLS_Documentation(t *testing.T) {
	t.Skip("requires database connection -- integration test")
}

// TestExecuteWithRLS_AnonSetsRole documents that when role is "anon",
// the function should call SET LOCAL ROLE "anon" and set JWT claims.
func TestExecuteWithRLS_AnonSetsRole_Documentation(t *testing.T) {
	t.Skip("requires database connection -- integration test")
}

// TestExecuteWithRLS_AuthenticatedSetsClaimsAndRole documents the
// authenticated role path.
func TestExecuteWithRLS_AuthenticatedSetsClaimsAndRole_Documentation(t *testing.T) {
	t.Skip("requires database connection -- integration test")
}

// TestExecuteWithRLS_CommitsOnSuccess documents that a successful
// callback results in a committed transaction.
func TestExecuteWithRLS_CommitsOnSuccess_Documentation(t *testing.T) {
	t.Skip("requires database connection -- integration test")
}

// TestExecuteWithRLS_RollsBackOnError documents that an error in the
// callback results in a rolled back transaction.
func TestExecuteWithRLS_RollsBackOnError_Documentation(t *testing.T) {
	t.Skip("requires database connection -- integration test")
}
