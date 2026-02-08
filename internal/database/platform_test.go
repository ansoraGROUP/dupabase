package database

import (
	"testing"
)

// ---------------------------------------------------------------------------
// Migration type
// ---------------------------------------------------------------------------

func TestMigration_Fields(t *testing.T) {
	m := Migration{
		Name: "001_test.sql",
		SQL:  "CREATE TABLE test (id INT);",
	}

	if m.Name != "001_test.sql" {
		t.Errorf("expected name '001_test.sql', got %q", m.Name)
	}
	if m.SQL != "CREATE TABLE test (id INT);" {
		t.Errorf("unexpected SQL")
	}
}

func TestMigration_EmptySQL(t *testing.T) {
	m := Migration{
		Name: "empty.sql",
		SQL:  "",
	}

	if m.SQL != "" {
		t.Error("expected empty SQL")
	}
}

// ---------------------------------------------------------------------------
// Note: NewPlatformPool and RunMigrations require a real PostgreSQL connection.
// The following tests document what should be tested in integration tests.
// ---------------------------------------------------------------------------

func TestNewPlatformPool_Documentation(t *testing.T) {
	t.Skip("requires database connection -- integration test")
	// Would test:
	// - Valid connection URL creates a pool
	// - Pool can be pinged
	// - Invalid URL returns error
	// - Unreachable host returns error
}

func TestRunMigrations_Documentation(t *testing.T) {
	t.Skip("requires database connection -- integration test")
	// Would test:
	// - Migrations table is created
	// - Migrations are executed in order
	// - Already-executed migrations are skipped
	// - Failed migration returns error
}
