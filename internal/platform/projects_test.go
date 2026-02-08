package platform

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ansoraGROUP/dupabase/internal/database"
)

// ---------------------------------------------------------------------------
// generateProjectAPIKey (exported indirectly through CreateProject, but
// the internal function is testable directly within the package)
// ---------------------------------------------------------------------------

func TestGenerateProjectAPIKey_Anon(t *testing.T) {
	secret := "test-jwt-secret-for-project-keys-long-enough"
	projectID := "proj-abc-123"

	tokenStr, err := generateProjectAPIKey(secret, projectID, "anon")
	if err != nil {
		t.Fatalf("generateProjectAPIKey failed: %v", err)
	}

	// Parse and verify
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(secret), nil
	})
	if err != nil {
		t.Fatalf("parse token failed: %v", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("expected MapClaims")
	}

	if role, _ := claims["role"].(string); role != "anon" {
		t.Errorf("expected role 'anon', got %q", role)
	}
	if pid, _ := claims["project_id"].(string); pid != projectID {
		t.Errorf("expected project_id %q, got %q", projectID, pid)
	}
	if iss, _ := claims["iss"].(string); iss != "supabase" {
		t.Errorf("expected issuer 'supabase', got %q", iss)
	}

	// Check expiry is roughly 1 year from now
	exp, err := claims.GetExpirationTime()
	if err != nil {
		t.Fatal(err)
	}
	expectedExp := time.Now().Add(365 * 24 * time.Hour)
	diff := exp.Time.Sub(expectedExp)
	if diff < -time.Minute || diff > time.Minute {
		t.Errorf("expiry not within 1 minute of expected 1-year expiry")
	}
}

func TestGenerateProjectAPIKey_ServiceRole(t *testing.T) {
	secret := "test-jwt-secret-for-project-keys-long-enough"
	projectID := "proj-xyz-789"

	tokenStr, err := generateProjectAPIKey(secret, projectID, "service_role")
	if err != nil {
		t.Fatalf("generateProjectAPIKey failed: %v", err)
	}

	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil {
		t.Fatal(err)
	}

	claims := token.Claims.(jwt.MapClaims)
	if role, _ := claims["role"].(string); role != "service_role" {
		t.Errorf("expected role 'service_role', got %q", role)
	}
}

func TestGenerateProjectAPIKey_DifferentSecrets(t *testing.T) {
	secret1 := "secret-one-for-testing-long-enough-32chars"
	secret2 := "secret-two-for-testing-long-enough-32chars"

	token1, _ := generateProjectAPIKey(secret1, "proj-1", "anon")
	token2, _ := generateProjectAPIKey(secret2, "proj-1", "anon")

	if token1 == token2 {
		t.Fatal("tokens with different secrets should not be identical")
	}

	// token1 should NOT be parseable with secret2
	_, err := jwt.Parse(token1, func(t *jwt.Token) (interface{}, error) {
		return []byte(secret2), nil
	})
	if err == nil {
		t.Fatal("token should not be valid with wrong secret")
	}
}

// ---------------------------------------------------------------------------
// projectMigrations
// ---------------------------------------------------------------------------

func TestProjectMigrations_ReturnsOneMigration(t *testing.T) {
	migrations := projectMigrations()
	if len(migrations) != 1 {
		t.Fatalf("expected 1 migration, got %d", len(migrations))
	}
	if migrations[0].Name != "001_auth_schema.sql" {
		t.Errorf("expected migration name '001_auth_schema.sql', got %q", migrations[0].Name)
	}
	if migrations[0].SQL == "" {
		t.Error("migration SQL should not be empty")
	}
}

func TestProjectMigrations_SQLContainsAuthSchema(t *testing.T) {
	migrations := projectMigrations()
	sql := migrations[0].SQL

	expectedParts := []string{
		"CREATE SCHEMA IF NOT EXISTS auth",
		"CREATE TABLE IF NOT EXISTS auth.users",
		"CREATE TABLE IF NOT EXISTS auth.sessions",
		"CREATE TABLE IF NOT EXISTS auth.refresh_tokens",
		"CREATE TABLE IF NOT EXISTS auth.identities",
		"auth.uid()",
		"auth.role()",
		"auth.jwt()",
	}

	for _, part := range expectedParts {
		if !strings.Contains(sql, part) {
			t.Errorf("migration SQL missing expected string: %q", part)
		}
	}
}

// ---------------------------------------------------------------------------
// CreateProjectRequest validation (tests that the code validates name)
// ---------------------------------------------------------------------------

func TestCreateProject_EmptyName(t *testing.T) {
	svc := &ProjectService{
		platformDB:  nil,
		poolManager: nil,
		siteURL:     "http://localhost:3000",
	}

	_, status, err := svc.CreateProject(nil, "user-1", CreateProjectRequest{Name: ""})
	if err == nil {
		t.Fatal("expected error for empty project name")
	}
	if status != 400 {
		t.Errorf("expected status 400, got %d", status)
	}
	if !strings.Contains(err.Error(), "project name is required") {
		t.Errorf("expected 'project name is required', got: %v", err)
	}
}

func TestCreateProject_WhitespaceOnlyName(t *testing.T) {
	svc := &ProjectService{
		platformDB:  nil,
		poolManager: nil,
		siteURL:     "http://localhost:3000",
	}

	_, status, err := svc.CreateProject(nil, "user-1", CreateProjectRequest{Name: "   "})
	if err == nil {
		t.Fatal("expected error for whitespace-only project name")
	}
	if status != 400 {
		t.Errorf("expected status 400, got %d", status)
	}
}

// ---------------------------------------------------------------------------
// ProjectSettings default values
// ---------------------------------------------------------------------------

func TestCreateProjectRequest_Defaults(t *testing.T) {
	req := CreateProjectRequest{
		Name: "test-project",
	}

	// When nil, defaults should be: enableSignup=true, autoconfirm=true, passwordMinLength=6
	if req.EnableSignup != nil {
		t.Error("EnableSignup should default to nil")
	}
	if req.Autoconfirm != nil {
		t.Error("Autoconfirm should default to nil")
	}
	if req.PasswordMinLength != nil {
		t.Error("PasswordMinLength should default to nil")
	}
}

// ---------------------------------------------------------------------------
// Verify types implement expected structure
// ---------------------------------------------------------------------------

func TestProjectResponse_Fields(t *testing.T) {
	resp := ProjectResponse{
		ID:             "id",
		Name:           "name",
		DBName:         "dbname",
		Region:         "local",
		AnonKey:        "anonkey",
		ServiceRoleKey: "srkey",
		JWTSecret:      "secret",
		Status:         "active",
		APIURL:         "http://localhost",
		SiteURL:        "http://localhost",
		Settings: ProjectSettings{
			EnableSignup:      true,
			Autoconfirm:       true,
			PasswordMinLength: 6,
		},
		CreatedAt: time.Now(),
	}

	if resp.ID != "id" {
		t.Error("unexpected ID")
	}
	if !resp.Settings.EnableSignup {
		t.Error("expected EnableSignup true")
	}
}

func TestMigrationTypeMatchesDatabaseMigration(t *testing.T) {
	// Verify that projectMigrations returns database.Migration type
	migrations := projectMigrations()
	var _ []database.Migration = migrations
	if len(migrations) == 0 {
		t.Error("expected at least one migration")
	}
}
