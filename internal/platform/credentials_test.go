package platform

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// NewCredentialService (URL parsing)
// ---------------------------------------------------------------------------

func TestNewCredentialService_ParsesURL(t *testing.T) {
	tests := []struct {
		name        string
		databaseURL string
		wantBase    string
	}{
		{
			name:        "standard_postgres_url",
			databaseURL: "postgresql://user:pass@localhost:5432/mydb",
			wantBase:    "localhost:5432",
		},
		{
			name:        "custom_port",
			databaseURL: "postgresql://user:pass@db.example.com:6543/mydb",
			wantBase:    "db.example.com:6543",
		},
		{
			name:        "ipv4_host",
			databaseURL: "postgresql://user:pass@192.168.1.100:5432/mydb",
			wantBase:    "192.168.1.100:5432",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := NewCredentialService(nil, tt.databaseURL)
			if svc.baseURL != tt.wantBase {
				t.Errorf("baseURL: got %q, want %q", svc.baseURL, tt.wantBase)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// RevealCredentials validation (no DB needed for input validation)
// ---------------------------------------------------------------------------

func TestRevealCredentials_EmptyPassword(t *testing.T) {
	svc := &CredentialService{
		db:      nil,
		baseURL: "localhost:5432",
	}

	_, status, err := svc.RevealCredentials(nil, "user-123", RevealRequest{PlatformPassword: ""})
	if err == nil {
		t.Fatal("expected error for empty platform_password")
	}
	if status != 400 {
		t.Errorf("expected status 400, got %d", status)
	}
	if !strings.Contains(err.Error(), "platform_password is required") {
		t.Errorf("expected 'platform_password is required', got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// CredentialResponse struct
// ---------------------------------------------------------------------------

func TestCredentialResponse_Fields(t *testing.T) {
	resp := CredentialResponse{
		PgUsername: "u_abc123",
		PgPassword: "secret",
		PgHost:     "localhost",
		PgPort:     "5432",
	}

	if resp.PgUsername != "u_abc123" {
		t.Error("unexpected PgUsername")
	}
	if resp.PgPassword != "secret" {
		t.Error("unexpected PgPassword")
	}
	if resp.PgHost != "localhost" {
		t.Error("unexpected PgHost")
	}
	if resp.PgPort != "5432" {
		t.Error("unexpected PgPort")
	}
}
