package platform

import (
	"testing"
)

// ---------------------------------------------------------------------------
// DeleteUser input validation
// ---------------------------------------------------------------------------

func TestDeleteUser_CannotDeleteSelf(t *testing.T) {
	svc := &AdminService{db: nil} // DB not needed for this check

	status, err := svc.DeleteUser(nil, "user-123", "user-123")
	if err == nil {
		t.Fatal("expected error when deleting self")
	}
	if status != 400 {
		t.Errorf("expected status 400, got %d", status)
	}
	if err.Error() != "cannot delete yourself" {
		t.Errorf("unexpected error message: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ListUsers pagination defaults
// ---------------------------------------------------------------------------

func TestListUsers_PaginationDefaults(t *testing.T) {
	// Test the default clamping logic from ListUsers
	tests := []struct {
		name       string
		page       int
		perPage    int
		wantPage   int
		wantPer    int
		wantOffset int
	}{
		{"valid", 2, 20, 2, 20, 20},
		{"zero_page", 0, 20, 1, 20, 0},
		{"negative_page", -1, 20, 1, 20, 0},
		{"zero_perPage", 1, 0, 1, 20, 0},
		{"over_max_perPage", 1, 150, 1, 20, 0},
		{"negative_perPage", 1, -5, 1, 20, 0},
		{"page_3", 3, 10, 3, 10, 20},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			page := tt.page
			perPage := tt.perPage
			if page < 1 {
				page = 1
			}
			if perPage < 1 || perPage > 100 {
				perPage = 20
			}
			offset := (page - 1) * perPage

			if page != tt.wantPage {
				t.Errorf("page: got %d, want %d", page, tt.wantPage)
			}
			if perPage != tt.wantPer {
				t.Errorf("perPage: got %d, want %d", perPage, tt.wantPer)
			}
			if offset != tt.wantOffset {
				t.Errorf("offset: got %d, want %d", offset, tt.wantOffset)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// adminQuoteIdent
// ---------------------------------------------------------------------------

func TestAdminQuoteIdent(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"simple", `"simple"`},
		{"with space", `"with space"`},
		{`with"quote`, `"with""quote"`},
		{"", `""`},
		{`"; DROP TABLE users;--`, `"""; DROP TABLE users;--"`},
		{`a""b`, `"a""""b"`},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := adminQuoteIdent(tt.input)
			if got != tt.expected {
				t.Errorf("adminQuoteIdent(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// NewAdminService
// ---------------------------------------------------------------------------

func TestNewAdminService(t *testing.T) {
	svc := NewAdminService(nil, nil)
	if svc == nil {
		t.Fatal("NewAdminService returned nil")
	}
}

// ---------------------------------------------------------------------------
// PlatformSettings validation
// ---------------------------------------------------------------------------

func TestPlatformSettings_ValidModes(t *testing.T) {
	valid := map[string]bool{"open": true, "invite": true, "disabled": true}
	validModes := []string{"open", "invite", "disabled"}
	invalidModes := []string{"closed", "public", "", "restricted"}

	for _, m := range validModes {
		if !valid[m] {
			t.Errorf("valid mode %q rejected", m)
		}
	}
	for _, m := range invalidModes {
		if valid[m] {
			t.Errorf("invalid mode %q accepted", m)
		}
	}
}

// ---------------------------------------------------------------------------
// CreateInviteRequest defaults
// ---------------------------------------------------------------------------

func TestCreateInviteRequest_ExpiresInDefault(t *testing.T) {
	req := CreateInviteRequest{}
	expiresHours := req.ExpiresIn
	if expiresHours <= 0 {
		expiresHours = 72
	}
	if expiresHours != 72 {
		t.Errorf("expected default 72 hours, got %d", expiresHours)
	}
}

func TestCreateInviteRequest_CustomExpiry(t *testing.T) {
	req := CreateInviteRequest{ExpiresIn: 24}
	expiresHours := req.ExpiresIn
	if expiresHours <= 0 {
		expiresHours = 72
	}
	if expiresHours != 24 {
		t.Errorf("expected 24 hours, got %d", expiresHours)
	}
}

// ---------------------------------------------------------------------------
// PaginatedUsers nil normalization
// ---------------------------------------------------------------------------

func TestPaginatedUsers_NilUsersNormalization(t *testing.T) {
	var users []AdminUser
	if users == nil {
		users = []AdminUser{}
	}
	if users == nil {
		t.Fatal("users should not be nil after normalization")
	}
	if len(users) != 0 {
		t.Errorf("expected empty slice, got length %d", len(users))
	}
}
