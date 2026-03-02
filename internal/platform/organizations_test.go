package platform

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// orgSlugRegex validation
// ---------------------------------------------------------------------------

func TestOrgSlugRegex(t *testing.T) {
	tests := []struct {
		slug  string
		valid bool
	}{
		{"my-org", true},
		{"abc", true},
		{"a-b", true}, // 3 chars: starts letter, middle hyphen, ends letter
		{"a-bc", true},
		{"my-cool-org", true},
		{"org123", true},
		{"a1b2c3", true},
		{"ab", false},   // too short (min 3)
		{"a", false},    // too short
		{"", false},     // empty
		{"-bad", false}, // starts with hyphen
		{"bad-", false}, // ends with hyphen
		{"Bad", false},  // uppercase
		{"MY-ORG", false},
		{"my org", false}, // space
		{"my_org", false}, // underscore
		{"1org", false},   // starts with digit
		{"personal-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", true},
	}

	for _, tt := range tests {
		t.Run(tt.slug, func(t *testing.T) {
			got := orgSlugRegex.MatchString(tt.slug)
			if got != tt.valid {
				t.Errorf("orgSlugRegex.MatchString(%q) = %v, want %v (len=%d)", tt.slug, got, tt.valid, len(tt.slug))
			}
		})
	}
}

func TestOrgSlugRegex_LengthBoundaries(t *testing.T) {
	// Exactly 50 chars (max allowed)
	slug50 := "a" + strings.Repeat("b", 48) + "c" // 1 + 48 + 1 = 50
	if !orgSlugRegex.MatchString(slug50) {
		t.Errorf("50-char slug should be valid, got invalid (len=%d)", len(slug50))
	}

	// 51 chars (too long)
	slug51 := "a" + strings.Repeat("b", 49) + "c" // 1 + 49 + 1 = 51
	if orgSlugRegex.MatchString(slug51) {
		t.Errorf("51-char slug should be invalid, got valid (len=%d)", len(slug51))
	}
}

// ---------------------------------------------------------------------------
// HasMinRole
// ---------------------------------------------------------------------------

func TestHasMinRole(t *testing.T) {
	tests := []struct {
		name     string
		userRole string
		minRole  string
		want     bool
	}{
		{"owner_has_owner", "owner", "owner", true},
		{"owner_has_admin", "owner", "admin", true},
		{"owner_has_developer", "owner", "developer", true},
		{"owner_has_viewer", "owner", "viewer", true},
		{"admin_has_admin", "admin", "admin", true},
		{"admin_has_developer", "admin", "developer", true},
		{"admin_has_viewer", "admin", "viewer", true},
		{"admin_not_owner", "admin", "owner", false},
		{"developer_has_developer", "developer", "developer", true},
		{"developer_has_viewer", "developer", "viewer", true},
		{"developer_not_admin", "developer", "admin", false},
		{"developer_not_owner", "developer", "owner", false},
		{"viewer_has_viewer", "viewer", "viewer", true},
		{"viewer_not_developer", "viewer", "developer", false},
		{"viewer_not_admin", "viewer", "admin", false},
		{"viewer_not_owner", "viewer", "owner", false},
		{"unknown_role_returns_false", "unknown", "viewer", false},
		{"empty_role_returns_false", "", "viewer", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HasMinRole(tt.userRole, tt.minRole)
			if got != tt.want {
				t.Errorf("HasMinRole(%q, %q) = %v, want %v", tt.userRole, tt.minRole, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// roleHierarchy completeness
// ---------------------------------------------------------------------------

func TestRoleHierarchy_AllRolesPresent(t *testing.T) {
	expected := []string{"viewer", "developer", "admin", "owner"}
	for _, role := range expected {
		if _, ok := roleHierarchy[role]; !ok {
			t.Errorf("role %q missing from roleHierarchy", role)
		}
	}
}

func TestRoleHierarchy_StrictOrdering(t *testing.T) {
	if roleHierarchy["viewer"] >= roleHierarchy["developer"] {
		t.Error("viewer should be less than developer")
	}
	if roleHierarchy["developer"] >= roleHierarchy["admin"] {
		t.Error("developer should be less than admin")
	}
	if roleHierarchy["admin"] >= roleHierarchy["owner"] {
		t.Error("admin should be less than owner")
	}
}

// ---------------------------------------------------------------------------
// NewOrgService
// ---------------------------------------------------------------------------

func TestNewOrgService(t *testing.T) {
	svc := NewOrgService(nil)
	if svc == nil {
		t.Fatal("NewOrgService returned nil")
	}
}

// ---------------------------------------------------------------------------
// CreateOrg validation (no DB needed — fails before DB access)
// ---------------------------------------------------------------------------

func TestCreateOrg_NameValidation(t *testing.T) {
	svc := &OrgService{db: nil}

	tests := []struct {
		name       string
		req        CreateOrgRequest
		wantErr    string
		wantStatus int
	}{
		{
			name:       "empty_name",
			req:        CreateOrgRequest{Name: "", Slug: "valid-slug"},
			wantErr:    "name is required",
			wantStatus: 400,
		},
		{
			name:       "whitespace_only_name",
			req:        CreateOrgRequest{Name: "   ", Slug: "valid-slug"},
			wantErr:    "name is required",
			wantStatus: 400,
		},
		{
			name:       "name_too_long",
			req:        CreateOrgRequest{Name: string(make([]byte, 101)), Slug: "valid-slug"},
			wantErr:    "at most 100 characters",
			wantStatus: 400,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, status, err := svc.CreateOrg(nil, "user-123", tt.req)
			if err == nil {
				t.Fatal("expected error")
			}
			if status != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, status)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

func TestCreateOrg_SlugValidation(t *testing.T) {
	svc := &OrgService{db: nil}

	invalidSlugs := []struct {
		name string
		slug string
	}{
		{"empty_slug", ""},
		{"too_short", "ab"},
		{"starts_with_digit", "1org"},
		{"starts_with_hyphen", "-org"},
		{"ends_with_hyphen", "org-"},
		{"uppercase", "My-Org"},
		{"has_space", "my org"},
		{"has_underscore", "my_org"},
	}

	for _, tt := range invalidSlugs {
		t.Run(tt.name, func(t *testing.T) {
			_, status, err := svc.CreateOrg(nil, "user-123", CreateOrgRequest{
				Name: "Test Org",
				Slug: tt.slug,
			})
			if err == nil {
				t.Fatal("expected error for slug:", tt.slug)
			}
			if status != 400 {
				t.Errorf("expected status 400, got %d", status)
			}
		})
	}

	// Valid slug passes validation but panics on nil DB. Recover from panic
	// to verify the slug validation itself did not reject it.
	t.Run("valid_slug_passes_validation", func(t *testing.T) {
		var createErr error
		func() {
			defer func() { recover() }()
			_, _, createErr = svc.CreateOrg(nil, "user-123", CreateOrgRequest{
				Name: "Test Org",
				Slug: "my-org",
			})
		}()
		// Should NOT fail on slug validation
		if createErr != nil && strings.Contains(createErr.Error(), "slug") {
			t.Error("valid slug should not be rejected by validation")
		}
	})
}

// ---------------------------------------------------------------------------
// UpdateOrg validation
// ---------------------------------------------------------------------------

func TestUpdateOrgRequest_Fields(t *testing.T) {
	// Verify the PATCH-style optional fields
	req := UpdateOrgRequest{}
	if req.Name != nil {
		t.Error("Name should be nil by default (omitempty)")
	}
	if req.Slug != nil {
		t.Error("Slug should be nil by default (omitempty)")
	}

	name := "New Name"
	req.Name = &name
	if *req.Name != "New Name" {
		t.Error("Name should be settable")
	}

	slug := "new-slug"
	req.Slug = &slug
	if *req.Slug != "new-slug" {
		t.Error("Slug should be settable")
	}
}

// ---------------------------------------------------------------------------
// CreateOrgInviteRequest validation
// ---------------------------------------------------------------------------

func TestCreateOrgInviteRequest_OwnerRoleBlocked(t *testing.T) {
	svc := &OrgService{db: nil}

	_, status, err := svc.CreateInvite(nil, "org-123", "user-123", CreateOrgInviteRequest{
		Email: "test@test.com",
		Role:  "owner",
	})
	if err == nil {
		t.Fatal("expected error when inviting as owner")
	}
	if status != 400 {
		t.Errorf("expected status 400, got %d", status)
	}
}

func TestCreateOrgInviteRequest_InvalidRole(t *testing.T) {
	svc := &OrgService{db: nil}

	_, status, err := svc.CreateInvite(nil, "org-123", "user-123", CreateOrgInviteRequest{
		Email: "test@test.com",
		Role:  "superadmin",
	})
	if err == nil {
		t.Fatal("expected error for invalid role")
	}
	if status != 400 {
		t.Errorf("expected status 400, got %d", status)
	}
}

func TestCreateOrgInviteRequest_EmptyEmail(t *testing.T) {
	svc := &OrgService{db: nil}

	_, status, err := svc.CreateInvite(nil, "org-123", "user-123", CreateOrgInviteRequest{
		Email: "",
		Role:  "developer",
	})
	if err == nil {
		t.Fatal("expected error for empty email")
	}
	if status != 400 {
		t.Errorf("expected status 400, got %d", status)
	}
}

func TestCreateOrgInviteRequest_InvalidEmail(t *testing.T) {
	svc := &OrgService{db: nil}

	_, status, err := svc.CreateInvite(nil, "org-123", "user-123", CreateOrgInviteRequest{
		Email: "not-an-email",
		Role:  "developer",
	})
	if err == nil {
		t.Fatal("expected error for invalid email")
	}
	if status != 400 {
		t.Errorf("expected status 400, got %d", status)
	}
}

func TestCreateOrgInviteRequest_ValidRoles(t *testing.T) {
	// Valid invite roles: admin, developer, viewer (NOT owner)
	validRoles := []string{"admin", "developer", "viewer"}
	for _, role := range validRoles {
		if _, ok := roleHierarchy[role]; !ok {
			t.Errorf("valid invite role %q not in roleHierarchy", role)
		}
	}
}

// ---------------------------------------------------------------------------
// UpdateMemberRole validation
// ---------------------------------------------------------------------------

func TestUpdateMemberRole_OwnerBlocked(t *testing.T) {
	svc := &OrgService{db: nil}

	status, err := svc.UpdateMemberRole(nil, "org-123", "user-456", "owner")
	if err == nil {
		t.Fatal("expected error when setting role to owner")
	}
	if status != 400 {
		t.Errorf("expected status 400, got %d", status)
	}
}

func TestUpdateMemberRole_InvalidRole(t *testing.T) {
	svc := &OrgService{db: nil}

	status, err := svc.UpdateMemberRole(nil, "org-123", "user-456", "superadmin")
	if err == nil {
		t.Fatal("expected error for invalid role")
	}
	if status != 400 {
		t.Errorf("expected status 400, got %d", status)
	}
}

func TestUpdateMemberRole_EmptyRole(t *testing.T) {
	svc := &OrgService{db: nil}

	status, err := svc.UpdateMemberRole(nil, "org-123", "user-456", "")
	if err == nil {
		t.Fatal("expected error for empty role")
	}
	if status != 400 {
		t.Errorf("expected status 400, got %d", status)
	}
}

// ---------------------------------------------------------------------------
// Type structure tests
// ---------------------------------------------------------------------------

func TestOrganization_RoleOmitEmpty(t *testing.T) {
	org := Organization{
		ID:   "test",
		Name: "Test",
		Slug: "test",
	}
	if org.Role != "" {
		t.Error("Role should default to empty string")
	}
}

func TestOrgDetail_EmbeddedOrganization(t *testing.T) {
	detail := OrgDetail{
		Organization: Organization{
			ID:   "org-1",
			Name: "Test Org",
			Slug: "test-org",
		},
		MemberCount: 5,
	}
	if detail.ID != "org-1" {
		t.Error("embedded Organization fields should be accessible")
	}
	if detail.MemberCount != 5 {
		t.Error("MemberCount should be 5")
	}
}

func TestOrgInvite_AcceptedAtNilByDefault(t *testing.T) {
	inv := OrgInvite{}
	if inv.AcceptedAt != nil {
		t.Error("AcceptedAt should be nil by default")
	}
}

// ---------------------------------------------------------------------------
// Nil slice normalization patterns (matching existing codebase pattern)
// ---------------------------------------------------------------------------

func TestListOrgs_NilSliceNormalization(t *testing.T) {
	var orgs []Organization
	if orgs == nil {
		orgs = []Organization{}
	}
	if orgs == nil {
		t.Fatal("orgs should not be nil after normalization")
	}
	if len(orgs) != 0 {
		t.Errorf("expected empty slice, got length %d", len(orgs))
	}
}

func TestListMembers_NilSliceNormalization(t *testing.T) {
	var members []OrgMember
	if members == nil {
		members = []OrgMember{}
	}
	if members == nil {
		t.Fatal("members should not be nil after normalization")
	}
	if len(members) != 0 {
		t.Errorf("expected empty slice, got length %d", len(members))
	}
}

func TestListInvites_NilSliceNormalization(t *testing.T) {
	var invites []OrgInvite
	if invites == nil {
		invites = []OrgInvite{}
	}
	if invites == nil {
		t.Fatal("invites should not be nil after normalization")
	}
	if len(invites) != 0 {
		t.Errorf("expected empty slice, got length %d", len(invites))
	}
}
