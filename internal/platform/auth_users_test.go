package platform

import (
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// NewAuthUserService constructor
// ---------------------------------------------------------------------------

func TestNewAuthUserService_ReturnsNonNil(t *testing.T) {
	svc := NewAuthUserService(nil, nil)
	if svc == nil {
		t.Fatal("NewAuthUserService returned nil")
	}
}

func TestNewAuthUserService_Fields(t *testing.T) {
	svc := NewAuthUserService(nil, nil)
	if svc.db != nil {
		t.Error("expected nil db")
	}
	if svc.poolManager != nil {
		t.Error("expected nil poolManager")
	}
}

// ---------------------------------------------------------------------------
// AuthUserInfo type
// ---------------------------------------------------------------------------

func TestAuthUserInfo_ZeroValue(t *testing.T) {
	var u AuthUserInfo
	if u.ID != "" {
		t.Errorf("expected empty ID, got %q", u.ID)
	}
	if u.Email != nil {
		t.Error("expected nil Email")
	}
	if u.Phone != nil {
		t.Error("expected nil Phone")
	}
	if u.EmailConfirmedAt != nil {
		t.Error("expected nil EmailConfirmedAt")
	}
	if u.PhoneConfirmedAt != nil {
		t.Error("expected nil PhoneConfirmedAt")
	}
	if u.LastSignInAt != nil {
		t.Error("expected nil LastSignInAt")
	}
	if u.IsAnonymous {
		t.Error("expected IsAnonymous false")
	}
	if u.BannedUntil != nil {
		t.Error("expected nil BannedUntil")
	}
	if !u.CreatedAt.IsZero() {
		t.Errorf("expected zero CreatedAt, got %v", u.CreatedAt)
	}
	if !u.UpdatedAt.IsZero() {
		t.Errorf("expected zero UpdatedAt, got %v", u.UpdatedAt)
	}
}

func TestAuthUserInfo_Populated(t *testing.T) {
	now := time.Now()
	email := "user@example.com"
	phone := "+1234567890"
	u := AuthUserInfo{
		ID:               "user-123",
		Email:            &email,
		Phone:            &phone,
		EmailConfirmedAt: &now,
		LastSignInAt:     &now,
		IsAnonymous:      false,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	if u.ID != "user-123" {
		t.Errorf("expected ID 'user-123', got %q", u.ID)
	}
	if *u.Email != "user@example.com" {
		t.Errorf("expected Email 'user@example.com', got %q", *u.Email)
	}
	if *u.Phone != "+1234567890" {
		t.Errorf("expected Phone '+1234567890', got %q", *u.Phone)
	}
	if u.EmailConfirmedAt == nil {
		t.Error("expected non-nil EmailConfirmedAt")
	}
}

// ---------------------------------------------------------------------------
// AuthUserDetail type
// ---------------------------------------------------------------------------

func TestAuthUserDetail_ZeroValue(t *testing.T) {
	var d AuthUserDetail
	if d.ID != "" {
		t.Errorf("expected empty ID (embedded), got %q", d.ID)
	}
	if d.AppMetadata != nil {
		t.Error("expected nil AppMetadata")
	}
	if d.UserMetadata != nil {
		t.Error("expected nil UserMetadata")
	}
	if d.Sessions != nil {
		t.Error("expected nil Sessions")
	}
}

func TestAuthUserDetail_EmbeddedAuthUserInfo(t *testing.T) {
	email := "test@test.com"
	d := AuthUserDetail{
		AuthUserInfo: AuthUserInfo{
			ID:    "user-456",
			Email: &email,
		},
		Sessions: []AuthSessionInfo{},
	}
	if d.ID != "user-456" {
		t.Errorf("expected ID 'user-456', got %q", d.ID)
	}
	if *d.Email != "test@test.com" {
		t.Errorf("expected Email 'test@test.com', got %q", *d.Email)
	}
	if d.Sessions == nil {
		t.Fatal("Sessions should not be nil when initialized")
	}
	if len(d.Sessions) != 0 {
		t.Errorf("expected empty Sessions, got length %d", len(d.Sessions))
	}
}

// ---------------------------------------------------------------------------
// AuthSessionInfo type
// ---------------------------------------------------------------------------

func TestAuthSessionInfo_ZeroValue(t *testing.T) {
	var s AuthSessionInfo
	if s.ID != "" {
		t.Errorf("expected empty ID, got %q", s.ID)
	}
	if !s.CreatedAt.IsZero() {
		t.Errorf("expected zero CreatedAt, got %v", s.CreatedAt)
	}
	if !s.UpdatedAt.IsZero() {
		t.Errorf("expected zero UpdatedAt, got %v", s.UpdatedAt)
	}
	if s.UserAgent != nil {
		t.Error("expected nil UserAgent")
	}
	if s.IP != nil {
		t.Error("expected nil IP")
	}
}

func TestAuthSessionInfo_Populated(t *testing.T) {
	now := time.Now()
	ua := "Mozilla/5.0"
	ip := "192.168.1.1"
	s := AuthSessionInfo{
		ID:        "sess-789",
		CreatedAt: now,
		UpdatedAt: now,
		UserAgent: &ua,
		IP:        &ip,
	}
	if s.ID != "sess-789" {
		t.Errorf("expected ID 'sess-789', got %q", s.ID)
	}
	if *s.UserAgent != "Mozilla/5.0" {
		t.Errorf("expected UserAgent 'Mozilla/5.0', got %q", *s.UserAgent)
	}
	if *s.IP != "192.168.1.1" {
		t.Errorf("expected IP '192.168.1.1', got %q", *s.IP)
	}
}

// ---------------------------------------------------------------------------
// AuthUserListResponse type
// ---------------------------------------------------------------------------

func TestAuthUserListResponse_ZeroValue(t *testing.T) {
	var resp AuthUserListResponse
	if resp.Users != nil {
		t.Error("expected nil Users")
	}
	if resp.Total != 0 {
		t.Errorf("expected Total 0, got %d", resp.Total)
	}
	if resp.Page != 0 {
		t.Errorf("expected Page 0, got %d", resp.Page)
	}
	if resp.PerPage != 0 {
		t.Errorf("expected PerPage 0, got %d", resp.PerPage)
	}
}

func TestAuthUserListResponse_Initialized(t *testing.T) {
	resp := AuthUserListResponse{
		Users:   []AuthUserInfo{},
		Total:   42,
		Page:    1,
		PerPage: 50,
	}
	if resp.Users == nil {
		t.Fatal("Users should not be nil when initialized")
	}
	if len(resp.Users) != 0 {
		t.Errorf("expected empty Users, got length %d", len(resp.Users))
	}
	if resp.Total != 42 {
		t.Errorf("expected Total 42, got %d", resp.Total)
	}
	if resp.Page != 1 {
		t.Errorf("expected Page 1, got %d", resp.Page)
	}
	if resp.PerPage != 50 {
		t.Errorf("expected PerPage 50, got %d", resp.PerPage)
	}
}

func TestAuthUserListResponse_WithUsers(t *testing.T) {
	email1 := "alice@test.com"
	email2 := "bob@test.com"
	resp := AuthUserListResponse{
		Users: []AuthUserInfo{
			{ID: "u1", Email: &email1},
			{ID: "u2", Email: &email2},
		},
		Total:   2,
		Page:    1,
		PerPage: 50,
	}
	if len(resp.Users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(resp.Users))
	}
	if resp.Users[0].ID != "u1" {
		t.Errorf("expected first user ID 'u1', got %q", resp.Users[0].ID)
	}
	if *resp.Users[1].Email != "bob@test.com" {
		t.Errorf("expected second user email 'bob@test.com', got %q", *resp.Users[1].Email)
	}
}
