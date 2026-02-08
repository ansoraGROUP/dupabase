package platform

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ---------------------------------------------------------------------------
// ValidateToken (pure unit tests -- no database needed)
// ---------------------------------------------------------------------------

func newTestAuthService(secret string, expiry int) *AuthService {
	return &AuthService{
		db:            nil, // not needed for token validation
		jwtSecret:     []byte(secret),
		jwtExpiry:     time.Duration(expiry) * time.Second,
		loginAttempts: make(map[string]*loginAttempt),
	}
}

func TestValidateToken_ValidPlatformToken(t *testing.T) {
	secret := "test-secret-that-is-long-enough-32chars"
	svc := newTestAuthService(secret, 3600)

	token, err := svc.generateToken("user-123", "user@example.com")
	if err != nil {
		t.Fatalf("generateToken failed: %v", err)
	}

	claims, err := svc.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}

	if claims.Subject != "user-123" {
		t.Errorf("expected subject 'user-123', got %q", claims.Subject)
	}
	if claims.Email != "user@example.com" {
		t.Errorf("expected email 'user@example.com', got %q", claims.Email)
	}
	if claims.Type != "platform" {
		t.Errorf("expected type 'platform', got %q", claims.Type)
	}
	if claims.Issuer != "dupabase" {
		t.Errorf("expected issuer 'dupabase', got %q", claims.Issuer)
	}
}

func TestValidateToken_ExpiredToken(t *testing.T) {
	secret := "test-secret-that-is-long-enough-32chars"
	// Create a service with a negative expiry so the token is already expired
	svc := &AuthService{
		jwtSecret:     []byte(secret),
		jwtExpiry:     -1 * time.Hour,
		loginAttempts: make(map[string]*loginAttempt),
	}

	token, err := svc.generateToken("user-123", "user@example.com")
	if err != nil {
		t.Fatalf("generateToken failed: %v", err)
	}

	_, err = svc.ValidateToken(token)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestValidateToken_WrongSecret(t *testing.T) {
	svc1 := newTestAuthService("secret-one-that-is-long-enough-32", 3600)
	svc2 := newTestAuthService("secret-two-that-is-long-enough-32", 3600)

	token, err := svc1.generateToken("user-123", "user@example.com")
	if err != nil {
		t.Fatal(err)
	}

	_, err = svc2.ValidateToken(token)
	if err == nil {
		t.Fatal("expected error when validating token with wrong secret")
	}
}

func TestValidateToken_MalformedToken(t *testing.T) {
	svc := newTestAuthService("test-secret-that-is-long-enough-32chars", 3600)

	tests := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"garbage", "not-a-jwt-at-all"},
		{"partial", "eyJhbGciOiJIUzI1NiJ9."},
		{"three_dots", "a.b.c"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.ValidateToken(tt.token)
			if err == nil {
				t.Fatal("expected error for malformed token")
			}
		})
	}
}

func TestValidateToken_NonHMACSigningMethod(t *testing.T) {
	// Create a token signed with "none" algorithm
	claims := PlatformClaims{
		Email: "user@example.com",
		Type:  "platform",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-123",
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	tokenStr, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("failed to create none-signed token: %v", err)
	}

	svc := newTestAuthService("test-secret-that-is-long-enough-32chars", 3600)
	_, err = svc.ValidateToken(tokenStr)
	if err == nil {
		t.Fatal("expected error for none signing method")
	}
	if !strings.Contains(err.Error(), "signing method") {
		t.Fatalf("expected 'signing method' in error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// generateToken (internal)
// ---------------------------------------------------------------------------

func TestGenerateToken_ContainsExpectedClaims(t *testing.T) {
	secret := "test-secret-that-is-long-enough-32chars"
	svc := newTestAuthService(secret, 7200)

	before := time.Now().Add(-time.Second) // JWT iat has second-level precision
	tokenStr, err := svc.generateToken("uid-abc", "test@test.com")
	if err != nil {
		t.Fatal(err)
	}
	after := time.Now().Add(time.Second)

	// Parse the token to inspect claims
	parsed, err := jwt.ParseWithClaims(tokenStr, &PlatformClaims{}, func(t *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	claims := parsed.Claims.(*PlatformClaims)

	if claims.Subject != "uid-abc" {
		t.Errorf("subject: got %q, want %q", claims.Subject, "uid-abc")
	}
	if claims.Email != "test@test.com" {
		t.Errorf("email: got %q, want %q", claims.Email, "test@test.com")
	}
	if claims.Type != "platform" {
		t.Errorf("type: got %q, want %q", claims.Type, "platform")
	}
	if claims.Issuer != "dupabase" {
		t.Errorf("issuer: got %q, want %q", claims.Issuer, "dupabase")
	}

	// Check IssuedAt is in the right range
	iat := claims.IssuedAt.Time
	if iat.Before(before) || iat.After(after) {
		t.Errorf("issued_at %v not in expected range [%v, %v]", iat, before, after)
	}

	// Check ExpiresAt is roughly 7200 seconds after IssuedAt
	expectedExpiry := iat.Add(7200 * time.Second)
	exp := claims.ExpiresAt.Time
	diff := exp.Sub(expectedExpiry)
	if diff < -time.Second || diff > time.Second {
		t.Errorf("expiry %v not close to expected %v (diff=%v)", exp, expectedExpiry, diff)
	}
}

// ---------------------------------------------------------------------------
// Register validation (unit test -- no DB calls, just input validation)
// These tests verify the validation logic runs before any DB query.
// Since Register uses s.db, it will panic/fail if we reach DB code.
// We test that empty email / password returns an appropriate error.
// ---------------------------------------------------------------------------

func TestRegister_ValidationErrors(t *testing.T) {
	svc := &AuthService{
		db:            nil, // will fail if DB is accessed
		jwtSecret:     []byte("test-secret-that-is-long-enough-32chars"),
		jwtExpiry:     time.Hour,
		loginAttempts: make(map[string]*loginAttempt),
	}

	tests := []struct {
		name    string
		req     RegisterRequest
		wantErr string
	}{
		{
			name:    "empty_email",
			req:     RegisterRequest{Email: "", Password: "password123"},
			wantErr: "email and password are required",
		},
		{
			name:    "empty_password",
			req:     RegisterRequest{Email: "test@test.com", Password: ""},
			wantErr: "email and password are required",
		},
		{
			name:    "both_empty",
			req:     RegisterRequest{Email: "", Password: ""},
			wantErr: "email and password are required",
		},
		{
			name:    "short_password",
			req:     RegisterRequest{Email: "test@test.com", Password: "1234567"},
			wantErr: "password must be at least 8 characters",
		},
		{
			name:    "whitespace_only_email",
			req:     RegisterRequest{Email: "   ", Password: "password123"},
			wantErr: "email and password are required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, status, err := svc.Register(nil, tt.req)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
			}
			if status != 400 {
				t.Errorf("expected status 400, got %d", status)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// PlatformClaims type checks
// ---------------------------------------------------------------------------

func TestPlatformClaims_ImplementsClaims(t *testing.T) {
	// Verify PlatformClaims satisfies jwt.Claims interface
	var _ jwt.Claims = &PlatformClaims{}
}
