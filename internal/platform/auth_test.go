package platform

import (
	"context"
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
		cleanupStop:   make(chan struct{}),
	}
}

func TestValidateToken_ValidPlatformToken(t *testing.T) {
	secret := "test-secret-that-is-long-enough-32chars"
	svc := newTestAuthService(secret, 3600)

	token, err := svc.generateToken(context.Background(), "user-123", "user@example.com")
	if err != nil {
		t.Fatalf("generateToken failed: %v", err)
	}

	claims, err := svc.ValidateToken(context.Background(), token)
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

	token, err := svc.generateToken(context.Background(), "user-123", "user@example.com")
	if err != nil {
		t.Fatalf("generateToken failed: %v", err)
	}

	_, err = svc.ValidateToken(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestValidateToken_WrongSecret(t *testing.T) {
	svc1 := newTestAuthService("secret-one-that-is-long-enough-32", 3600)
	svc2 := newTestAuthService("secret-two-that-is-long-enough-32", 3600)

	token, err := svc1.generateToken(context.Background(), "user-123", "user@example.com")
	if err != nil {
		t.Fatal(err)
	}

	_, err = svc2.ValidateToken(context.Background(), token)
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
			_, err := svc.ValidateToken(context.Background(), tt.token)
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
	_, err = svc.ValidateToken(context.Background(), tokenStr)
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
	tokenStr, err := svc.generateToken(context.Background(), "uid-abc", "test@test.com")
	if err != nil {
		t.Fatal(err)
	}
	after := time.Now().Add(time.Second)

	// Parse the token to inspect claims (generateToken now uses jwt.MapClaims)
	parsed, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("expected MapClaims")
	}

	if sub, _ := claims["sub"].(string); sub != "uid-abc" {
		t.Errorf("subject: got %q, want %q", sub, "uid-abc")
	}
	if email, _ := claims["email"].(string); email != "test@test.com" {
		t.Errorf("email: got %q, want %q", email, "test@test.com")
	}
	if typ, _ := claims["type"].(string); typ != "platform" {
		t.Errorf("type: got %q, want %q", typ, "platform")
	}
	if iss, _ := claims["iss"].(string); iss != "dupabase" {
		t.Errorf("issuer: got %q, want %q", iss, "dupabase")
	}

	// Check IssuedAt is in the right range
	iatFloat, _ := claims["iat"].(float64)
	iat := time.Unix(int64(iatFloat), 0)
	if iat.Before(before) || iat.After(after) {
		t.Errorf("issued_at %v not in expected range [%v, %v]", iat, before, after)
	}

	// Check ExpiresAt is roughly 7200 seconds after IssuedAt
	expectedExpiry := iat.Add(7200 * time.Second)
	expFloat, _ := claims["exp"].(float64)
	exp := time.Unix(int64(expFloat), 0)
	diff := exp.Sub(expectedExpiry)
	if diff < -time.Second || diff > time.Second {
		t.Errorf("expiry %v not close to expected %v (diff=%v)", exp, expectedExpiry, diff)
	}

	// Verify token_version claim is present (defaults to 0 when no DB)
	if tv, exists := claims["tv"]; !exists {
		t.Error("expected tv (token_version) claim to be present")
	} else if tvFloat, ok := tv.(float64); !ok || int(tvFloat) != 0 {
		t.Errorf("expected tv=0, got %v", tv)
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

// ---------------------------------------------------------------------------
// Register email validation
// ---------------------------------------------------------------------------

func TestRegister_EmailValidation(t *testing.T) {
	svc := &AuthService{
		db:            nil,
		jwtSecret:     []byte("test-secret-that-is-long-enough-32chars"),
		jwtExpiry:     time.Hour,
		loginAttempts: make(map[string]*loginAttempt),
	}

	tests := []struct {
		name    string
		email   string
		wantErr string
	}{
		{"invalid_format", "notanemail", "invalid email format"},
		{"missing_at", "userdomain.com", "invalid email format"},
		{"at_only", "@", "invalid email format"},
		{"just_at", "@example.com", "invalid email format"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, status, err := svc.Register(nil, RegisterRequest{
				Email:    tt.email,
				Password: "validpassword123",
			})
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
// Register password length validation
// ---------------------------------------------------------------------------

func TestRegister_PasswordLengthValidation(t *testing.T) {
	svc := &AuthService{
		db:            nil,
		jwtSecret:     []byte("test-secret-that-is-long-enough-32chars"),
		jwtExpiry:     time.Hour,
		loginAttempts: make(map[string]*loginAttempt),
	}

	t.Run("too_long_password", func(t *testing.T) {
		longPassword := strings.Repeat("a", 73)
		_, status, err := svc.Register(nil, RegisterRequest{
			Email:    "test@example.com",
			Password: longPassword,
		})
		if err == nil {
			t.Fatal("expected error for password > 72 chars")
		}
		if !strings.Contains(err.Error(), "must not exceed 72") {
			t.Errorf("expected 'must not exceed 72' in error, got: %v", err)
		}
		if status != 400 {
			t.Errorf("expected status 400, got %d", status)
		}
	})

	t.Run("too_short_password", func(t *testing.T) {
		_, status, err := svc.Register(nil, RegisterRequest{
			Email:    "test@example.com",
			Password: "short",
		})
		if err == nil {
			t.Fatal("expected error for password < 8 chars")
		}
		if !strings.Contains(err.Error(), "at least 8 characters") {
			t.Errorf("expected 'at least 8 characters' in error, got: %v", err)
		}
		if status != 400 {
			t.Errorf("expected status 400, got %d", status)
		}
	})

	t.Run("exactly_72_accepted", func(t *testing.T) {
		// 72 chars is valid; this will proceed past password validation to
		// DB access and panic since db is nil. We recover from the panic to
		// verify that the password length check itself did not reject it.
		password := strings.Repeat("a", 72)
		var regErr error
		func() {
			defer func() { recover() }()
			_, _, regErr = svc.Register(nil, RegisterRequest{
				Email:    "test@example.com",
				Password: password,
			})
		}()
		// Should NOT fail on password validation
		if regErr != nil && strings.Contains(regErr.Error(), "exceed 72") {
			t.Error("72-char password should not be rejected")
		}
	})
}

// ---------------------------------------------------------------------------
// dummyHash initialization (platform auth)
// ---------------------------------------------------------------------------

func TestDummyHash_NotNil(t *testing.T) {
	if dummyHash == nil {
		t.Fatal("dummyHash should not be nil")
	}
	if len(dummyHash) == 0 {
		t.Fatal("dummyHash should not be empty")
	}
}

// ---------------------------------------------------------------------------
// ChangePassword validation
// ---------------------------------------------------------------------------

func TestChangePassword_ValidationErrors(t *testing.T) {
	svc := &AuthService{
		db:            nil,
		jwtSecret:     []byte("test-secret-that-is-long-enough-32chars"),
		jwtExpiry:     time.Hour,
		loginAttempts: make(map[string]*loginAttempt),
	}

	tests := []struct {
		name    string
		req     ChangePasswordRequest
		wantErr string
	}{
		{
			name:    "empty_current",
			req:     ChangePasswordRequest{CurrentPassword: "", NewPassword: "newpass123"},
			wantErr: "current_password and new_password are required",
		},
		{
			name:    "empty_new",
			req:     ChangePasswordRequest{CurrentPassword: "oldpass", NewPassword: ""},
			wantErr: "current_password and new_password are required",
		},
		{
			name:    "short_new_password",
			req:     ChangePasswordRequest{CurrentPassword: "oldpass", NewPassword: "short"},
			wantErr: "at least 8 characters",
		},
		{
			name:    "too_long_new_password",
			req:     ChangePasswordRequest{CurrentPassword: "oldpass", NewPassword: strings.Repeat("a", 73)},
			wantErr: "must not exceed 72",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, status, err := svc.ChangePassword(nil, "user-id", tt.req)
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
// quoteLiteral (SQL injection prevention)
// ---------------------------------------------------------------------------

func TestQuoteLiteral(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"simple", "E'simple'"},
		{"with'quote", "E'with''quote'"},
		{`with\backslash`, `E'with\\backslash'`},
		{"", "E''"},
		{`'; DROP TABLE users;--`, `E'''; DROP TABLE users;--'`},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := quoteLiteral(tt.input)
			if got != tt.expected {
				t.Errorf("quoteLiteral(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// pgUsernameRegex validation
// ---------------------------------------------------------------------------

func TestPgUsernameRegex(t *testing.T) {
	tests := []struct {
		input string
		valid bool
	}{
		{"u_aabbccddeeff", true},
		{"u_123456789abc", true},
		{"u_000000000000", true},
		{"u_", false},
		{"u_short", false},
		{"u_toolongstring", false},
		{"invalid", false},
		{"", false},
		{"u_AABBCCDDEEFF", false}, // uppercase not allowed
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := pgUsernameRegex.MatchString(tt.input)
			if got != tt.valid {
				t.Errorf("pgUsernameRegex.MatchString(%q) = %v, want %v", tt.input, got, tt.valid)
			}
		})
	}
}
