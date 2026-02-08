package platform

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// GenerateRandomPassword
// ---------------------------------------------------------------------------

func TestGenerateRandomPassword_Length(t *testing.T) {
	lengths := []int{0, 1, 8, 16, 32, 64, 128}
	for _, l := range lengths {
		t.Run("length="+string(rune('0'+l)), func(t *testing.T) {
			pw, err := GenerateRandomPassword(l)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(pw) != l {
				t.Fatalf("expected length %d, got %d", l, len(pw))
			}
		})
	}
}

func TestGenerateRandomPassword_CharsetOnly(t *testing.T) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	pw, err := GenerateRandomPassword(1000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for i, c := range pw {
		if !strings.ContainsRune(charset, c) {
			t.Fatalf("character at position %d (%q) not in charset", i, string(c))
		}
	}
}

func TestGenerateRandomPassword_Uniqueness(t *testing.T) {
	// Generating two passwords of reasonable length should be different
	// (astronomically unlikely to collide).
	pw1, err := GenerateRandomPassword(32)
	if err != nil {
		t.Fatal(err)
	}
	pw2, err := GenerateRandomPassword(32)
	if err != nil {
		t.Fatal(err)
	}
	if pw1 == pw2 {
		t.Fatal("two random passwords should not be identical")
	}
}

func TestGenerateRandomPassword_ZeroLength(t *testing.T) {
	pw, err := GenerateRandomPassword(0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pw != "" {
		t.Fatalf("expected empty string for length 0, got %q", pw)
	}
}

// ---------------------------------------------------------------------------
// EncryptPgPassword / DecryptPgPassword round-trip
// ---------------------------------------------------------------------------

func TestEncryptDecryptRoundTrip(t *testing.T) {
	tests := []struct {
		name             string
		pgPassword       string
		platformPassword string
	}{
		{"simple", "mydbpass", "platformpass"},
		{"empty_pg_password", "", "platformpass"},
		{"unicode_passwords", "пароль123", "платформа!@#"},
		{"long_password", strings.Repeat("a", 1000), strings.Repeat("b", 200)},
		{"special_chars", "p@$$w0rd!#%^&*()", "k3y:w1th;spec1al"},
		{"single_char", "x", "y"},
		{"with_colons", "pass:word:here", "key:with:colons"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := EncryptPgPassword(tt.pgPassword, tt.platformPassword)
			if err != nil {
				t.Fatalf("EncryptPgPassword failed: %v", err)
			}

			// Verify format: salt:iv:authTag:ciphertext (4 hex parts)
			parts := strings.Split(encrypted, ":")
			if len(parts) != 4 {
				t.Fatalf("expected 4 colon-separated parts, got %d", len(parts))
			}
			for i, p := range parts {
				if i < 3 && len(p) == 0 {
					t.Fatalf("part %d is empty", i)
				}
				// Verify each part is valid hex
				for _, c := range p {
					if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
						t.Fatalf("part %d contains non-hex character: %q", i, string(c))
					}
				}
			}

			decrypted, err := DecryptPgPassword(encrypted, tt.platformPassword)
			if err != nil {
				t.Fatalf("DecryptPgPassword failed: %v", err)
			}

			if decrypted != tt.pgPassword {
				t.Fatalf("round-trip mismatch: got %q, want %q", decrypted, tt.pgPassword)
			}
		})
	}
}

func TestEncryptProducesDifferentCiphertexts(t *testing.T) {
	// Same plaintext encrypted twice should yield different ciphertexts
	// because salt and IV are random.
	enc1, err := EncryptPgPassword("password", "key")
	if err != nil {
		t.Fatal(err)
	}
	enc2, err := EncryptPgPassword("password", "key")
	if err != nil {
		t.Fatal(err)
	}
	if enc1 == enc2 {
		t.Fatal("two encryptions of the same plaintext should produce different ciphertexts")
	}
}

// ---------------------------------------------------------------------------
// DecryptPgPassword error paths
// ---------------------------------------------------------------------------

func TestDecrypt_WrongPassword(t *testing.T) {
	encrypted, err := EncryptPgPassword("secret_db_pass", "correct_platform_password")
	if err != nil {
		t.Fatal(err)
	}

	_, err = DecryptPgPassword(encrypted, "wrong_platform_password")
	if err == nil {
		t.Fatal("expected error when decrypting with wrong password")
	}
	if !strings.Contains(err.Error(), "decrypt") {
		t.Fatalf("expected 'decrypt' in error message, got: %v", err)
	}
}

func TestDecrypt_InvalidFormat(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"one_part", "aabbcc"},
		{"two_parts", "aa:bb"},
		{"three_parts", "aa:bb:cc"},
		{"five_parts", "aa:bb:cc:dd:ee"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecryptPgPassword(tt.input, "anykey")
			if err == nil {
				t.Fatal("expected error for invalid format")
			}
			if !strings.Contains(err.Error(), "invalid encrypted format") {
				t.Fatalf("expected 'invalid encrypted format' in error, got: %v", err)
			}
		})
	}
}

func TestDecrypt_InvalidHex(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"bad_salt", "ZZZZ:aabb:ccdd:eeff", "decode salt"},
		{"bad_iv", "aabb:ZZZZ:ccdd:eeff", "decode IV"},
		{"bad_authtag", "aabb:ccdd:ZZZZ:eeff", "decode auth tag"},
		{"bad_ciphertext", "aabb:ccdd:eeff:ZZZZ", "decode ciphertext"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecryptPgPassword(tt.input, "anykey")
			if err == nil {
				t.Fatal("expected error for invalid hex")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected %q in error, got: %v", tt.want, err)
			}
		})
	}
}

func TestDecrypt_TamperedCiphertext(t *testing.T) {
	encrypted, err := EncryptPgPassword("dbpass", "platformkey")
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with the ciphertext part (last segment)
	parts := strings.Split(encrypted, ":")
	// Flip a byte in the ciphertext
	runes := []rune(parts[3])
	if len(runes) > 0 {
		if runes[0] == 'a' {
			runes[0] = 'b'
		} else {
			runes[0] = 'a'
		}
	}
	parts[3] = string(runes)
	tampered := strings.Join(parts, ":")

	_, err = DecryptPgPassword(tampered, "platformkey")
	if err == nil {
		t.Fatal("expected error when ciphertext is tampered")
	}
}

func TestDecrypt_TamperedAuthTag(t *testing.T) {
	encrypted, err := EncryptPgPassword("dbpass", "platformkey")
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(encrypted, ":")
	runes := []rune(parts[2])
	if len(runes) > 0 {
		if runes[0] == 'a' {
			runes[0] = 'b'
		} else {
			runes[0] = 'a'
		}
	}
	parts[2] = string(runes)
	tampered := strings.Join(parts, ":")

	_, err = DecryptPgPassword(tampered, "platformkey")
	if err == nil {
		t.Fatal("expected error when auth tag is tampered")
	}
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

func BenchmarkEncryptPgPassword(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = EncryptPgPassword("benchmark_password", "benchmark_key")
	}
}

func BenchmarkDecryptPgPassword(b *testing.B) {
	encrypted, _ := EncryptPgPassword("benchmark_password", "benchmark_key")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecryptPgPassword(encrypted, "benchmark_key")
	}
}

func BenchmarkGenerateRandomPassword(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = GenerateRandomPassword(32)
	}
}
