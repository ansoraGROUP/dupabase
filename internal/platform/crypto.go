package platform

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const pbkdf2Iterations = 310_000

// GenerateRandomPassword generates a random alphanumeric password of given length.
func GenerateRandomPassword(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b), nil
}

// EncryptPgPassword encrypts a PG password using AES-256-GCM with a key
// derived from the user's platform password via PBKDF2.
// Returns the encrypted string in format: salt:iv:authTag:ciphertext (all hex).
func EncryptPgPassword(pgPassword, platformPassword string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	key := pbkdf2.Key([]byte(platformPassword), salt, pbkdf2Iterations, 32, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create GCM: %w", err)
	}

	iv := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return "", fmt.Errorf("generate IV: %w", err)
	}

	ciphertext := gcm.Seal(nil, iv, []byte(pgPassword), nil)

	// GCM appends auth tag to ciphertext, split it out
	tagSize := gcm.Overhead()
	authTag := ciphertext[len(ciphertext)-tagSize:]
	encrypted := ciphertext[:len(ciphertext)-tagSize]

	return fmt.Sprintf("%s:%s:%s:%s",
		hex.EncodeToString(salt),
		hex.EncodeToString(iv),
		hex.EncodeToString(authTag),
		hex.EncodeToString(encrypted),
	), nil
}

// DecryptPgPassword decrypts a PG password using the user's platform password.
func DecryptPgPassword(encryptedStr, platformPassword string) (string, error) {
	parts := strings.Split(encryptedStr, ":")
	if len(parts) != 4 {
		return "", fmt.Errorf("invalid encrypted format")
	}

	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("decode salt: %w", err)
	}
	iv, err := hex.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode IV: %w", err)
	}
	authTag, err := hex.DecodeString(parts[2])
	if err != nil {
		return "", fmt.Errorf("decode auth tag: %w", err)
	}
	encrypted, err := hex.DecodeString(parts[3])
	if err != nil {
		return "", fmt.Errorf("decode ciphertext: %w", err)
	}

	key := pbkdf2.Key([]byte(platformPassword), salt, pbkdf2Iterations, 32, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create GCM: %w", err)
	}

	// Reconstruct ciphertext with appended auth tag (as GCM expects)
	ciphertextWithTag := append(encrypted, authTag...)
	plaintext, err := gcm.Open(nil, iv, ciphertextWithTag, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}

	return string(plaintext), nil
}
