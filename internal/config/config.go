package config

import (
	"fmt"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	// Server
	Port    int
	Host    string
	SiteURL string

	// Platform database (superuser connection)
	DatabaseURL string

	// Platform JWT
	PlatformJWTSecret string
	PlatformJWTExpiry int // seconds

	// Pool Manager
	MaxConnectionsPerDB int
	GlobalMaxConnections int
	PoolIdleTimeout      int // seconds

	// Default auth settings for new projects
	DefaultEnableSignup      bool
	DefaultAutoconfirm       bool
	DefaultPasswordMinLength int

	// Backup
	BackupEncryptionKey string

	// Import
	ImportMaxSizeMB int
	ImportTempDir   string

	// Admin
	AdminEmail    string
	AdminPassword string
}

func Load() (*Config, error) {
	_ = godotenv.Load()

	cfg := &Config{
		Port:                     getEnvInt("PORT", 3000),
		Host:                     getEnv("HOST", "0.0.0.0"),
		SiteURL:                  getEnv("SITE_URL", "http://localhost:3000"),
		DatabaseURL:              mustGetEnv("DATABASE_URL"),
		PlatformJWTSecret:        mustGetEnv("PLATFORM_JWT_SECRET"),
		PlatformJWTExpiry:        getEnvInt("PLATFORM_JWT_EXPIRY", 86400),
		MaxConnectionsPerDB:     getEnvInt("MAX_CONNECTIONS_PER_DB", 5),
		GlobalMaxConnections:    getEnvInt("GLOBAL_MAX_CONNECTIONS", 100),
		PoolIdleTimeout:          getEnvInt("POOL_IDLE_TIMEOUT_SECONDS", 300),
		DefaultEnableSignup:      getEnvBool("DEFAULT_ENABLE_SIGNUP", true),
		DefaultAutoconfirm:       getEnvBool("DEFAULT_AUTOCONFIRM", true),
		DefaultPasswordMinLength: getEnvInt("DEFAULT_PASSWORD_MIN_LENGTH", 6),
		BackupEncryptionKey:      getEnv("BACKUP_ENCRYPTION_KEY", ""),
		ImportMaxSizeMB:          getEnvInt("IMPORT_MAX_SIZE_MB", 500),
		ImportTempDir:            getEnv("IMPORT_TEMP_DIR", "/tmp/imports"),
		AdminEmail:               getEnv("ADMIN_EMAIL", ""),
		AdminPassword:            getEnv("ADMIN_PASSWORD", ""),
	}

	if len(cfg.PlatformJWTSecret) < 32 {
		return nil, fmt.Errorf("PLATFORM_JWT_SECRET must be at least 32 characters")
	}

	// Validate admin config: both or neither
	if (cfg.AdminEmail != "" && cfg.AdminPassword == "") || (cfg.AdminEmail == "" && cfg.AdminPassword != "") {
		return nil, fmt.Errorf("ADMIN_EMAIL and ADMIN_PASSWORD must both be set or both be empty")
	}
	if cfg.AdminPassword != "" && len(cfg.AdminPassword) < 8 {
		return nil, fmt.Errorf("ADMIN_PASSWORD must be at least 8 characters")
	}

	return cfg, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func mustGetEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		panic(fmt.Sprintf("required environment variable %s is not set", key))
	}
	return v
}

func getEnvInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return i
}

func getEnvBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	return v == "true" || v == "1"
}
