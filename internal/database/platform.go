package database

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
)

// NewPlatformPool creates the connection pool for the platform database.
func NewPlatformPool(ctx context.Context, databaseURL string, maxConns, minConns int32) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse platform database URL: %w", err)
	}

	if maxConns <= 0 {
		maxConns = 10
	}
	if minConns <= 0 {
		minConns = 2
	}
	cfg.MaxConns = maxConns
	cfg.MinConns = minConns

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create platform pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping platform database: %w", err)
	}

	return pool, nil
}

// RunMigrations executes SQL migration files against a database pool.
func RunMigrations(ctx context.Context, pool *pgxpool.Pool, migrations []Migration) error {
	// Ensure platform schema exists before tracking migrations
	if _, err := pool.Exec(ctx, `CREATE SCHEMA IF NOT EXISTS platform`); err != nil {
		return fmt.Errorf("create platform schema: %w", err)
	}

	// Create migrations tracking table in platform schema
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS platform._migrations (
			id SERIAL PRIMARY KEY,
			name VARCHAR(255) NOT NULL UNIQUE,
			executed_at TIMESTAMPTZ DEFAULT NOW()
		)
	`)
	if err != nil {
		return fmt.Errorf("create migrations table: %w", err)
	}

	for _, m := range migrations {
		// Check if already executed
		var count int
		err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM platform._migrations WHERE name = $1`, m.Name).Scan(&count)
		if err != nil {
			return fmt.Errorf("check migration %s: %w", m.Name, err)
		}
		if count > 0 {
			slog.Debug("Migration already executed, skipping", "name", m.Name)
			continue
		}

		slog.Info("Running migration", "name", m.Name)

		tx, err := pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin transaction for migration %s: %w", m.Name, err)
		}

		if _, err = tx.Exec(ctx, m.SQL); err != nil {
			tx.Rollback(ctx)
			return fmt.Errorf("execute migration %s: %w", m.Name, err)
		}

		if _, err = tx.Exec(ctx, `INSERT INTO platform._migrations (name) VALUES ($1)`, m.Name); err != nil {
			tx.Rollback(ctx)
			return fmt.Errorf("record migration %s: %w", m.Name, err)
		}

		if err = tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit migration %s: %w", m.Name, err)
		}
	}

	return nil
}

type Migration struct {
	Name string
	SQL  string
}
