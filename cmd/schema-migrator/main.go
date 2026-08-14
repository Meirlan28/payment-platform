package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/example/payment-platform/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const maxMigrationBytes = 16 << 20

var migrationName = regexp.MustCompile(`^[0-9]{3}_[a-z0-9_]+\.sql$`)

type migration struct {
	version  string
	contents []byte
	checksum [sha256.Size]byte
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(context.Background(), logger); err != nil {
		logger.Error("schema migration failed", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, logger *slog.Logger) error {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return errors.New("DATABASE_URL is required")
	}
	directory := os.Getenv("MIGRATIONS_DIR")
	if directory == "" {
		directory = "migrations"
	}
	migrations, err := loadMigrations(directory)
	if err != nil {
		return err
	}

	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return fmt.Errorf("parse DATABASE_URL: %w", err)
	}
	config.MaxConns = 2
	config.MinConns = 1
	config.MaxConnLifetime = 30 * time.Minute
	// Migrations contain deliberately reviewed multi-statement SQL files.
	// Runtime services retain pgx's prepared/extended protocol.
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return fmt.Errorf("connect database: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("ping database: %w", err)
	}
	if err := bootstrap(ctx, pool); err != nil {
		return err
	}

	runner := store.NewRunner(pool)
	for _, next := range migrations {
		applied := false
		err := runner.RunSerializable(ctx, func(tx pgx.Tx) error {
			var lock int
			if err := tx.QueryRow(ctx, `
SELECT lock_id FROM schema_migration_lock WHERE lock_id=1 FOR UPDATE`).Scan(&lock); err != nil {
				return fmt.Errorf("acquire schema migration lock: %w", err)
			}
			var stored []byte
			err := tx.QueryRow(ctx, `
SELECT checksum FROM schema_migrations WHERE version=$1`, next.version).Scan(&stored)
			if err == nil {
				if len(stored) != sha256.Size || string(stored) != string(next.checksum[:]) {
					return fmt.Errorf("migration %s checksum changed: stored=%s current=%s",
						next.version, hex.EncodeToString(stored), hex.EncodeToString(next.checksum[:]))
				}
				return nil
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			if _, err := tx.Exec(ctx, string(next.contents)); err != nil {
				return fmt.Errorf("execute %s: %w", next.version, err)
			}
			if _, err := tx.Exec(ctx, `
INSERT INTO schema_migrations (version, checksum, executor_version)
VALUES ($1,$2,$3)`, next.version, next.checksum[:], "schema-migrator/v1"); err != nil {
				return fmt.Errorf("record %s: %w", next.version, err)
			}
			applied = true
			return nil
		})
		if err != nil {
			return err
		}
		logger.Info("schema migration verified", "version", next.version,
			"checksum", hex.EncodeToString(next.checksum[:]), "newly_applied", applied)
	}
	return nil
}

func bootstrap(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version STRING PRIMARY KEY,
    checksum BYTES NOT NULL CHECK (length(checksum)=32),
    executor_version STRING NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp()
);
CREATE TABLE IF NOT EXISTS schema_migration_lock (
    lock_id INT8 PRIMARY KEY CHECK (lock_id=1),
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp()
);
INSERT INTO schema_migration_lock (lock_id) VALUES (1)
ON CONFLICT (lock_id) DO NOTHING;`)
	if err != nil {
		return fmt.Errorf("bootstrap migration metadata: %w", err)
	}
	return nil
}

func loadMigrations(directory string) ([]migration, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("read migration directory: %w", err)
	}
	var result []migration
	for _, entry := range entries {
		if entry.IsDir() || !migrationName.MatchString(entry.Name()) {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		if info.Size() <= 0 || info.Size() > maxMigrationBytes {
			return nil, fmt.Errorf("migration %s has invalid size %d", entry.Name(), info.Size())
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		result = append(result, migration{
			version: entry.Name(), contents: contents, checksum: sha256.Sum256(contents),
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].version < result[j].version })
	if len(result) == 0 {
		return nil, errors.New("no ordered migrations found")
	}
	for index, next := range result {
		expected := fmt.Sprintf("%03d_", index+1)
		if len(next.version) < len(expected) || next.version[:len(expected)] != expected {
			return nil, fmt.Errorf("migration sequence gap at %s: expected prefix %s", next.version, expected)
		}
	}
	return result, nil
}
