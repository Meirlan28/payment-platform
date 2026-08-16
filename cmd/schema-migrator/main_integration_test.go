//go:build integration

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// CockroachDB does not promise atomic rollback for a batch containing schema
// changes. This test proves the migrator records the exact committed prefix and
// refuses to guess/replay after the following statement fails.
func TestPartialDDLIsDurablyFencedFromAutomaticReplay(t *testing.T) {
	base := os.Getenv("DATABASE_URL")
	if base == "" {
		t.Skip("DATABASE_URL is required for integration test")
	}
	ctx := context.Background()
	databaseName := "migration_partial_" + randomHex(t, 8)
	adminURL := databaseURLWithName(t, base, "defaultdb")
	admin, err := pgxpool.New(ctx, adminURL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `CREATE DATABASE `+databaseName); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), `DROP DATABASE `+databaseName+` CASCADE`)
		admin.Close()
	})

	directory := t.TempDir()
	contents := []byte(`
CREATE TABLE migration_probe (id INT8 PRIMARY KEY);
SELECT * FROM relation_that_must_not_exist;
CREATE TABLE migration_must_not_run (id INT8 PRIMARY KEY);
`)
	if err := os.WriteFile(directory+"/001_partial.sql", contents, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DATABASE_URL", databaseURLWithName(t, base, databaseName))
	t.Setenv("MIGRATIONS_DIR", directory)
	t.Setenv("MIGRATION_TARGET_VERSION", "001_partial.sql")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := run(ctx, logger); err == nil || !strings.Contains(err.Error(), "relation_that_must_not_exist") {
		t.Fatalf("first run must expose the failing statement: %v", err)
	}

	probe, err := pgxpool.New(ctx, databaseURLWithName(t, base, databaseName))
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	var probeRows, migrationReceipts int64
	if err := probe.QueryRow(ctx, `SELECT count(*) FROM migration_probe`).Scan(&probeRows); err != nil {
		t.Fatalf("the first DDL statement should be durably committed: %v", err)
	}
	if err := probe.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&migrationReceipts); err != nil {
		t.Fatal(err)
	}
	if probeRows != 0 || migrationReceipts != 0 {
		t.Fatalf("unexpected probe=%d migration receipts=%d", probeRows, migrationReceipts)
	}
	var attemptStatus string
	if err := probe.QueryRow(ctx, `
SELECT status FROM schema_migration_attempts WHERE version='001_partial.sql'`).Scan(&attemptStatus); err != nil {
		t.Fatal(err)
	}
	if attemptStatus != "FAILED" {
		t.Fatalf("attempt status=%s, want FAILED", attemptStatus)
	}
	rows, err := probe.Query(ctx, `
SELECT ordinal, status FROM schema_migration_steps
WHERE version='001_partial.sql' ORDER BY ordinal`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var statuses []string
	for rows.Next() {
		var ordinal int64
		var status string
		if err := rows.Scan(&ordinal, &status); err != nil {
			t.Fatal(err)
		}
		statuses = append(statuses, status)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(statuses, ",") != "APPLIED,FAILED" {
		t.Fatalf("step statuses=%v, want [APPLIED FAILED]", statuses)
	}

	if err := run(ctx, logger); err == nil || !strings.Contains(err.Error(), "unresolved FAILED attempt") {
		t.Fatalf("second run must refuse automatic replay: %v", err)
	}
	if _, err := probe.Exec(ctx, `SELECT 1 FROM migration_must_not_run`); err == nil {
		t.Fatal("statement after the failure was unexpectedly executed")
	}
}

func TestSelectedTargetRejectsDatabaseAheadOfArtifact(t *testing.T) {
	base := os.Getenv("DATABASE_URL")
	if base == "" {
		t.Skip("DATABASE_URL is required for integration test")
	}
	ctx := context.Background()
	databaseName := "migration_ahead_" + randomHex(t, 8)
	admin, err := pgxpool.New(ctx, databaseURLWithName(t, base, "defaultdb"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `CREATE DATABASE `+databaseName); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), `DROP DATABASE `+databaseName+` CASCADE`)
		admin.Close()
	})
	directory := t.TempDir()
	if err := os.WriteFile(directory+"/001_first.sql", []byte(`SELECT 1;`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DATABASE_URL", databaseURLWithName(t, base, databaseName))
	t.Setenv("MIGRATIONS_DIR", directory)
	t.Setenv("MIGRATION_TARGET_VERSION", "001_first.sql")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := run(ctx, logger); err != nil {
		t.Fatal(err)
	}
	probe, err := pgxpool.New(ctx, databaseURLWithName(t, base, databaseName))
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	if _, err := probe.Exec(ctx, `
INSERT INTO schema_migrations (version, checksum, executor_version)
VALUES ('002_future.sql', $1, 'future-test')`, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if err := run(ctx, logger); err == nil || !strings.Contains(err.Error(), "schema is ahead") {
		t.Fatalf("schema-ahead catalog was not rejected: %v", err)
	}
}

func randomHex(t *testing.T, bytesCount int) string {
	t.Helper()
	raw := make([]byte, bytesCount)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(raw)
}

func databaseURLWithName(t *testing.T, raw, databaseName string) string {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	parsed.Path = "/" + databaseName
	return parsed.String()
}
