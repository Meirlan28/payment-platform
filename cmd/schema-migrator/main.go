package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/example/payment-platform/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const maxMigrationBytes = 16 << 20
const integrationApplyAllAck = "APPLY_ALL_CHECKED_IN_MIGRATIONS_FOR_EPHEMERAL_INTEGRATION"

var migrationName = regexp.MustCompile(`^[0-9]{3}_[a-z0-9_]+\.sql$`)

type migration struct {
	version  string
	contents []byte
	checksum [sha256.Size]byte
}

type migrationStatement struct {
	ordinal  int64
	contents string
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
	migrations, err = migrationsThrough(
		migrations,
		os.Getenv("MIGRATION_TARGET_VERSION"),
		os.Getenv("MIGRATION_APPLY_ALL_ACK"),
	)
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
	// Migration files are lexically split into one reviewed statement per
	// implicit transaction. Runtime services retain pgx's prepared/extended
	// protocol; SimpleProtocol here preserves Cockroach-specific DDL syntax.
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
	if err := verifyDatabaseCatalog(ctx, pool, migrations); err != nil {
		return err
	}
	runID, err := newRunID()
	if err != nil {
		return err
	}

	runner := store.NewRunner(pool)
	for _, next := range migrations {
		statements, err := splitMigrationStatements(next.contents)
		if err != nil {
			return err
		}
		claimed, err := claimMigration(ctx, runner, next, int64(len(statements)), runID)
		if err != nil {
			return err
		}
		if !claimed {
			logger.Info("schema migration verified", "version", next.version,
				"checksum", hex.EncodeToString(next.checksum[:]), "newly_applied", false)
			continue
		}
		if err := applyMigration(ctx, pool, runner, next, statements, runID); err != nil {
			return err
		}
		logger.Info("schema migration verified", "version", next.version,
			"checksum", hex.EncodeToString(next.checksum[:]), "newly_applied", true)
	}
	return nil
}

// verifyDatabaseCatalog prevents an older image or a lower target gate from
// declaring success against a schema which is already ahead, divergent, or
// has unresolved work outside this exact release prefix.
func verifyDatabaseCatalog(ctx context.Context, pool *pgxpool.Pool, migrations []migration) error {
	rows, err := pool.Query(ctx, `
SELECT version, checksum FROM schema_migrations ORDER BY version`)
	if err != nil {
		return fmt.Errorf("read applied migration catalog: %w", err)
	}
	type appliedMigration struct {
		version  string
		checksum []byte
	}
	var applied []appliedMigration
	for rows.Next() {
		var item appliedMigration
		if err := rows.Scan(&item.version, &item.checksum); err != nil {
			rows.Close()
			return err
		}
		applied = append(applied, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if len(applied) > len(migrations) {
		return fmt.Errorf("database schema is ahead of the selected artifact/target: applied=%d selected=%d",
			len(applied), len(migrations))
	}
	selected := make(map[string]struct{}, len(migrations))
	for index := range migrations {
		selected[migrations[index].version] = struct{}{}
		if index >= len(applied) {
			continue
		}
		if applied[index].version != migrations[index].version {
			return fmt.Errorf("database migration catalog is not the selected exact prefix at position %d: stored=%s selected=%s",
				index+1, applied[index].version, migrations[index].version)
		}
		if err := verifyChecksum(migrations[index], applied[index].checksum); err != nil {
			return err
		}
	}

	attemptRows, err := pool.Query(ctx, `
SELECT attempt.version, attempt.status,
       EXISTS (SELECT 1 FROM schema_migrations AS applied
                WHERE applied.version=attempt.version)
FROM schema_migration_attempts AS attempt
ORDER BY attempt.version`)
	if err != nil {
		return fmt.Errorf("read migration attempt catalog: %w", err)
	}
	defer attemptRows.Close()
	for attemptRows.Next() {
		var version, status string
		var hasReceipt bool
		if err := attemptRows.Scan(&version, &status, &hasReceipt); err != nil {
			return err
		}
		if _, ok := selected[version]; !ok {
			return fmt.Errorf("database contains migration attempt %s outside the selected artifact/target", version)
		}
		if status == "APPLIED" && !hasReceipt {
			return fmt.Errorf("migration attempt %s is APPLIED without a schema_migrations receipt", version)
		}
		if status != "APPLIED" && hasReceipt {
			return fmt.Errorf("migration attempt %s has status %s despite a completed receipt", version, status)
		}
	}
	if err := attemptRows.Err(); err != nil {
		return err
	}
	return nil
}

func bootstrap(ctx context.Context, pool *pgxpool.Pool) error {
	statements := []string{`
CREATE TABLE IF NOT EXISTS schema_migrations (
    version STRING PRIMARY KEY,
    checksum BYTES NOT NULL CHECK (length(checksum)=32),
    executor_version STRING NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp()
)`, `
CREATE TABLE IF NOT EXISTS schema_migration_lock (
    lock_id INT8 PRIMARY KEY CHECK (lock_id=1),
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp()
)`, `
INSERT INTO schema_migration_lock (lock_id) VALUES (1)
	ON CONFLICT (lock_id) DO NOTHING`, `
CREATE TABLE IF NOT EXISTS schema_migration_attempts (
    version STRING PRIMARY KEY,
    checksum BYTES NOT NULL CHECK (length(checksum)=32),
    statement_count INT8 NOT NULL CHECK (statement_count > 0),
    owner_id STRING NOT NULL,
    status STRING NOT NULL CHECK (status IN ('ACTIVE','FAILED','APPLIED')),
    error STRING NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    CHECK ((status='FAILED') = (error IS NOT NULL))
)`, `
CREATE TABLE IF NOT EXISTS schema_migration_steps (
    version STRING NOT NULL REFERENCES schema_migration_attempts (version),
    ordinal INT8 NOT NULL CHECK (ordinal > 0),
    statement_checksum BYTES NOT NULL CHECK (length(statement_checksum)=32),
    status STRING NOT NULL CHECK (status IN ('ACTIVE','FAILED','APPLIED')),
    error STRING NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    completed_at TIMESTAMPTZ NULL,
    PRIMARY KEY (version, ordinal),
    CHECK ((status='FAILED') = (error IS NOT NULL)),
    CHECK ((status='APPLIED') = (completed_at IS NOT NULL))
)`}
	for index, statement := range statements {
		if _, err := pool.Exec(ctx, statement); err != nil {
			return fmt.Errorf("bootstrap migration metadata statement %d: %w", index+1, err)
		}
	}
	return nil
}

func newRunID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("create migration run id: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

// claimMigration durably fences concurrent migrators before any DDL runs. If a
// previous process died with ACTIVE/FAILED state and no completed migration
// receipt, automatic replay is forbidden: a DDL commit may have succeeded even
// when its response was lost.
func claimMigration(
	ctx context.Context,
	runner *store.Runner,
	next migration,
	statementCount int64,
	runID string,
) (bool, error) {
	claimed := false
	err := runner.RunSerializable(ctx, func(tx pgx.Tx) error {
		var lock int64
		if err := tx.QueryRow(ctx, `
SELECT lock_id FROM schema_migration_lock WHERE lock_id=1 FOR UPDATE`).Scan(&lock); err != nil {
			return fmt.Errorf("acquire schema migration lock: %w", err)
		}
		var stored []byte
		err := tx.QueryRow(ctx, `
SELECT checksum FROM schema_migrations WHERE version=$1`, next.version).Scan(&stored)
		if err == nil {
			return verifyChecksum(next, stored)
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}

		var attemptChecksum []byte
		var owner, status string
		err = tx.QueryRow(ctx, `
SELECT checksum, owner_id, status
FROM schema_migration_attempts
WHERE version=$1`, next.version).Scan(&attemptChecksum, &owner, &status)
		if err == nil {
			if !bytes.Equal(attemptChecksum, next.checksum[:]) {
				return fmt.Errorf("migration %s in-flight checksum differs: stored=%s current=%s",
					next.version, hex.EncodeToString(attemptChecksum), hex.EncodeToString(next.checksum[:]))
			}
			return fmt.Errorf("migration %s has unresolved %s attempt owned by %s; inspect schema_migration_steps before any incident-specific signed recovery",
				next.version, status, owner)
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if _, err := tx.Exec(ctx, `
INSERT INTO schema_migration_attempts
    (version, checksum, statement_count, owner_id, status)
VALUES ($1,$2,$3,$4,'ACTIVE')`, next.version, next.checksum[:], statementCount, runID); err != nil {
			return err
		}
		claimed = true
		return nil
	})
	return claimed, err
}

func verifyChecksum(next migration, stored []byte) error {
	if len(stored) != sha256.Size || !bytes.Equal(stored, next.checksum[:]) {
		return fmt.Errorf("migration %s checksum changed: stored=%s current=%s",
			next.version, hex.EncodeToString(stored), hex.EncodeToString(next.checksum[:]))
	}
	return nil
}

func applyMigration(
	ctx context.Context,
	pool *pgxpool.Pool,
	runner *store.Runner,
	next migration,
	statements []migrationStatement,
	runID string,
) error {
	for _, statement := range statements {
		if err := startMigrationStep(ctx, runner, next, statement, runID); err != nil {
			return err
		}
		// Exactly one SQL statement is executed as its own implicit transaction.
		// CockroachDB explicitly does not promise atomic rollback for a batch of
		// schema changes inside one explicit transaction.
		if _, err := pool.Exec(ctx, statement.contents); err != nil {
			wrapped := fmt.Errorf("execute %s statement %d: %w", next.version, statement.ordinal, err)
			markMigrationFailed(ctx, runner, next.version, statement.ordinal, runID, wrapped)
			return wrapped
		}
		if err := completeMigrationStep(ctx, runner, next, statement, runID); err != nil {
			// The statement may already be committed. Never replay it merely because
			// recording its receipt was ambiguous or unavailable.
			return fmt.Errorf("record %s statement %d (do not replay before inspection): %w",
				next.version, statement.ordinal, err)
		}
	}
	return finalizeMigration(ctx, runner, next, int64(len(statements)), runID)
}

func startMigrationStep(
	ctx context.Context,
	runner *store.Runner,
	next migration,
	statement migrationStatement,
	runID string,
) error {
	return runner.RunSerializable(ctx, func(tx pgx.Tx) error {
		if err := lockOwnedAttempt(ctx, tx, next, runID); err != nil {
			return err
		}
		var stored []byte
		var status string
		err := tx.QueryRow(ctx, `
SELECT statement_checksum, status
FROM schema_migration_steps
WHERE version=$1 AND ordinal=$2`, next.version, statement.ordinal).Scan(&stored, &status)
		if err == nil {
			if !bytes.Equal(stored, statement.checksum[:]) {
				return fmt.Errorf("migration %s statement %d checksum changed", next.version, statement.ordinal)
			}
			return fmt.Errorf("migration %s statement %d has unresolved status %s; automatic replay is unsafe",
				next.version, statement.ordinal, status)
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		_, err = tx.Exec(ctx, `
INSERT INTO schema_migration_steps
    (version, ordinal, statement_checksum, status)
VALUES ($1,$2,$3,'ACTIVE')`, next.version, statement.ordinal, statement.checksum[:])
		return err
	})
}

func completeMigrationStep(
	ctx context.Context,
	runner *store.Runner,
	next migration,
	statement migrationStatement,
	runID string,
) error {
	return runner.RunSerializable(ctx, func(tx pgx.Tx) error {
		if err := lockOwnedAttempt(ctx, tx, next, runID); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `
UPDATE schema_migration_steps
SET status='APPLIED', completed_at=transaction_timestamp(), error=NULL
WHERE version=$1 AND ordinal=$2 AND statement_checksum=$3 AND status='ACTIVE'`,
			next.version, statement.ordinal, statement.checksum[:])
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errors.New("migration step receipt CAS failed")
		}
		return nil
	})
}

func finalizeMigration(
	ctx context.Context,
	runner *store.Runner,
	next migration,
	statementCount int64,
	runID string,
) error {
	return runner.RunSerializable(ctx, func(tx pgx.Tx) error {
		if err := lockOwnedAttempt(ctx, tx, next, runID); err != nil {
			return err
		}
		var applied int64
		if err := tx.QueryRow(ctx, `
SELECT count(*) FROM schema_migration_steps
WHERE version=$1 AND status='APPLIED'`, next.version).Scan(&applied); err != nil {
			return err
		}
		if applied != statementCount {
			return fmt.Errorf("migration %s has %d/%d durable step receipts",
				next.version, applied, statementCount)
		}
		if _, err := tx.Exec(ctx, `
INSERT INTO schema_migrations (version, checksum, executor_version)
VALUES ($1,$2,$3)`, next.version, next.checksum[:], "schema-migrator/v2"); err != nil {
			return fmt.Errorf("record %s: %w", next.version, err)
		}
		tag, err := tx.Exec(ctx, `
UPDATE schema_migration_attempts
SET status='APPLIED', updated_at=transaction_timestamp(), error=NULL
WHERE version=$1 AND owner_id=$2 AND status='ACTIVE'`, next.version, runID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errors.New("migration attempt finalization CAS failed")
		}
		return nil
	})
}

func lockOwnedAttempt(ctx context.Context, tx pgx.Tx, next migration, runID string) error {
	var checksum []byte
	var owner, status string
	if err := tx.QueryRow(ctx, `
SELECT checksum, owner_id, status
FROM schema_migration_attempts
WHERE version=$1
FOR UPDATE`, next.version).Scan(&checksum, &owner, &status); err != nil {
		return err
	}
	if !bytes.Equal(checksum, next.checksum[:]) || owner != runID || status != "ACTIVE" {
		return fmt.Errorf("migration %s attempt fence rejected owner=%s status=%s",
			next.version, owner, status)
	}
	return nil
}

func markMigrationFailed(
	ctx context.Context,
	runner *store.Runner,
	version string,
	ordinal int64,
	runID string,
	cause error,
) {
	message := cause.Error()
	if len(message) > 4096 {
		message = message[:4096]
	}
	_ = runner.RunSerializable(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
UPDATE schema_migration_steps
SET status='FAILED', error=$3
WHERE version=$1 AND ordinal=$2 AND status='ACTIVE'`, version, ordinal, message); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
UPDATE schema_migration_attempts
SET status='FAILED', error=$3, updated_at=transaction_timestamp()
WHERE version=$1 AND owner_id=$2 AND status='ACTIVE'`, version, runID, message)
		return err
	})
}

// splitMigrationStatements is a conservative SQL lexical splitter. It honors
// quoted identifiers, standard/E strings, nested block comments and tagged or
// untagged dollar quotes used by PL/pgSQL bodies. It does not try to parse SQL;
// it only recognizes semicolons that are outside those lexical constructs.
func splitMigrationStatements(contents []byte) ([]migrationStatement, error) {
	var result []migrationStatement
	start := 0
	inSingle := false
	singleBackslashEscapes := false
	inDouble := false
	lineComment := false
	blockDepth := 0
	dollarTag := ""

	for index := 0; index < len(contents); {
		if lineComment {
			if contents[index] == '\n' {
				lineComment = false
			}
			index++
			continue
		}
		if blockDepth > 0 {
			if index+1 < len(contents) && contents[index] == '/' && contents[index+1] == '*' {
				blockDepth++
				index += 2
				continue
			}
			if index+1 < len(contents) && contents[index] == '*' && contents[index+1] == '/' {
				blockDepth--
				index += 2
				continue
			}
			index++
			continue
		}
		if dollarTag != "" {
			if bytes.HasPrefix(contents[index:], []byte(dollarTag)) {
				index += len(dollarTag)
				dollarTag = ""
				continue
			}
			index++
			continue
		}
		if inSingle {
			if singleBackslashEscapes && contents[index] == '\\' && index+1 < len(contents) {
				index += 2
				continue
			}
			if contents[index] == '\'' {
				if index+1 < len(contents) && contents[index+1] == '\'' {
					index += 2
					continue
				}
				inSingle = false
				singleBackslashEscapes = false
			}
			index++
			continue
		}
		if inDouble {
			if contents[index] == '"' {
				if index+1 < len(contents) && contents[index+1] == '"' {
					index += 2
					continue
				}
				inDouble = false
			}
			index++
			continue
		}

		if index+1 < len(contents) && contents[index] == '-' && contents[index+1] == '-' {
			lineComment = true
			index += 2
			continue
		}
		if index+1 < len(contents) && contents[index] == '/' && contents[index+1] == '*' {
			blockDepth = 1
			index += 2
			continue
		}
		switch contents[index] {
		case '\'':
			inSingle = true
			singleBackslashEscapes = escapeStringPrefix(contents, index)
			index++
			continue
		case '"':
			inDouble = true
			index++
			continue
		case '$':
			if index == 0 || !identifierByte(contents[index-1]) {
				if tag, ok := readDollarTag(contents[index:]); ok {
					dollarTag = tag
					index += len(tag)
					continue
				}
			}
		case ';':
			appendMigrationStatement(&result, contents[start:index+1])
			start = index + 1
		}
		index++
	}
	if inSingle || inDouble || blockDepth != 0 || dollarTag != "" {
		return nil, errors.New("migration contains an unterminated SQL lexical construct")
	}
	appendMigrationStatement(&result, contents[start:])
	if len(result) == 0 {
		return nil, errors.New("migration contains no SQL statements")
	}
	return result, nil
}

func escapeStringPrefix(contents []byte, quote int) bool {
	if quote >= 1 && (contents[quote-1] == 'e' || contents[quote-1] == 'E') &&
		(quote == 1 || !identifierByte(contents[quote-2])) {
		return true
	}
	return quote >= 2 && contents[quote-1] == '&' &&
		(contents[quote-2] == 'u' || contents[quote-2] == 'U') &&
		(quote == 2 || !identifierByte(contents[quote-3]))
}

func identifierByte(character byte) bool {
	return (character >= 'a' && character <= 'z') ||
		(character >= 'A' && character <= 'Z') ||
		(character >= '0' && character <= '9') || character == '_' ||
		character == '$' || character >= utf8.RuneSelf
}

func readDollarTag(contents []byte) (string, bool) {
	if len(contents) == 0 || contents[0] != '$' {
		return "", false
	}
	for index := 1; index < len(contents); index++ {
		if contents[index] == '$' {
			return string(contents[:index+1]), true
		}
		character := contents[index]
		if !((character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9' && index > 1) || character == '_') {
			return "", false
		}
	}
	return "", false
}

func appendMigrationStatement(result *[]migrationStatement, raw []byte) {
	statement := strings.TrimSpace(string(raw))
	if statement == "" {
		return
	}
	checksum := sha256.Sum256([]byte(statement))
	*result = append(*result, migrationStatement{
		ordinal: int64(len(*result) + 1), contents: statement, checksum: checksum,
	})
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

// migrationsThrough makes expand/enforce gates executable as separate release
// jobs. An unknown or empty production target is rejected rather than silently
// applying too much or stopping short. Apply-all exists only behind a loud,
// exact acknowledgement for an ephemeral integration database.
func migrationsThrough(migrations []migration, target, applyAllAck string) ([]migration, error) {
	if target == "" {
		if applyAllAck != integrationApplyAllAck {
			return nil, errors.New("MIGRATION_TARGET_VERSION is required; apply-all is allowed only with the explicit ephemeral-integration acknowledgement")
		}
		return migrations, nil
	}
	if !migrationName.MatchString(target) {
		return nil, fmt.Errorf("MIGRATION_TARGET_VERSION %q is not an exact migration filename", target)
	}
	for index := range migrations {
		if migrations[index].version == target {
			return migrations[:index+1], nil
		}
	}
	return nil, fmt.Errorf("MIGRATION_TARGET_VERSION %q is not present in MIGRATIONS_DIR", target)
}
