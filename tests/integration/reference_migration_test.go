//go:build integration

package integration_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/example/payment-platform/internal/ledger"
	"github.com/example/payment-platform/internal/schemamigration"
	"github.com/example/payment-platform/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type referenceTestIDs struct {
	prefix string
	next   atomic.Uint64
}

func (g *referenceTestIDs) Next(context.Context) (string, error) {
	return fmt.Sprintf("%s-%d", g.prefix, g.next.Add(1)), nil
}

func TestReferenceMigrationFullWorkflowIsRestartSafe(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL is not set; CockroachDB integration test skipped")
	}
	ctx := context.Background()
	adminConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := pgxpool.NewWithConfig(ctx, adminConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()

	databaseName := "reference_migration_test_" + randomHex(t, 8)
	quotedDatabase := pgx.Identifier{databaseName}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quotedDatabase); err != nil {
		t.Fatal(err)
	}
	var testPool *pgxpool.Pool
	defer func() {
		if testPool != nil {
			testPool.Close()
		}
		if _, err := admin.Exec(context.Background(), "DROP DATABASE "+quotedDatabase+" CASCADE"); err != nil {
			t.Errorf("drop isolated test database: %v", err)
		}
	}()

	testConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	testConfig.ConnConfig.Database = databaseName
	testConfig.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	testPool, err = pgxpool.NewWithConfig(ctx, testConfig)
	if err != nil {
		t.Fatal(err)
	}
	applyAllMigrations(t, ctx, testPool)
	// Correctness-critical service queries use the extended protocol; only the
	// multi-statement migration bootstrap above needs simple protocol.
	testPool.Close()
	testConfig.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeCacheStatement
	testPool, err = pgxpool.NewWithConfig(ctx, testConfig)
	if err != nil {
		t.Fatal(err)
	}

	prefix := "reference-" + randomHex(t, 6)
	runner := store.NewRunner(testPool)
	journal := ledger.NewService(runner, &referenceTestIDs{prefix: prefix})
	assetID, bookID := prefix+"-asset", prefix+"-book"
	debitID, creditID := prefix+"-debit", prefix+"-credit"
	if err := journal.RegisterAsset(ctx, ledger.Asset{
		AssetID: assetID, DisplayCode: strings.ToUpper(prefix), AtomicScale: 0,
	}); err != nil {
		t.Fatal(err)
	}
	if err := journal.CreateBook(ctx, ledger.Book{
		BookID: bookID, LegalEntityID: prefix + "-entity", Jurisdiction: "TEST",
	}); err != nil {
		t.Fatal(err)
	}
	for _, account := range []ledger.Account{
		{AccountID: debitID, BookID: bookID, AssetID: assetID,
			AccountType: "TEST", NormalSide: ledger.Debit},
		{AccountID: creditID, BookID: bookID, AssetID: assetID,
			AccountType: "TEST", NormalSide: ledger.Credit},
	} {
		if err := journal.CreateAccount(ctx, account); err != nil {
			t.Fatal(err)
		}
	}

	base := postReferenceFixture(t, ctx, journal, prefix+"-base", bookID,
		assetID, debitID, creditID, nil)
	_ = postReferenceFixture(t, ctx, journal, prefix+"-before-start", bookID,
		assetID, debitID, creditID, &base.TransactionID)

	workflow, err := schemamigration.NewWorkflow(runner, 1)
	if err != nil {
		t.Fatal(err)
	}
	started, err := workflow.Start(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if started.Phase != schemamigration.PhaseShadowing || started.ActiveGeneration != 1 || started.StateVersion != 1 {
		t.Fatalf("unexpected start state: %+v", started)
	}
	// Same command after an unknown COMMIT result resolves to the durable state.
	if replay, err := workflow.Start(ctx, 0); err != nil || replay != started {
		t.Fatalf("start replay is not idempotent: state=%+v err=%v", replay, err)
	}
	legacyRead, err := workflow.ReadReference(ctx, prefix+"-before-start-tx")
	if err != nil {
		t.Fatal(err)
	}
	if !legacyRead.Found || legacyRead.ReferenceID != base.TransactionID || legacyRead.ReadGeneration != 0 {
		t.Fatalf("pre-cutover reader did not use immutable legacy fact: %+v", legacyRead)
	}

	_ = postReferenceFixture(t, ctx, journal, prefix+"-after-start", bookID,
		assetID, debitID, creditID, &base.TransactionID)
	report, err := workflow.Backfill(ctx, started.ActiveGeneration, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Complete || report.Batches != 2 || report.ReferencesSeen != 1 {
		t.Fatalf("unexpected bounded backfill report: %+v", report)
	}

	verification, verified, err := workflow.Verify(ctx, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Phase != schemamigration.PhaseVerified || verification.SourceRows != 1 ||
		verification.ProjectedRows != 1 || verification.SourceDigest != verification.ProjectedDigest {
		t.Fatalf("unexpected verification: %+v status=%+v", verification, verified)
	}
	if replay, status, err := workflow.Verify(ctx, 1, 1); err != nil ||
		replay != verification || status != verified {
		t.Fatalf("verify replay is not idempotent: verification=%+v status=%+v err=%v",
			replay, status, err)
	}

	if err := workflow.RegisterConsumer(ctx, "payment-api-v2", true); err != nil {
		t.Fatal(err)
	}
	if err := workflow.RegisterConsumer(ctx, "offline-reporter", false); err != nil {
		t.Fatal(err)
	}
	cutover, err := workflow.Cutover(ctx, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if cutover.Phase != schemamigration.PhaseCutover || cutover.ReadGeneration != 1 {
		t.Fatalf("unexpected cutover state: %+v", cutover)
	}
	projectedRead, err := workflow.ReadReference(ctx, prefix+"-before-start-tx")
	if err != nil {
		t.Fatal(err)
	}
	if !projectedRead.Found || projectedRead.ReferenceID != base.TransactionID ||
		projectedRead.ReadGeneration != 1 {
		t.Fatalf("post-cutover reader did not use verified generation: %+v", projectedRead)
	}
	if _, err := workflow.Contract(ctx, 1, 3); !errors.Is(err, schemamigration.ErrContractBlocked) {
		t.Fatalf("contract must wait for required consumers, got %v", err)
	}
	if err := workflow.AcknowledgeConsumer(ctx, "payment-api-v2", 1); err != nil {
		t.Fatal(err)
	}
	contracted, err := workflow.Contract(ctx, 1, 3)
	if err != nil {
		t.Fatal(err)
	}
	if contracted.Phase != schemamigration.PhaseContracted || contracted.StateVersion != 4 {
		t.Fatalf("unexpected contract state: %+v", contracted)
	}
	if replay, err := workflow.Contract(ctx, 1, 3); err != nil || replay != contracted {
		t.Fatalf("contract replay is not idempotent: state=%+v err=%v", replay, err)
	}

	var projected int64
	if err := testPool.QueryRow(ctx, `
SELECT count(*) FROM ledger_transaction_references_shadow
WHERE reference_id=$1`, base.TransactionID).Scan(&projected); err != nil {
		t.Fatal(err)
	}
	if projected != 2 {
		t.Fatalf("expected one backfilled and one atomic dual-written reference, got %d", projected)
	}
	if _, err := testPool.Exec(ctx, `
UPDATE ledger_transaction_references_shadow SET reference_id='tampered'
WHERE reference_id=$1`, base.TransactionID); err == nil {
		t.Fatal("append-only projection accepted UPDATE")
	}
	var unchanged string
	if err := testPool.QueryRow(ctx, `
SELECT reference_transaction_id FROM ledger_transactions WHERE transaction_id=$1`,
		prefix+"-before-start-tx").Scan(&unchanged); err != nil {
		t.Fatal(err)
	}
	if unchanged != base.TransactionID {
		t.Fatalf("historical source fact was changed: %q", unchanged)
	}
}

func postReferenceFixture(t *testing.T, ctx context.Context, journal *ledger.Service,
	id, bookID, assetID, debitID, creditID string, reference *string) ledger.Receipt {
	t.Helper()
	requestHash := sha256.Sum256([]byte("reference-migration-test/v1\x00" + id))
	receipt, err := journal.Post(ctx, ledger.PostRequest{
		TransactionID: id + "-tx", BookID: bookID, OperationID: id + "-operation",
		EffectID: id + "-effect", Kind: "REFERENCE_TEST",
		ReferenceTransactionID: reference, PostingRuleVersion: "test-v1",
		SchemaVersion: 1, RequestHash: requestHash,
		Lines: []ledger.Line{
			{AccountID: debitID, AssetID: assetID, Side: ledger.Debit,
				AmountAtoms: ledger.NewAmountInt64(1)},
			{AccountID: creditID, AssetID: assetID, Side: ledger.Credit,
				AmountAtoms: ledger.NewAmountInt64(1)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func randomHex(t *testing.T, bytes int) string {
	t.Helper()
	raw := make([]byte, bytes)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(raw)
}

func applyAllMigrations(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("..", "..", "migrations", "*.sql"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		t.Fatal("no migrations found")
	}
	for _, path := range paths {
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, string(contents)); err != nil {
			t.Fatalf("apply %s: %v", filepath.Base(path), err)
		}
	}
}
