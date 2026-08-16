//go:build integration

package dbroles

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/example/payment-platform/internal/authz"
	"github.com/example/payment-platform/internal/escrow"
	"github.com/example/payment-platform/internal/idempotency"
	"github.com/example/payment-platform/internal/idgen"
	"github.com/example/payment-platform/internal/ledger"
	"github.com/example/payment-platform/internal/payment"
	"github.com/example/payment-platform/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type fixtureIDs struct {
	prefix string
	next   int64
}

func (ids *fixtureIDs) Next(context.Context) (string, error) {
	ids.next++
	return fmt.Sprintf("%s-%d", ids.prefix, ids.next), nil
}

func TestPaymentCredentialUsesComposedCapabilitiesWithoutCrossProtocolAccess(t *testing.T) {
	ctx, root := rootPool(t)
	suffix := fmt.Sprintf("lp-%d", time.Now().UnixNano())
	assetID, bookID := "asset-"+suffix, "book-"+suffix
	availableID, heldID := "available-"+suffix, "held-"+suffix
	merchantID, fundingID := "merchant-"+suffix, "funding-"+suffix
	wrongFeeID := "wrong-fee-" + suffix
	region, issuer := "region-a", "issuer-"+suffix
	principal := "spiffe://payments.test/merchant/" + suffix

	fixtureGenerator := &fixtureIDs{prefix: suffix}
	fixtureLedger := ledger.NewService(store.NewRunner(root), fixtureGenerator)
	if err := fixtureLedger.RegisterAsset(ctx, ledger.Asset{
		AssetID: assetID, DisplayCode: "LP-" + suffix, AtomicScale: 0,
	}); err != nil {
		t.Fatal(err)
	}
	if err := fixtureLedger.CreateBook(ctx, ledger.Book{
		BookID: bookID, LegalEntityID: "entity", Jurisdiction: "KZ",
	}); err != nil {
		t.Fatal(err)
	}
	for _, account := range []ledger.Account{
		{AccountID: availableID, BookID: bookID, AssetID: assetID, AccountType: "CUSTOMER_AVAILABLE", NormalSide: ledger.Credit, EnforceSpendLimit: true},
		{AccountID: heldID, BookID: bookID, AssetID: assetID, AccountType: "CUSTOMER_HELD", NormalSide: ledger.Credit, EnforceSpendLimit: true},
		{AccountID: merchantID, BookID: bookID, AssetID: assetID, AccountType: "MERCHANT", NormalSide: ledger.Credit},
		{AccountID: fundingID, BookID: bookID, AssetID: assetID, AccountType: "CASH", NormalSide: ledger.Debit},
		{AccountID: wrongFeeID, BookID: bookID, AssetID: assetID, AccountType: "FEE_REVENUE", NormalSide: ledger.Credit},
	} {
		if err := fixtureLedger.CreateAccount(ctx, account); err != nil {
			t.Fatal(err)
		}
	}
	fundingHash := sha256.Sum256([]byte("least-privilege-fixture"))
	if _, err := fixtureLedger.Post(ctx, ledger.PostRequest{
		TransactionID: "fund-transaction-" + suffix,
		BookID:        bookID,
		OperationID:   "fund-operation-" + suffix,
		EffectID:      "fund-effect-" + suffix,
		Kind:          "DEPOSIT", PostingRuleVersion: "fixture-v1", SchemaVersion: 1,
		RequestHash: fundingHash,
		Lines: []ledger.Line{
			{AccountID: fundingID, AssetID: assetID, Side: ledger.Debit, AmountAtoms: ledger.NewAmountInt64(50)},
			{AccountID: availableID, AssetID: assetID, Side: ledger.Credit, AmountAtoms: ledger.NewAmountInt64(50)},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := root.Exec(ctx, `
INSERT INTO escrow_authorities (account_id, asset_id, total_authority, unallocated)
VALUES ($1,$2,50,0)`, availableID, assetID); err != nil {
		t.Fatal(err)
	}
	if _, err := root.Exec(ctx, `
INSERT INTO escrow_regional_rights (account_id, asset_id, region, available)
VALUES ($1,$2,$3,50)`, availableID, assetID, region); err != nil {
		t.Fatal(err)
	}
	if _, err := root.Exec(ctx, `
INSERT INTO id_issuers (issuer_prefix, incarnation) VALUES ($1,1)`, issuer); err != nil {
		t.Fatal(err)
	}
	for index, capability := range []struct {
		accountID  string
		permission string
	}{
		{availableID, authz.AuthorizePayerAvailable},
		{heldID, authz.AuthorizePayerHeld},
		{merchantID, authz.AuthorizeMerchant},
		// Deliberately wrong for this account type. A CAPTURE fee must require
		// CAPTURE_FEE; CAPTURE_TAX must not authorize a FEE_REVENUE credit.
		{wrongFeeID, authz.CaptureTax},
	} {
		if _, err := root.Exec(ctx, `
INSERT INTO payment_account_capabilities
 (capability_id, principal_id, book_id, account_id, permission,
  policy_version, granted_by, evidence_hash)
VALUES ($1,$2,$3,$4,$5,'policy-v1','test-admin',$6)`,
			fmt.Sprintf("capability-%d-%s", index, suffix), principal, bookID,
			capability.accountID, capability.permission, make([]byte, 32)); err != nil {
			t.Fatal(err)
		}
	}

	roleName := "payment_api_test_" + fmt.Sprintf("%d", time.Now().UnixNano())
	roleIdentifier := pgx.Identifier{roleName}.Sanitize()
	if _, err := root.Exec(ctx, "CREATE USER "+roleIdentifier); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = root.Exec(context.Background(), "DROP USER "+roleIdentifier) })
	if _, err := root.Exec(ctx, `GRANT payment_journal_runtime, payment_runtime,
payment_escrow_runtime, idempotency_runtime, outbox_enqueue_runtime,
id_allocator, payment_authorizer TO `+roleIdentifier); err != nil {
		t.Fatal(err)
	}

	restricted := loginPool(t, root.Config().ConnString(), roleName)
	generator, err := idgen.New(restricted, issuer, 8)
	if err != nil {
		t.Fatal(err)
	}
	if generated, err := generator.Next(ctx); err != nil || generated == "" {
		t.Fatalf("id_allocator capability failed: id=%q err=%v", generated, err)
	}
	authorizer, err := authz.New(restricted)
	if err != nil {
		t.Fatal(err)
	}
	if err := authorizer.Authorize(ctx, authz.Request{
		Principal: principal, BookID: bookID,
		Accounts: []authz.AccountPermission{{
			AccountID: availableID, Permission: authz.AuthorizePayerAvailable,
		}},
	}); err != nil {
		t.Fatalf("payment_authorizer capability failed: %v", err)
	}

	runner := store.NewRunner(restricted)
	runner.MaxAttempts = 20
	journal := ledger.NewService(runner, generator)
	payments := payment.NewService(runner, journal, idempotency.NewService(generator), generator)
	request := payment.HoldRequest{
		Scope: "principal/" + principal, IdempotencyKey: "hold", BookID: bookID, AssetID: assetID,
		CustomerAvailableAccountID: availableID, CustomerHeldAccountID: heldID,
		MerchantAccountID: merchantID, AuthorityRegion: region,
		Amount: ledger.NewAmountInt64(10), PostingRuleVersion: "payment-v1",
	}
	first, err := payments.Hold(ctx, request)
	if err != nil {
		t.Fatalf("composed payment credential failed valid hold: %v", err)
	}
	replayed, err := payments.Hold(ctx, request)
	if err != nil || !replayed.Duplicate || replayed.Ledger.TransactionID != first.Ledger.TransactionID {
		t.Fatalf("idempotent payment replay=%#v err=%v", replayed, err)
	}

	if _, err := payments.Capture(ctx, payment.CaptureRequest{
		Scope: "principal/" + principal, IdempotencyKey: "wrong-fee-permission",
		PaymentID: first.PaymentID, BookID: bookID, AssetID: assetID,
		Amount: ledger.NewAmountInt64(1), Fee: ledger.NewAmountInt64(1),
		FeeAccountID: wrongFeeID, PostingRuleVersion: "payment-v1",
	}); err == nil {
		t.Fatal("CAPTURE accepted CAPTURE_TAX capability for a FEE_REVENUE account")
	}
	var captureEffects, capturedAtoms int64
	if err := root.QueryRow(ctx, `
SELECT (SELECT count(*) FROM payment_effects
         WHERE payment_id=$1 AND effect_kind='CAPTURE'),
       captured_atoms::INT8
  FROM payment_operations WHERE payment_id=$1`, first.PaymentID).Scan(
		&captureEffects, &capturedAtoms); err != nil {
		t.Fatal(err)
	}
	if captureEffects != 0 || capturedAtoms != 0 {
		t.Fatalf("rejected CAPTURE was not atomic: effects=%d captured=%d",
			captureEffects, capturedAtoms)
	}

	tx, err := restricted.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := escrow.PaymentSpendInTx(ctx, tx, escrow.EffectRequest{
		EffectID: first.Ledger.EffectID, AccountID: availableID, AssetID: assetID,
		Region: region, Amount: ledger.NewAmountInt64(10),
	})
	if err != nil || !duplicate.Duplicate {
		_ = tx.Rollback(ctx)
		t.Fatalf("payment escrow procedure retry=%#v err=%v", duplicate, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	conflictTx, err := restricted.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatal(err)
	}
	_, err = escrow.PaymentSpendInTx(ctx, conflictTx, escrow.EffectRequest{
		EffectID: first.Ledger.EffectID, AccountID: availableID, AssetID: assetID,
		Region: region, Amount: ledger.NewAmountInt64(11),
	})
	_ = conflictTx.Rollback(ctx)
	if !errors.Is(err, escrow.ErrEffectConflict) {
		t.Fatalf("effect ID substitution error=%v, want ErrEffectConflict", err)
	}

	var available, total string
	var receipts int
	if err := root.QueryRow(ctx, `
SELECT rights.available::STRING, authority.total_authority::STRING,
       (SELECT count(*) FROM escrow_effect_receipts WHERE effect_id=$4)
FROM escrow_regional_rights AS rights
JOIN escrow_authorities AS authority USING (account_id, asset_id)
WHERE rights.account_id=$1 AND rights.asset_id=$2 AND rights.region=$3`,
		availableID, assetID, region, first.Ledger.EffectID).Scan(
		&available, &total, &receipts); err != nil {
		t.Fatal(err)
	}
	if available != "40" || total != "40" || receipts != 1 {
		t.Fatalf("escrow applied more than once: available=%s total=%s receipts=%d",
			available, total, receipts)
	}

	// EXECUTE alone is not a mint primitive: a fresh RETURN without its exact
	// immutable payment effect and ledger credit must fail.
	forged, err := restricted.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatal(err)
	}
	_, err = escrow.PaymentReturnInTx(ctx, forged, escrow.EffectRequest{
		EffectID: "forged-return-" + suffix, AccountID: availableID,
		AssetID: assetID, Region: region, Amount: ledger.NewAmountInt64(10),
	})
	_ = forged.Rollback(ctx)
	if err == nil {
		t.Fatal("unlinked payment escrow RETURN was accepted")
	}

	forgedHash := sha256.Sum256([]byte("forged-composed-return/" + suffix))
	_, err = ledger.NewService(store.NewRunner(restricted), generator).Post(ctx, ledger.PostRequest{
		TransactionID: "forged-transaction-" + suffix,
		BookID:        bookID,
		OperationID:   "forged-operation-" + suffix,
		EffectID:      "forged-effect-" + suffix,
		Kind:          "REFUND", PostingRuleVersion: "forged-v1", SchemaVersion: 1,
		RequestHash: forgedHash,
		Lines: []ledger.Line{
			{AccountID: fundingID, AssetID: assetID, Side: ledger.Debit, AmountAtoms: ledger.NewAmountInt64(10)},
			{AccountID: availableID, AssetID: assetID, Side: ledger.Credit, AmountAtoms: ledger.NewAmountInt64(10)},
		},
	})
	if !isPermissionDenied(err) {
		t.Fatalf("composed payment credential generic finalizer error=%v, want SQLSTATE 42501", err)
	}

	for name, statement := range map[string]string{
		"raw authority update": `UPDATE escrow_authorities SET total_authority=999 WHERE account_id='` + availableID + `'`,
		"raw escrow receipt":   `INSERT INTO escrow_effect_receipts (effect_id,effect_kind,account_id,asset_id,region,amount,request_hash) VALUES ('forged','RETURN','` + availableID + `','` + assetID + `','` + region + `',1,decode(repeat('00',32),'hex'))`,
		"raw payment effect":   `INSERT INTO payment_effects (payment_effect_id,payment_id,effect_kind,amount_atoms,ledger_transaction_id) VALUES ('forged','` + first.PaymentID + `','REFUND',1,'` + first.Ledger.TransactionID + `')`,
		"transfer read":        `SELECT transfer_id FROM escrow_transfers LIMIT 0`,
		"offline read":         `SELECT allowance_id FROM offline_allowances LIMIT 0`,
		"saga read":            `SELECT saga_id FROM saga_instances LIMIT 0`,
		"rail read":            `SELECT operation_id FROM external_attempts LIMIT 0`,
		"fx read":              `SELECT quote_id FROM fx_quotes LIMIT 0`,
		"outbox publish":       `UPDATE outbox_messages SET status='PUBLISHED' WHERE false`,
	} {
		assertPermissionDenied(t, ctx, restricted, name, statement)
	}
}

func TestRuntimeCapabilityRolesCannotCrossProtocolTables(t *testing.T) {
	ctx, root := rootPool(t)
	tests := []struct {
		role, allowed, denied string
	}{
		{"ledger_writer", `SELECT book_id FROM books LIMIT 0`, `SELECT payment_id FROM payment_operations LIMIT 0`},
		{"payment_journal_runtime", `SELECT book_id FROM books LIMIT 0`, `SELECT public.finalize_ledger_transaction('missing')`},
		{"payment_runtime", `SELECT payment_id FROM payment_operations LIMIT 0`, `SELECT saga_id FROM saga_instances LIMIT 0`},
		{"cashback_repair_runtime", `SELECT repair_id FROM cashback_repair_manifests LIMIT 0`, `SELECT public.apply_payment_escrow_effect('missing','RETURN','missing','missing','missing',1,decode(repeat('00',32),'hex'))`},
		{"idempotency_runtime", `SELECT scope FROM idempotency_records LIMIT 0`, `SELECT event_id FROM outbox_messages LIMIT 0`},
		{"fx_runtime", `SELECT quote_id FROM fx_quotes LIMIT 0`, `SELECT payment_id FROM payment_operations LIMIT 0`},
		{"escrow_transfer_runtime", `SELECT transfer_id FROM escrow_transfers LIMIT 0`, `SELECT allowance_id FROM offline_allowances LIMIT 0`},
		{"offline_runtime", `SELECT allowance_id FROM offline_allowances LIMIT 0`, `SELECT transfer_id FROM escrow_transfers LIMIT 0`},
		{"offline_configuration_runtime", `SELECT acceptance_domain FROM offline_acceptance_domains LIMIT 0`, `SELECT allowance_id FROM offline_allowances LIMIT 0`},
		{"transport_inbox_runtime", `SELECT message_id FROM transport_inbox_messages LIMIT 0`, `SELECT saga_id FROM saga_instances LIMIT 0`},
		{"saga_runtime", `SELECT saga_id FROM saga_instances LIMIT 0`, `SELECT operation_id FROM external_attempts LIMIT 0`},
		{"rail_runtime", `SELECT operation_id FROM external_attempts LIMIT 0`, `SELECT message_id FROM transport_inbox_messages LIMIT 0`},
	}
	for _, test := range tests {
		t.Run(test.role, func(t *testing.T) {
			tx, err := root.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{test.role}.Sanitize()); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, test.allowed); err != nil {
				t.Fatalf("allowed query failed: %v", err)
			}
			if _, err := tx.Exec(ctx, test.denied); !isPermissionDenied(err) {
				t.Fatalf("cross-protocol query error=%v, want SQLSTATE 42501", err)
			}
		})
	}
}

func rootPool(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return ctx, pool
}

func rolePool(t *testing.T, dsn, roleIdentifier string) *pgxpool.Pool {
	t.Helper()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.MaxConns = 4
	config.AfterConnect = func(ctx context.Context, connection *pgx.Conn) error {
		_, err := connection.Exec(ctx, "SET ROLE "+roleIdentifier)
		return err
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func loginPool(t *testing.T, dsn, user string) *pgxpool.Pool {
	t.Helper()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.MaxConns = 4
	config.ConnConfig.User = user
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func assertPermissionDenied(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	name, statement string,
) {
	t.Helper()
	_, err := pool.Exec(ctx, statement)
	if !isPermissionDenied(err) {
		t.Fatalf("%s error=%v, want SQLSTATE 42501", name, err)
	}
}

func isPermissionDenied(err error) bool {
	var pgErr *pgconn.PgError
	return err != nil && errors.As(err, &pgErr) && pgErr.Code == "42501"
}
