//go:build integration

package offline

import (
	"context"
	"crypto/sha256"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/example/payment-platform/internal/ledger"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestOfflineExpandContractRollout is intentionally an opt-in release test: it
// creates an isolated Cockroach database and invokes the production migrator
// at each exact target. Ordinary package integration tests use an already
// migrated database and must not pay this multi-minute cost.
func TestOfflineExpandContractRollout(t *testing.T) {
	if os.Getenv("RUN_OFFLINE_MIGRATION_ROLLOUT_TEST") != "1" {
		t.Skip("set RUN_OFFLINE_MIGRATION_ROLLOUT_TEST=1 for staged migration validation")
	}
	baseDSN := os.Getenv("DATABASE_URL")
	if baseDSN == "" {
		t.Skip("DATABASE_URL is not set")
	}
	ctx := context.Background()
	basePool, err := pgxpool.New(ctx, baseDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(basePool.Close)
	databaseName := "offline_rollout_" + integrationSuffix(t)
	databaseIdentifier := pgx.Identifier{databaseName}.Sanitize()
	if _, err := basePool.Exec(ctx, "CREATE DATABASE "+databaseIdentifier); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = basePool.Exec(context.Background(), "DROP DATABASE "+databaseIdentifier+" CASCADE")
	})
	scratchDSN := rolloutDatabaseURL(t, baseDSN, databaseName)
	repositoryRoot := rolloutRepositoryRoot(t)

	runOfflineMigrator(t, repositoryRoot, scratchDSN, "015_offline_presentations.sql")
	scratch, err := pgxpool.New(ctx, scratchDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(scratch.Close)
	insertLegacyOfflineReceipt(t, ctx, scratch, "after-015", "ledger_writer")
	insertLegacyOfflineProof(t, ctx, scratch, "after-015", "ledger_writer")
	var ignored bool
	err = scratch.QueryRow(ctx, `
SELECT public.configure_offline_acceptance_domain('new-writer-before-023','key',1,2)`).Scan(&ignored)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "unknown function") {
		t.Fatalf("new procedure-aware writer before 023 error=%v", err)
	}

	runOfflineMigrator(t, repositoryRoot, scratchDSN, "023_offline_authority_expand.sql")
	legacyRole := "old_offline_writer_" + integrationSuffix(t)
	legacyRoleIdentifier := pgx.Identifier{legacyRole}.Sanitize()
	if _, err := scratch.Exec(ctx, "CREATE ROLE "+legacyRoleIdentifier+" NOLOGIN"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = basePool.Exec(context.Background(),
			"REVOKE ledger_writer, offline_runtime FROM "+legacyRoleIdentifier)
		_, _ = basePool.Exec(context.Background(), "DROP ROLE "+legacyRoleIdentifier)
	})
	if _, err := scratch.Exec(ctx,
		"GRANT ledger_writer, offline_runtime TO "+legacyRoleIdentifier); err != nil {
		t.Fatal(err)
	}
	insertLegacyOfflineReceipt(t, ctx, scratch, "after-023", legacyRole)
	insertLegacyOfflineProof(t, ctx, scratch, "after-023", legacyRole)
	insertLegacyConfiguredDomain(t, ctx, scratch, "after-023")
	assertRawKeyHistoryDeniedBeforeContract(t, ctx, scratch)
	var missingInitialKeys int64
	if err := scratch.QueryRow(ctx, `
SELECT count(*)
FROM offline_acceptance_domains AS domain
WHERE NOT EXISTS (
 SELECT 1 FROM offline_acceptance_domain_key_activations AS activation
 WHERE activation.acceptance_domain=domain.acceptance_domain
   AND activation.key_id=domain.closure_key_id
   AND activation.activated_epoch=domain.first_settlement_epoch
)`).Scan(&missingInitialKeys); err != nil {
		t.Fatal(err)
	}
	if missingInitialKeys != 0 {
		t.Fatalf("legacy domain inserts missing %d initial key activations", missingInitialKeys)
	}

	// The current writer uses only 023 procedures and must work before raw
	// privileges are contracted by 024.
	t.Setenv("DATABASE_URL", scratchDSN)
	fixture := newIntegrationFixture(t, 40)
	toRedeem := fixture.issue(t, 10)
	verified := fixture.presentation(t, toRedeem)
	effect := RedemptionEffect{
		EffectID:            "rollout-redeem-" + toRedeem.AllowanceID,
		LedgerTransactionID: "rollout-redeem-tx-" + toRedeem.AllowanceID,
		PostingRequestHash:  sha256.Sum256([]byte("rollout-redeem")),
	}
	if _, err := fixture.service.RedeemAndPost(
		fixture.ctx, verified, fixture.journal, fixture.posting(toRedeem, effect),
	); err != nil {
		t.Fatalf("procedure writer before 024 redemption: %v", err)
	}
	toTerminate := fixture.issue(t, 10)
	if _, err := fixture.service.Terminate(
		fixture.ctx, fixture.fenceRequest(t, toTerminate, fixture.closureFor(t, toTerminate)),
	); err != nil {
		t.Fatalf("procedure writer before 024 termination: %v", err)
	}
	assertOfflineRolloutGates(t, ctx, scratch)

	runOfflineMigrator(t, repositoryRoot, scratchDSN, "024_offline_authority_contract.sql")
	if err := insertLegacyOfflineReceiptError(ctx, scratch, "after-024", legacyRole); err == nil {
		t.Fatal("old v1 writer unexpectedly inserted a receipt after 024")
	}
	var legacyRows int64
	if err := scratch.QueryRow(ctx, `
SELECT count(*) FROM offline_redemption_receipts
WHERE presentation_payload_hash IS NULL
  AND presentation_hash IS NULL
  AND merchant_challenge IS NULL`).Scan(&legacyRows); err != nil {
		t.Fatal(err)
	}
	if legacyRows != 2 {
		t.Fatalf("immutable legacy audit rows after contract=%d, want 2", legacyRows)
	}
	var legacyProofs int64
	if err := scratch.QueryRow(ctx, `
SELECT count(*) FROM offline_non_redemption_proofs
WHERE closure_set_hash IS NULL`).Scan(&legacyProofs); err != nil {
		t.Fatal(err)
	}
	if legacyProofs != 2 {
		t.Fatalf("immutable legacy non-redemption proofs after contract=%d, want 2", legacyProofs)
	}
	var ready bool
	if err := scratch.QueryRow(ctx,
		`SELECT public.assert_offline_authority_contract_ready()`).Scan(&ready); err != nil || !ready {
		t.Fatalf("offline contract postcondition ready=%t err=%v", ready, err)
	}
}

func insertLegacyOfflineReceipt(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	label, role string,
) {
	t.Helper()
	if err := insertLegacyOfflineReceiptError(ctx, pool, label, role); err != nil {
		t.Fatalf("legacy writer %s: %v", label, err)
	}
}

func insertLegacyOfflineReceiptError(
	ctx context.Context,
	pool *pgxpool.Pool,
	label, role string,
) error {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	assetID := "legacy-asset-" + label
	bookID := "legacy-book-" + label
	accountID := "legacy-account-" + label
	merchantID := "legacy-merchant-" + label
	region := "legacy-region-" + label
	domain := "legacy-domain-" + label
	allowanceID := "legacy-allowance-" + label
	transactionID := "legacy-tx-" + label
	effectID := "legacy-effect-" + label
	deviceHash := sha256.Sum256([]byte("legacy-device-" + label))
	requestHash := sha256.Sum256([]byte("legacy-request-" + label))
	entryHash := sha256.Sum256([]byte("legacy-entry-" + label))
	effectHash := sha256.Sum256([]byte("legacy-effect-hash-" + label))
	statements := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO assets (asset_id,display_code,atomic_scale) VALUES ($1,$2,0)`,
			[]any{assetID, "LEGACY-" + label}},
		{`INSERT INTO books (book_id,legal_entity_id,jurisdiction,last_entry_hash)
 VALUES ($1,'legacy-entity','KZ',$2)`, []any{bookID, make([]byte, 32)}},
		{`INSERT INTO accounts (account_id,book_id,asset_id,account_type,normal_side)
 VALUES ($1,$3,$4,'CUSTOMER','CREDIT'),($2,$3,$4,'MERCHANT','CREDIT')`,
			[]any{accountID, merchantID, bookID, assetID}},
		{`INSERT INTO ledger_transactions
 (transaction_id,book_id,operation_id,effect_id,transaction_kind,
  posting_rule_version,schema_version,request_hash,status,sequence_no,prev_hash,entry_hash)
 VALUES ($1,$2,$3,$4,'OFFLINE_REDEMPTION','legacy/v1',1,$5,'DRAFT',1,$6,$7)`,
			[]any{transactionID, bookID, "legacy-operation-" + label, effectID,
				requestHash[:], make([]byte, 32), entryHash[:]}},
		{`INSERT INTO ledger_lines
 (transaction_id,line_no,account_id,asset_id,side,amount_atoms)
 VALUES ($1,1,$2,$4,'DEBIT',10),($1,2,$3,$4,'CREDIT',10)`,
			[]any{transactionID, accountID, merchantID, assetID}},
		{`SELECT public.finalize_ledger_transaction($1)`, []any{transactionID}},
		{`INSERT INTO escrow_authorities (account_id,asset_id,total_authority,unallocated)
 VALUES ($1,$2,10,0)`, []any{accountID, assetID}},
		{`INSERT INTO escrow_regional_rights (account_id,asset_id,region,available)
 VALUES ($1,$2,$3,0)`, []any{accountID, assetID, region}},
		{`INSERT INTO offline_acceptance_domains
 (acceptance_domain,closure_key_id,first_settlement_epoch,last_settlement_epoch)
 VALUES ($1,$2,1,4)`, []any{domain, "legacy-closure-key-" + label}},
	}
	for _, statement := range statements {
		if _, err = tx.Exec(ctx, statement.sql, statement.args...); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{role}.Sanitize()); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `
INSERT INTO offline_device_counters
 (account_id,asset_id,origin_region,device_identity_hash,issuer_epoch,last_counter)
VALUES ($1,$2,$3,$4,1,1)`, accountID, assetID, region, deviceHash[:]); err != nil {
		return err
	}
	allowance := Allowance{
		Version: AllowanceVersion, AllowanceID: allowanceID,
		AccountID: accountID, AssetID: assetID, OriginRegion: region,
		DeviceIdentityHash: deviceHash, Counter: 1,
		Amount: ledgerAmountTen(), IssuerEpoch: 1, KeyID: "legacy-issuer-key-" + label,
	}
	payload, err := allowance.CanonicalPayload()
	if err != nil {
		return err
	}
	payloadHash := sha256.Sum256(payload)
	if _, err = tx.Exec(ctx, `
INSERT INTO offline_allowances
 (allowance_id,account_id,asset_id,origin_region,device_identity_hash,
  device_counter,amount,issuer_epoch,key_id,canonical_payload,payload_hash)
 VALUES ($1,$2,$3,$4,$5,1,10,1,$6,$7,$8);
UPDATE offline_allowances
 SET signature=$9,state='ISSUED',issued_at=transaction_timestamp()
 WHERE allowance_id=$1;
INSERT INTO escrow_offline_issued (account_id,asset_id,origin_region,amount)
 VALUES ($2,$3,$4,10);
INSERT INTO offline_redemption_receipts
 (allowance_id,payload_hash,effect_hash,effect_id,ledger_transaction_id,
  posting_request_hash)
 VALUES ($1,$8,$10,$11,$12,$13)`, allowanceID, accountID, assetID, region,
		deviceHash[:], allowance.KeyID, payload, payloadHash[:], []byte("legacy-signature"),
		effectHash[:], effectID, transactionID, requestHash[:]); err != nil {
		return err
	}
	for _, update := range []struct {
		sql  string
		args []any
	}{
		{`UPDATE escrow_offline_issued
 SET amount=amount-10,version=version+1,updated_at=transaction_timestamp()
 WHERE account_id=$1 AND asset_id=$2 AND origin_region=$3 AND amount>=10`,
			[]any{accountID, assetID, region}},
		{`UPDATE escrow_authorities
 SET total_authority=total_authority-10,version=version+1
 WHERE account_id=$1 AND asset_id=$2 AND total_authority>=10`,
			[]any{accountID, assetID}},
		{`UPDATE offline_allowances
 SET state='REDEEMED',redeemed_at=transaction_timestamp()
 WHERE allowance_id=$1 AND state='ISSUED'`, []any{allowanceID}},
	} {
		if _, err = tx.Exec(ctx, update.sql, update.args...); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func insertLegacyOfflineProof(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	label, role string,
) {
	t.Helper()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	assetID := "legacy-proof-asset-" + label
	bookID := "legacy-proof-book-" + label
	accountID := "legacy-proof-account-" + label
	region := "legacy-proof-region-" + label
	domain := "legacy-proof-domain-" + label
	allowanceID := "legacy-proof-allowance-" + label
	deviceHash := sha256.Sum256([]byte("legacy-proof-device-" + label))
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO assets (asset_id,display_code,atomic_scale) VALUES ($1,$2,0)`,
			[]any{assetID, "LEGACY-PROOF-" + label}},
		{`INSERT INTO books (book_id,legal_entity_id,jurisdiction,last_entry_hash)
 VALUES ($1,'legacy-proof-entity','KZ',$2)`, []any{bookID, make([]byte, 32)}},
		{`INSERT INTO accounts (account_id,book_id,asset_id,account_type,normal_side)
 VALUES ($1,$2,$3,'CUSTOMER','CREDIT')`, []any{accountID, bookID, assetID}},
		{`INSERT INTO escrow_authorities (account_id,asset_id,total_authority,unallocated)
 VALUES ($1,$2,10,0)`, []any{accountID, assetID}},
		{`INSERT INTO escrow_regional_rights (account_id,asset_id,region,available)
 VALUES ($1,$2,$3,0)`, []any{accountID, assetID, region}},
		{`INSERT INTO offline_acceptance_domains
 (acceptance_domain,closure_key_id,first_settlement_epoch,last_settlement_epoch)
 VALUES ($1,$2,1,4)`, []any{domain, "legacy-proof-closure-key-" + label}},
	} {
		if _, err = tx.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{role}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `
INSERT INTO offline_device_counters
 (account_id,asset_id,origin_region,device_identity_hash,issuer_epoch,last_counter)
VALUES ($1,$2,$3,$4,1,1)`, accountID, assetID, region, deviceHash[:]); err != nil {
		t.Fatal(err)
	}
	allowance := Allowance{
		Version: AllowanceVersion, AllowanceID: allowanceID,
		AccountID: accountID, AssetID: assetID, OriginRegion: region,
		DeviceIdentityHash: deviceHash, Counter: 1,
		Amount: ledgerAmountTen(), IssuerEpoch: 1,
		KeyID: "legacy-proof-issuer-key-" + label,
	}
	payload, err := allowance.CanonicalPayload()
	if err != nil {
		t.Fatal(err)
	}
	payloadHash := sha256.Sum256(payload)
	if _, err = tx.Exec(ctx, `
INSERT INTO offline_allowances
 (allowance_id,account_id,asset_id,origin_region,device_identity_hash,
  device_counter,amount,issuer_epoch,key_id,canonical_payload,payload_hash)
VALUES ($1,$2,$3,$4,$5,1,10,1,$6,$7,$8)`, allowanceID, accountID,
		assetID, region, deviceHash[:], allowance.KeyID, payload, payloadHash[:]); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `
UPDATE offline_allowances
 SET signature=$2,state='ISSUED',issued_at=transaction_timestamp()
 WHERE allowance_id=$1`, allowanceID, []byte("legacy-proof-signature")); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `
INSERT INTO escrow_offline_issued (account_id,asset_id,origin_region,amount)
VALUES ($1,$2,$3,10)`, accountID, assetID, region); err != nil {
		t.Fatal(err)
	}
	for _, update := range []struct {
		sql  string
		args []any
	}{
		{`UPDATE offline_device_counters SET fence_version=1
 WHERE account_id=$1 AND asset_id=$2 AND origin_region=$3
   AND device_identity_hash=$4`, []any{accountID, assetID, region, deviceHash[:]}},
		{`UPDATE escrow_offline_issued SET amount=0,version=version+1
 WHERE account_id=$1 AND asset_id=$2 AND origin_region=$3`,
			[]any{accountID, assetID, region}},
		{`UPDATE escrow_regional_rights SET available=10,version=version+1
 WHERE account_id=$1 AND asset_id=$2 AND region=$3`,
			[]any{accountID, assetID, region}},
		{`UPDATE offline_allowances
 SET state='REVOKED',terminal_at=transaction_timestamp()
 WHERE allowance_id=$1`, []any{allowanceID}},
	} {
		if _, err = tx.Exec(ctx, update.sql, update.args...); err != nil {
			t.Fatal(err)
		}
	}
	policyHash := sha256.Sum256([]byte("legacy-proof-policy-" + label))
	proofHash := sha256.Sum256([]byte("legacy-proof-hash-" + label))
	if _, err = tx.Exec(ctx, `
INSERT INTO offline_non_redemption_proofs
 (allowance_id,terminal_kind,payload_hash,issuer_epoch,device_counter,
  fence_version,policy_evidence_hash,proof_hash)
VALUES ($1,'REVOKED',$2,1,1,1,$3,$4)`, allowanceID, payloadHash[:],
		policyHash[:], proofHash[:]); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func assertOfflineRolloutGates(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	var partial, missing, overlaps int64
	if err := pool.QueryRow(ctx, `
SELECT
 (SELECT count(*) FROM offline_redemption_receipts
   WHERE (presentation_payload_hash IS NOT NULL OR presentation_hash IS NOT NULL)
     AND (presentation_payload_hash IS NULL OR presentation_hash IS NULL
          OR merchant_challenge IS NULL OR presentation_payload IS NULL
          OR presentation_signature IS NULL)),
 (SELECT count(*) FROM offline_acceptance_domains AS domain
   WHERE NOT EXISTS (
    SELECT 1 FROM offline_acceptance_domain_key_activations AS activation
    WHERE activation.acceptance_domain=domain.acceptance_domain
      AND activation.key_id=domain.closure_key_id
      AND activation.activated_epoch=domain.first_settlement_epoch)),
 (SELECT count(*)
  FROM offline_acceptance_domain_key_activations AS left_key
  JOIN offline_acceptance_domain_key_activations AS right_key
    ON right_key.acceptance_domain=left_key.acceptance_domain
   AND right_key.activated_epoch>left_key.activated_epoch
  LEFT JOIN offline_acceptance_domain_key_terminations AS left_end
    ON left_end.acceptance_domain=left_key.acceptance_domain
   AND left_end.key_id=left_key.key_id
  WHERE left_end.terminated_epoch IS NULL
     OR left_end.terminated_epoch>right_key.activated_epoch)`).Scan(
		&partial, &missing, &overlaps); err != nil {
		t.Fatal(err)
	}
	if partial != 0 || missing != 0 || overlaps != 0 {
		t.Fatalf("offline rollout gates partial=%d missing=%d overlaps=%d",
			partial, missing, overlaps)
	}
}

func assertRawKeyHistoryDeniedBeforeContract(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
) {
	t.Helper()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE offline_configuration_runtime`); err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `
INSERT INTO offline_acceptance_domain_key_activations
 (acceptance_domain,key_id,activated_epoch)
VALUES ('raw-key-history-must-fail','raw-key-history-must-fail',1)`)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "permission") {
		t.Fatalf("raw key-history insert before contract error=%v", err)
	}
}

func insertLegacyConfiguredDomain(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	label string,
) {
	t.Helper()
	domain := "legacy-config-domain-" + label
	keyID := "legacy-config-key-" + label
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE offline_configuration_runtime`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO offline_acceptance_domains
 (acceptance_domain,closure_key_id,first_settlement_epoch,last_settlement_epoch)
VALUES ($1,$2,1,4)`, domain, keyID); err != nil {
		t.Fatalf("legacy domain writer after 023: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var exact int64
	if err := pool.QueryRow(ctx, `
SELECT count(*) FROM offline_acceptance_domain_key_activations
WHERE acceptance_domain=$1 AND key_id=$2 AND activated_epoch=1`,
		domain, keyID).Scan(&exact); err != nil {
		t.Fatal(err)
	}
	if exact != 1 {
		t.Fatalf("legacy domain bootstrap activation=%d, want 1", exact)
	}
}

func runOfflineMigrator(t *testing.T, repositoryRoot, dsn, target string) {
	t.Helper()
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(goBinary, "run", "./cmd/schema-migrator")
	command.Dir = repositoryRoot
	command.Env = append(os.Environ(),
		"DATABASE_URL="+dsn,
		"MIGRATIONS_DIR="+filepath.Join(repositoryRoot, "migrations"),
		"MIGRATION_TARGET_VERSION="+target,
		"MIGRATION_APPLY_ALL_ACK=",
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("migrator target %s: %v\n%s", target, err, output)
	}
}

func rolloutRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}

func rolloutDatabaseURL(t *testing.T, dsn, databaseName string) string {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	parsed.Path = "/" + databaseName
	return parsed.String()
}

func ledgerAmountTen() ledger.Amount { return ledger.NewAmountInt64(10) }
