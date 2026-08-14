//go:build integration

package escrow

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/example/payment-platform/internal/ledger"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRightsTransferLostAckAndDuplicateCertificate(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL is not set; CockroachDB integration test skipped")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	receiptPublicKey, receiptPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	suffix := integrationSuffix(t)
	signer := Ed25519Signer{KeyID: "key-" + suffix, PrivateKey: privateKey,
		Region: "A", LegalEntityID: "entity-a", Epoch: 1}
	receiptSigner := Ed25519ReceiptSigner{
		KeyID: "receipt-key-" + suffix, PrivateKey: receiptPrivateKey,
		Region: "B", LegalEntityID: "entity-b", Epoch: 3,
	}
	registry := StaticKeyRegistry{
		signer.KeyID:        {Binding: signer.Binding(), PublicKey: publicKey},
		receiptSigner.KeyID: {Binding: receiptSigner.Binding(), PublicKey: receiptPublicKey},
	}
	source := NewTransferService(pool, signer, nil, registry)
	destination := NewTransferService(pool, nil, receiptSigner, registry)
	accountID, assetID := "escrow-account-"+suffix, "escrow-asset-"+suffix
	if err := source.CreateAuthority(ctx, accountID, assetID, ledger.NewAmountInt64(100)); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Allocate(ctx, EffectRequest{
		EffectID: "allocate-" + suffix, AccountID: accountID, AssetID: assetID,
		Region: "A", Amount: ledger.NewAmountInt64(100),
	}); err != nil {
		t.Fatal(err)
	}
	request := TransferRequest{
		TransferID: "transfer-" + suffix, AccountID: accountID, AssetID: assetID,
		SourceRegion: "A", DestinationRegion: "B", SourceLegalEntityID: "entity-a",
		DestinationLegalEntityID: "entity-b", Amount: ledger.NewAmountInt64(40),
	}
	certificate, err := source.InitiateTransfer(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	// A source certificate is not an ACK.  Without destination consumption
	// proof, closing in-transit authority would destroy spending authority.
	if err := source.AcknowledgeTransfer(ctx, certificate, ConsumptionReceipt{}); !errors.Is(err, ErrConsumptionProofMissing) {
		t.Fatalf("ack without consumption proof = %v", err)
	}
	first, err := destination.ConsumeCertificate(ctx, certificate, "B")
	if err != nil || first.Duplicate {
		t.Fatalf("first consumption = %#v, %v", first, err)
	}
	// Simulate lost ACK by retrying the exact certificate.  Permanent receipt
	// deduplication must make this a no-op.
	second, err := destination.ConsumeCertificate(ctx, certificate, "B")
	if err != nil || !second.Duplicate {
		t.Fatalf("duplicate consumption = %#v, %v", second, err)
	}
	firstPayload, firstPayloadErr := first.Receipt.Payload()
	secondPayload, secondPayloadErr := second.Receipt.Payload()
	if firstPayloadErr != nil || secondPayloadErr != nil ||
		!bytes.Equal(firstPayload, secondPayload) ||
		!bytes.Equal(second.Receipt.Signature, first.Receipt.Signature) {
		t.Fatal("duplicate consumption returned a different durable receipt")
	}
	tamperedReceipt := first.Receipt
	tamperedReceipt.DestinationCommitWatermark++
	if err := source.AcknowledgeTransfer(ctx, certificate, tamperedReceipt); !errors.Is(err, ErrConsumptionReceiptInvalid) {
		t.Fatalf("tampered receipt ACK = %v", err)
	}
	preACK, err := source.Snapshot(ctx, accountID, assetID)
	if err != nil {
		t.Fatal(err)
	}
	if !preACK.Conserved() || preACK.InTransit.String() != "40" {
		t.Fatalf("rejected receipt changed source authority: %#v", preACK)
	}
	if err := source.AcknowledgeTransfer(ctx, certificate, first.Receipt); err != nil {
		t.Fatalf("ack with proof: %v", err)
	}
	if err := source.AcknowledgeTransfer(ctx, certificate, first.Receipt); err != nil {
		t.Fatalf("duplicate signed ACK: %v", err)
	}
	snapshot, err := source.Snapshot(ctx, accountID, assetID)
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.Conserved() || snapshot.RegionalRights["A"].String() != "60" ||
		snapshot.RegionalRights["B"].String() != "40" || !snapshot.InTransit.IsZero() {
		t.Fatalf("rights were created or lost: %#v", snapshot)
	}
	if _, err := pool.Exec(ctx, `
UPDATE escrow_consumed_certificates SET amount=amount+1 WHERE transfer_id=$1`,
		certificate.TransferID); err == nil {
		t.Fatal("database allowed mutation of a consumed certificate")
	}
}

func TestDestinationDeduplicatesImmutableSourceIssuanceTuple(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL is not set; CockroachDB integration test skipped")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	suffix := integrationSuffix(t)
	sourcePublic, sourcePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	destinationPublic, destinationPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sourceSigner := Ed25519Signer{
		KeyID: "tuple-source-" + suffix, PrivateKey: sourcePrivate,
		Region: "A", LegalEntityID: "entity-a", Epoch: 5,
	}
	destinationSigner := Ed25519ReceiptSigner{
		KeyID: "tuple-destination-" + suffix, PrivateKey: destinationPrivate,
		Region: "B", LegalEntityID: "entity-b", Epoch: 8,
	}
	registry := StaticKeyRegistry{
		sourceSigner.KeyID: {
			Binding: sourceSigner.Binding(), PublicKey: sourcePublic,
		},
		destinationSigner.KeyID: {
			Binding: destinationSigner.Binding(), PublicKey: destinationPublic,
		},
	}
	source := NewTransferService(pool, sourceSigner, nil, registry)
	destination := NewTransferService(pool, nil, destinationSigner, registry)
	accountID, assetID := "tuple-account-"+suffix, "tuple-asset-"+suffix
	if err := source.CreateAuthority(ctx, accountID, assetID, ledger.NewAmountInt64(100)); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Allocate(ctx, EffectRequest{
		EffectID: "tuple-allocate-" + suffix, AccountID: accountID,
		AssetID: assetID, Region: "A", Amount: ledger.NewAmountInt64(100),
	}); err != nil {
		t.Fatal(err)
	}
	certificate, err := source.InitiateTransfer(ctx, TransferRequest{
		TransferID: "tuple-transfer-1-" + suffix, AccountID: accountID,
		AssetID: assetID, SourceRegion: "A", DestinationRegion: "B",
		SourceLegalEntityID: "entity-a", DestinationLegalEntityID: "entity-b",
		Amount: ledger.NewAmountInt64(40),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := destination.ConsumeCertificate(ctx, certificate, "B"); err != nil {
		t.Fatal(err)
	}
	// Model a faulty/compromised source that signs a second TransferID with the
	// same durable issuance tuple. TransferID-only deduplication would mint 40.
	conflicting := certificate
	conflicting.TransferID = "tuple-transfer-2-" + suffix
	conflicting.Signature = nil
	conflicting, err = sourceSigner.Sign(conflicting)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := destination.ConsumeCertificate(ctx, conflicting, "B"); !errors.Is(err, ErrCertificateConflict) {
		t.Fatalf("reused source issuance tuple = %v", err)
	}
	var destinationAmount string
	var consumptionCount int
	if err := pool.QueryRow(ctx, `
SELECT available::STRING FROM escrow_regional_rights
WHERE account_id=$1 AND asset_id=$2 AND region='B'`, accountID, assetID).
		Scan(&destinationAmount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `
SELECT count(*) FROM escrow_consumed_certificates
WHERE account_id=$1 AND asset_id=$2`, accountID, assetID).Scan(&consumptionCount); err != nil {
		t.Fatal(err)
	}
	if destinationAmount != "40" || consumptionCount != 1 {
		t.Fatalf("source tuple replay created rights: destination=%s consumptions=%d",
			destinationAmount, consumptionCount)
	}
}

func TestSignedReceiptClosesSourceAcrossIndependentDatabases(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL is not set; CockroachDB integration test skipped")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	suffix := integrationSuffix(t)
	sourceDatabase := "escrow_source_" + suffix
	destinationDatabase := "escrow_destination_" + suffix
	for _, database := range []string{sourceDatabase, destinationDatabase} {
		if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{database}.Sanitize()); err != nil {
			t.Fatal(err)
		}
	}
	var sourcePool, destinationPool *pgxpool.Pool
	defer func() {
		if sourcePool != nil {
			sourcePool.Close()
		}
		if destinationPool != nil {
			destinationPool.Close()
		}
		for _, database := range []string{sourceDatabase, destinationDatabase} {
			_, _ = admin.Exec(context.Background(),
				"DROP DATABASE "+pgx.Identifier{database}.Sanitize()+" CASCADE")
		}
	}()
	openDatabase := func(name string) *pgxpool.Pool {
		t.Helper()
		config, err := pgxpool.ParseConfig(dsn)
		if err != nil {
			t.Fatal(err)
		}
		config.ConnConfig.Database = name
		config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
		pool, err := pgxpool.NewWithConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		if err := pool.Ping(ctx); err != nil {
			pool.Close()
			t.Fatal(err)
		}
		return pool
	}
	sourcePool = openDatabase(sourceDatabase)
	destinationPool = openDatabase(destinationDatabase)

	if _, err := sourcePool.Exec(ctx, independentSourceSchema); err != nil {
		t.Fatal(err)
	}
	if _, err := destinationPool.Exec(ctx, independentDestinationSchema); err != nil {
		t.Fatal(err)
	}
	accountID, assetID := "cross-db-account-"+suffix, "cross-db-asset-"+suffix
	if _, err := sourcePool.Exec(ctx, `
INSERT INTO escrow_authorities (account_id, asset_id, total_authority, unallocated)
VALUES ($1,$2,100,0);
INSERT INTO escrow_regional_rights (account_id, asset_id, region, available)
VALUES ($1,$2,'A',100)`, accountID, assetID); err != nil {
		t.Fatal(err)
	}

	sourcePublic, sourcePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	destinationPublic, destinationPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sourceSigner := Ed25519Signer{
		KeyID: "cross-db-source-key-" + suffix, PrivateKey: sourcePrivate,
		Region: "A", LegalEntityID: "entity-a", Epoch: 31,
	}
	destinationSigner := Ed25519ReceiptSigner{
		KeyID: "cross-db-destination-key-" + suffix, PrivateKey: destinationPrivate,
		Region: "B", LegalEntityID: "entity-b", Epoch: 47,
	}
	registry := StaticKeyRegistry{
		sourceSigner.KeyID: {
			Binding: sourceSigner.Binding(), PublicKey: sourcePublic,
		},
		destinationSigner.KeyID: {
			Binding: destinationSigner.Binding(), PublicKey: destinationPublic,
		},
	}
	source := NewTransferService(sourcePool, sourceSigner, nil, registry)
	destination := NewTransferService(destinationPool, nil, destinationSigner, registry)
	certificate, err := source.InitiateTransfer(ctx, TransferRequest{
		TransferID: "cross-db-transfer-" + suffix, AccountID: accountID,
		AssetID: assetID, SourceRegion: "A", DestinationRegion: "B",
		SourceLegalEntityID: "entity-a", DestinationLegalEntityID: "entity-b",
		Amount: ledger.NewAmountInt64(40),
	})
	if err != nil {
		t.Fatal(err)
	}
	consumption, err := destination.ConsumeCertificate(ctx, certificate, "B")
	if err != nil {
		t.Fatal(err)
	}
	var destinationTotal, destinationAvailable string
	if err := destinationPool.QueryRow(ctx, `
SELECT a.total_authority::STRING, r.available::STRING
FROM escrow_authorities a
JOIN escrow_regional_rights r USING (account_id, asset_id)
WHERE a.account_id=$1 AND a.asset_id=$2 AND r.region='B'`, accountID, assetID).
		Scan(&destinationTotal, &destinationAvailable); err != nil {
		t.Fatal(err)
	}
	if destinationTotal != "40" || destinationAvailable != "40" {
		t.Fatalf("destination commit mismatch: total=%s available=%s",
			destinationTotal, destinationAvailable)
	}
	// Make destination state physically unavailable. Source settlement must use
	// only the signed receipt and its local transfer row.
	destinationPool.Close()
	destinationPool = nil
	if err := source.AcknowledgeTransfer(ctx, certificate, consumption.Receipt); err != nil {
		t.Fatalf("source required destination-local state: %v", err)
	}
	var sourceTotal, sourceAvailable, status string
	if err := sourcePool.QueryRow(ctx, `
SELECT a.total_authority::STRING, r.available::STRING, t.status
FROM escrow_authorities a
JOIN escrow_regional_rights r USING (account_id, asset_id)
JOIN escrow_transfers t USING (account_id, asset_id)
WHERE a.account_id=$1 AND a.asset_id=$2 AND r.region='A'`, accountID, assetID).
		Scan(&sourceTotal, &sourceAvailable, &status); err != nil {
		t.Fatal(err)
	}
	if sourceTotal != "60" || sourceAvailable != "60" || status != "ACKNOWLEDGED" {
		t.Fatalf("cross-database settlement mismatch: total=%s available=%s status=%s",
			sourceTotal, sourceAvailable, status)
	}
}

const independentSourceSchema = `
CREATE TABLE escrow_authorities (
 account_id STRING NOT NULL, asset_id STRING NOT NULL,
 total_authority DECIMAL(38,0) NOT NULL CHECK (total_authority >= 0),
 unallocated DECIMAL(38,0) NOT NULL CHECK (unallocated >= 0),
 version INT8 NOT NULL DEFAULT 0, PRIMARY KEY (account_id, asset_id));
CREATE TABLE escrow_regional_rights (
 account_id STRING NOT NULL, asset_id STRING NOT NULL, region STRING NOT NULL,
 available DECIMAL(38,0) NOT NULL CHECK (available >= 0),
 version INT8 NOT NULL DEFAULT 0, updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY (account_id, asset_id, region));
CREATE TABLE escrow_transfers (
 transfer_id STRING PRIMARY KEY, account_id STRING NOT NULL, asset_id STRING NOT NULL,
 source_region STRING NOT NULL, destination_region STRING NOT NULL,
 source_legal_entity_id STRING NULL, destination_legal_entity_id STRING NULL,
 amount DECIMAL(38,0) NOT NULL CHECK (amount > 0), source_epoch INT8 NOT NULL,
 key_id STRING NOT NULL, source_key_epoch INT8 NULL, certificate_payload BYTES NOT NULL,
 certificate_sig BYTES NULL, status STRING NOT NULL DEFAULT 'IN_TRANSIT',
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(), acknowledged_at TIMESTAMPTZ NULL,
 consumption_receipt_payload BYTES NULL, consumption_receipt_sig BYTES NULL,
 consumption_receipt_hash BYTES NULL, destination_watermark INT8 NULL,
 receipt_key_id STRING NULL, receipt_key_epoch INT8 NULL,
 UNIQUE (account_id, asset_id, source_region, source_epoch));`

const independentDestinationSchema = `
CREATE TABLE escrow_authorities (
 account_id STRING NOT NULL, asset_id STRING NOT NULL,
 total_authority DECIMAL(38,0) NOT NULL CHECK (total_authority >= 0),
 unallocated DECIMAL(38,0) NOT NULL CHECK (unallocated >= 0),
 version INT8 NOT NULL DEFAULT 0, PRIMARY KEY (account_id, asset_id));
CREATE TABLE escrow_regional_rights (
 account_id STRING NOT NULL, asset_id STRING NOT NULL, region STRING NOT NULL,
 available DECIMAL(38,0) NOT NULL CHECK (available >= 0),
 version INT8 NOT NULL DEFAULT 0, updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY (account_id, asset_id, region));
CREATE TABLE escrow_consumed_certificates (
 transfer_id STRING PRIMARY KEY, account_id STRING NOT NULL, asset_id STRING NOT NULL,
 source_region STRING NOT NULL, destination_region STRING NOT NULL,
 amount DECIMAL(38,0) NOT NULL CHECK (amount > 0), payload_hash BYTES NOT NULL,
 consumed_at TIMESTAMPTZ NOT NULL DEFAULT now(), source_legal_entity_id STRING NULL,
 source_key_epoch INT8 NULL, source_epoch INT8 NULL,
 destination_legal_entity_id STRING NULL, destination_key_id STRING NULL,
 destination_key_epoch INT8 NULL, destination_watermark INT8 NULL,
 receipt_payload BYTES NULL, receipt_sig BYTES NULL, receipt_signed_at TIMESTAMPTZ NULL,
 UNIQUE (source_legal_entity_id, source_region, source_key_epoch, account_id, asset_id, source_epoch));
CREATE TABLE escrow_consumption_watermarks (
 destination_legal_entity_id STRING NOT NULL, destination_region STRING NOT NULL,
 next_watermark INT8 NOT NULL DEFAULT 0,
 PRIMARY KEY (destination_legal_entity_id, destination_region));
CREATE TABLE escrow_consumption_transfer_locks (
 transfer_id STRING PRIMARY KEY, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE escrow_consumption_issuance_locks (
 source_legal_entity_id STRING NOT NULL, source_region STRING NOT NULL,
 source_key_epoch INT8 NOT NULL, account_id STRING NOT NULL, asset_id STRING NOT NULL,
 source_epoch INT8 NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY (source_legal_entity_id, source_region, source_key_epoch,
              account_id, asset_id, source_epoch));`

func TestPartitionedRegionsCannotSpendBeyondAllocatedRights(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL is not set; CockroachDB integration test skipped")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	suffix := integrationSuffix(t)
	service := NewService(pool, nil, nil)
	accountID, assetID := "partition-account-"+suffix, "partition-asset-"+suffix
	if err := service.CreateAuthority(ctx, accountID, assetID, ledger.NewAmountInt64(100)); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Allocate(ctx, EffectRequest{
		EffectID: "allocate-a-" + suffix, AccountID: accountID, AssetID: assetID,
		Region: "A", Amount: ledger.NewAmountInt64(60),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Allocate(ctx, EffectRequest{
		EffectID: "allocate-b-" + suffix, AccountID: accountID, AssetID: assetID,
		Region: "B", Amount: ledger.NewAmountInt64(40),
	}); err != nil {
		t.Fatal(err)
	}
	var confirmed atomic.Int64
	var unexpected atomic.Value
	var workers sync.WaitGroup
	for _, region := range []string{"A", "B"} {
		region := region
		for attempt := 0; attempt < 100; attempt++ {
			attempt := attempt
			workers.Add(1)
			go func() {
				defer workers.Done()
				_, err := service.Spend(ctx, EffectRequest{
					EffectID:  fmt.Sprintf("spend-%s-%s-%d", suffix, region, attempt),
					AccountID: accountID, AssetID: assetID, Region: region,
					Amount: ledger.NewAmountInt64(2),
				})
				switch {
				case err == nil:
					confirmed.Add(2)
				case errors.Is(err, ErrInsufficientRights):
				default:
					unexpected.Store(err)
				}
			}()
		}
	}
	workers.Wait()
	if value := unexpected.Load(); value != nil {
		t.Fatalf("unexpected spend error: %v", value)
	}
	if got := confirmed.Load(); got != 100 {
		t.Fatalf("confirmed spend = %d, want exactly allocated 100", got)
	}
	snapshot, err := service.Snapshot(ctx, accountID, assetID)
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.Conserved() || !snapshot.Total.IsZero() ||
		!snapshot.RegionalRights["A"].IsZero() || !snapshot.RegionalRights["B"].IsZero() {
		t.Fatalf("partition spend broke conservation: %#v", snapshot)
	}
}

func integrationSuffix(t *testing.T) string {
	t.Helper()
	var value [12]byte
	if _, err := rand.Read(value[:]); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(value[:])
}
