//go:build integration

package escrow

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/example/payment-platform/internal/ledger"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var errInjectedCommitACKLoss = errors.New("test: commit response lost after durable commit")

func TestAuthorityEffectsDeduplicateConflictsAndConcurrentRetries(t *testing.T) {
	ctx, pool := effectTestPool(t)
	suffix := integrationSuffix(t)
	service := NewService(pool, nil, nil)
	accountID, assetID := "effects-account-"+suffix, "effects-asset-"+suffix
	if err := service.CreateAuthority(ctx, accountID, assetID, ledger.NewAmountInt64(100)); err != nil {
		t.Fatal(err)
	}

	allocateA := EffectRequest{
		EffectID: "allocate-a-" + suffix, AccountID: accountID, AssetID: assetID,
		Region: "A", Amount: ledger.NewAmountInt64(60),
	}
	first, err := service.Allocate(ctx, allocateA)
	if err != nil || first.Duplicate {
		t.Fatalf("first allocation = %#v, %v", first, err)
	}
	duplicate, err := service.Allocate(ctx, allocateA)
	if err != nil || !duplicate.Duplicate || duplicate.RequestHash != first.RequestHash {
		t.Fatalf("allocation retry = %#v, %v", duplicate, err)
	}
	conflicting := allocateA
	conflicting.Amount = ledger.NewAmountInt64(61)
	if _, err := service.Allocate(ctx, conflicting); !errors.Is(err, ErrEffectConflict) {
		t.Fatalf("effect ID request substitution = %v, want ErrEffectConflict", err)
	}
	if _, err := service.Allocate(ctx, EffectRequest{}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("missing mandatory effect ID = %v", err)
	}

	allocateB := EffectRequest{
		EffectID: "allocate-b-" + suffix, AccountID: accountID, AssetID: assetID,
		Region: "B", Amount: ledger.NewAmountInt64(20),
	}
	var firstApplications atomic.Int64
	var workers sync.WaitGroup
	errorsSeen := make(chan error, 24)
	for range 24 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			receipt, applyErr := service.Allocate(ctx, allocateB)
			if applyErr == nil && !receipt.Duplicate {
				firstApplications.Add(1)
			}
			errorsSeen <- applyErr
		}()
	}
	workers.Wait()
	close(errorsSeen)
	for applyErr := range errorsSeen {
		if applyErr != nil {
			t.Fatalf("concurrent duplicate allocation: %v", applyErr)
		}
	}
	if firstApplications.Load() != 1 {
		t.Fatalf("first applications = %d, want 1", firstApplications.Load())
	}

	spend := EffectRequest{
		EffectID: "spend-" + suffix, AccountID: accountID, AssetID: assetID,
		Region: "A", Amount: ledger.NewAmountInt64(10),
	}
	if receipt, err := service.Spend(ctx, spend); err != nil || receipt.Duplicate {
		t.Fatalf("first spend = %#v, %v", receipt, err)
	}
	if receipt, err := service.Spend(ctx, spend); err != nil || !receipt.Duplicate {
		t.Fatalf("duplicate spend = %#v, %v", receipt, err)
	}
	if _, err := service.Return(ctx, spend); !errors.Is(err, ErrEffectConflict) {
		t.Fatalf("cross-kind effect substitution = %v, want ErrEffectConflict", err)
	}
	failedSpend := spend
	failedSpend.EffectID = "insufficient-" + suffix
	failedSpend.Amount = ledger.NewAmountInt64(1000)
	if _, err := service.Spend(ctx, failedSpend); !errors.Is(err, ErrInsufficientRights) {
		t.Fatalf("overspend = %v, want ErrInsufficientRights", err)
	}
	var failedReceipts int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM escrow_effect_receipts WHERE effect_id=$1`,
		failedSpend.EffectID).Scan(&failedReceipts); err != nil {
		t.Fatal(err)
	}
	if failedReceipts != 0 {
		t.Fatal("failed mutation committed a deduplication receipt")
	}

	returned := EffectRequest{
		EffectID: "return-" + suffix, AccountID: accountID, AssetID: assetID,
		Region: "A", Amount: ledger.NewAmountInt64(5),
	}
	if receipt, err := service.Return(ctx, returned); err != nil || receipt.Duplicate {
		t.Fatalf("first return = %#v, %v", receipt, err)
	}
	if receipt, err := service.Return(ctx, returned); err != nil || !receipt.Duplicate {
		t.Fatalf("duplicate return = %#v, %v", receipt, err)
	}
	if _, err := pool.Exec(ctx, `
UPDATE escrow_effect_receipts SET amount=amount+1 WHERE effect_id=$1`, returned.EffectID); err == nil {
		t.Fatal("database accepted mutation of a committed effect receipt")
	}
	if _, err := pool.Exec(ctx, `
DELETE FROM escrow_effect_receipts WHERE effect_id=$1`, returned.EffectID); err == nil {
		t.Fatal("database accepted deletion of a committed effect receipt")
	}

	snapshot, err := service.Snapshot(ctx, accountID, assetID)
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.Conserved() || snapshot.Total.String() != "95" ||
		snapshot.Unallocated.String() != "20" || snapshot.RegionalRights["A"].String() != "55" ||
		snapshot.RegionalRights["B"].String() != "20" {
		t.Fatalf("deduplication changed authority more than once: %#v", snapshot)
	}
}

func TestAuthorityEffectsSurviveCommitACKLoss(t *testing.T) {
	ctx, pool := effectTestPool(t)
	suffix := integrationSuffix(t)
	accountID, assetID := "lost-ack-account-"+suffix, "lost-ack-asset-"+suffix
	bootstrap := NewService(pool, nil, nil)
	if err := bootstrap.CreateAuthority(ctx, accountID, assetID, ledger.NewAmountInt64(50)); err != nil {
		t.Fatal(err)
	}

	lossyDB := &commitACKLossDB{pool: pool}
	service := NewService(lossyDB, nil, nil)
	requests := []struct {
		name  string
		apply func(context.Context, EffectRequest) (EffectReceipt, error)
		req   EffectRequest
	}{
		{name: "allocate", apply: service.Allocate, req: EffectRequest{
			EffectID: "lost-allocate-" + suffix, AccountID: accountID, AssetID: assetID,
			Region: "A", Amount: ledger.NewAmountInt64(40),
		}},
		{name: "spend", apply: service.Spend, req: EffectRequest{
			EffectID: "lost-spend-" + suffix, AccountID: accountID, AssetID: assetID,
			Region: "A", Amount: ledger.NewAmountInt64(10),
		}},
		{name: "return", apply: service.Return, req: EffectRequest{
			EffectID: "lost-return-" + suffix, AccountID: accountID, AssetID: assetID,
			Region: "A", Amount: ledger.NewAmountInt64(5),
		}},
	}
	for _, test := range requests {
		t.Run(test.name, func(t *testing.T) {
			lossyDB.arm()
			if _, err := test.apply(ctx, test.req); !errors.Is(err, errInjectedCommitACKLoss) {
				t.Fatalf("ambiguous commit = %v, want injected ACK loss", err)
			}
			receipt, err := test.apply(ctx, test.req)
			if err != nil || !receipt.Duplicate {
				t.Fatalf("retry after durable commit/ACK loss = %#v, %v", receipt, err)
			}
		})
	}

	snapshot, err := service.Snapshot(ctx, accountID, assetID)
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.Conserved() || snapshot.Total.String() != "45" ||
		snapshot.Unallocated.String() != "10" || snapshot.RegionalRights["A"].String() != "35" {
		t.Fatalf("ambiguous commit retry double-applied an effect: %#v", snapshot)
	}
}

type commitACKLossDB struct {
	pool     *pgxpool.Pool
	dropNext atomic.Bool
}

func (db *commitACKLossDB) arm() { db.dropNext.Store(true) }

func (db *commitACKLossDB) BeginTx(ctx context.Context, options pgx.TxOptions) (pgx.Tx, error) {
	tx, err := db.pool.BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	return &commitACKLossTx{Tx: tx, dropNext: &db.dropNext}, nil
}

type commitACKLossTx struct {
	pgx.Tx
	dropNext *atomic.Bool
}

func (tx *commitACKLossTx) Commit(ctx context.Context) error {
	if err := tx.Tx.Commit(ctx); err != nil {
		return err
	}
	if tx.dropNext.CompareAndSwap(true, false) {
		return errInjectedCommitACKLoss
	}
	return nil
}

func effectTestPool(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL is not set; CockroachDB integration test skipped")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return ctx, pool
}
