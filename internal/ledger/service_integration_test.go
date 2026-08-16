//go:build integration

package ledger

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/example/payment-platform/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type integrationIDs struct {
	prefix string
	value  atomic.Int64
}

func (g *integrationIDs) Next(context.Context) (string, error) {
	return fmt.Sprintf("%s-%d", g.prefix, g.value.Add(1)), nil
}

func TestFoldBalanceIgnoresCommittedDraftLines(t *testing.T) {
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
	ids := &integrationIDs{prefix: fmt.Sprintf("integration-%d", time.Now().UnixNano())}
	runner := store.NewRunner(pool)
	journal := NewService(runner, ids)

	suffix, _ := ids.Next(ctx)
	assetID, bookID := "asset-"+suffix, "book-"+suffix
	debitID, creditID := "debit-"+suffix, "credit-"+suffix
	if err := journal.RegisterAsset(ctx, Asset{AssetID: assetID, DisplayCode: "CODE-" + suffix, AtomicScale: 2}); err != nil {
		t.Fatal(err)
	}
	if err := journal.CreateBook(ctx, Book{BookID: bookID, LegalEntityID: "entity", Jurisdiction: "KZ"}); err != nil {
		t.Fatal(err)
	}
	for _, account := range []Account{
		{AccountID: debitID, BookID: bookID, AssetID: assetID, AccountType: "TEST", NormalSide: Debit},
		{AccountID: creditID, BookID: bookID, AssetID: assetID, AccountType: "TEST", NormalSide: Credit},
	} {
		if err := journal.CreateAccount(ctx, account); err != nil {
			t.Fatal(err)
		}
	}

	requestHash := sha256.Sum256([]byte("draft-only"))
	err = runner.RunSerializable(ctx, func(tx pgx.Tx) error {
		var sequence int64
		var previous []byte
		if err := tx.QueryRow(ctx, `SELECT next_sequence_no, last_entry_hash FROM books WHERE book_id=$1 FOR UPDATE`, bookID).Scan(&sequence, &previous); err != nil {
			return err
		}
		entry := sha256.Sum256([]byte("unposted-draft"))
		_, err := tx.Exec(ctx, `
INSERT INTO ledger_transactions (
 transaction_id, book_id, operation_id, effect_id, transaction_kind,
 posting_rule_version, request_hash, metadata, canonical_metadata,
 sequence_no, prev_hash, entry_hash
) VALUES ($1,$2,$3,$4,'TEST_DRAFT','v1',$5,'{}'::JSONB,$6,$7,$8,$9)`,
			"draft-tx-"+suffix, bookID, "draft-op-"+suffix, "draft-effect-"+suffix,
			requestHash[:], []byte("{}"), sequence, previous, entry[:])
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `
INSERT INTO ledger_lines(transaction_id,line_no,account_id,asset_id,side,amount_atoms)
VALUES ($1,1,$2,$4,'DEBIT','50'), ($1,2,$3,$4,'CREDIT','50')`,
			"draft-tx-"+suffix, debitID, creditID, assetID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	folded, err := journal.FoldBalance(ctx, creditID)
	if err != nil {
		t.Fatal(err)
	}
	if !folded.IsZero() {
		t.Fatalf("DRAFT lines leaked into posted balance fold: %s", folded.String())
	}
}
