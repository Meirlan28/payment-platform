//go:build integration

package fx

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/example/payment-platform/internal/idempotency"
	"github.com/example/payment-platform/internal/ledger"
	"github.com/example/payment-platform/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
)

type fxTestIDs struct {
	prefix string
	value  atomic.Int64
}

func (g *fxTestIDs) Next(context.Context) (string, error) {
	return fmt.Sprintf("%s-%d", g.prefix, g.value.Add(1)), nil
}

func TestExchangeBalancesAssetsSeparatelyAndConsumesQuoteOnce(t *testing.T) {
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
	ids := &fxTestIDs{prefix: fmt.Sprintf("fx-test-%d", time.Now().UnixNano())}
	runner := store.NewRunner(pool)
	journal := ledger.NewService(runner, ids)
	service := NewService(runner, journal, idempotency.NewService(ids), ids)
	suffix, _ := ids.Next(ctx)
	bookID := "book-" + suffix
	baseAsset, quoteAsset := "USD-"+suffix, "EUR-"+suffix
	for _, asset := range []ledger.Asset{
		{AssetID: baseAsset, DisplayCode: baseAsset, AtomicScale: 2},
		{AssetID: quoteAsset, DisplayCode: quoteAsset, AtomicScale: 2},
	} {
		if err := journal.RegisterAsset(ctx, asset); err != nil {
			t.Fatal(err)
		}
	}
	if err := journal.CreateBook(ctx, ledger.Book{BookID: bookID, LegalEntityID: "entity", Jurisdiction: "KZ"}); err != nil {
		t.Fatal(err)
	}
	baseCustomer := "base-customer-" + suffix
	baseCash := "base-cash-" + suffix
	basePosition := "base-position-" + suffix
	quotePosition := "quote-position-" + suffix
	quoteBeneficiary := "quote-beneficiary-" + suffix
	for _, account := range []ledger.Account{
		{AccountID: baseCustomer, BookID: bookID, AssetID: baseAsset, AccountType: "CUSTOMER", NormalSide: ledger.Credit, EnforceSpendLimit: true},
		{AccountID: baseCash, BookID: bookID, AssetID: baseAsset, AccountType: "CASH", NormalSide: ledger.Debit},
		{AccountID: basePosition, BookID: bookID, AssetID: baseAsset, AccountType: "FX_POSITION", NormalSide: ledger.Credit},
		{AccountID: quotePosition, BookID: bookID, AssetID: quoteAsset, AccountType: "FX_POSITION", NormalSide: ledger.Debit},
		{AccountID: quoteBeneficiary, BookID: bookID, AssetID: quoteAsset, AccountType: "BENEFICIARY", NormalSide: ledger.Credit},
	} {
		if err := journal.CreateAccount(ctx, account); err != nil {
			t.Fatal(err)
		}
	}
	fundingHash := sha256.Sum256([]byte(suffix))
	_, err = journal.Post(ctx, ledger.PostRequest{
		TransactionID: "fund-tx-" + suffix, BookID: bookID,
		OperationID: "fund-op-" + suffix, EffectID: "fund-effect-" + suffix,
		Kind: "DEPOSIT", PostingRuleVersion: "v1", SchemaVersion: 1,
		RequestHash: fundingHash,
		Lines: []ledger.Line{
			{AccountID: baseCash, AssetID: baseAsset, Side: ledger.Debit, AmountAtoms: ledger.NewAmountInt64(100)},
			{AccountID: baseCustomer, AssetID: baseAsset, Side: ledger.Credit, AmountAtoms: ledger.NewAmountInt64(100)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	quote, err := service.CreateQuote(ctx, CreateQuoteRequest{
		BaseAssetID: baseAsset, QuoteAssetID: quoteAsset,
		RateNumerator: ledger.NewAmountInt64(9), RateDenominator: ledger.NewAmountInt64(10),
		BaseAmount: ledger.NewAmountInt64(100), RoundingRule: HalfEven,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := ExchangeRequest{
		Scope: bookID, IdempotencyKey: "exchange", QuoteID: quote.QuoteID, BookID: bookID,
		BaseDebitAccountID: baseCustomer, BasePositionAccountID: basePosition,
		QuotePositionAccountID: quotePosition, QuoteCreditAccountID: quoteBeneficiary,
		PostingRuleVersion: "v1",
	}
	first, err := service.Exchange(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Exchange(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Duplicate || first.Ledger.TransactionID != second.Ledger.TransactionID {
		t.Fatal("FX retry did not return original durable result")
	}
	request.IdempotencyKey = "different-economic-request"
	if _, err := service.Exchange(ctx, request); !errors.Is(err, ErrQuoteConsumed) {
		t.Fatalf("quote was consumed twice: %v", err)
	}
	baseBalance, err := journal.Balance(ctx, baseCustomer)
	if err != nil {
		t.Fatal(err)
	}
	quoteBalance, err := journal.Balance(ctx, quoteBeneficiary)
	if err != nil {
		t.Fatal(err)
	}
	if !baseBalance.CurrentBalanceAtoms.IsZero() || quoteBalance.CurrentBalanceAtoms.Cmp(ledger.NewAmountInt64(90)) != 0 {
		t.Fatalf("unexpected FX balances: base=%s quote=%s",
			baseBalance.CurrentBalanceAtoms.String(), quoteBalance.CurrentBalanceAtoms.String())
	}
}
