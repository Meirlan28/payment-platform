// Command dev-seed provisions demo fixtures for local development and
// integration testing.
//
// It is not a production path and must never be run against a production
// cluster: it connects with an administrative database identity, funds wallets
// without any settlement evidence, and creates merchants that no onboarding
// process approved.
//
// It deliberately drives the same internal/provisioning primitives the
// production account-provisioning and funding services use, rather than
// writing its own INSERT statements. A fixture tool that took a shortcut
// around the real code would stop proving anything about the real code the
// first time the two drifted apart.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/example/payment-platform/internal/idgen"
	"github.com/example/payment-platform/internal/ledger"
	"github.com/example/payment-platform/internal/provisioning"
	"github.com/example/payment-platform/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Manifest is the contract between this tool and whatever consumes the
// fixtures. It is deliberately explicit that the balances it reports came from
// a fixture deposit and not from a real funding rail.
type Manifest struct {
	GeneratedAt        time.Time        `json:"generated_at"`
	Fixture            bool             `json:"fixture"`
	Region             string           `json:"region"`
	AssetID            string           `json:"asset_id"`
	AssetScale         int64            `json:"asset_scale"`
	PaymentPrincipalID string           `json:"payment_principal_id"`
	FundingAccountID   string           `json:"funding_account_id"`
	Merchants          []ManifestEntry  `json:"merchants"`
	Customers          []ManifestWallet `json:"customers"`
}

type ManifestEntry struct {
	ID          string `json:"id"`
	AccountID   string `json:"account_id"`
	BookID      string `json:"book_id"`
	DisplayName string `json:"display_name"`
}

type ManifestWallet struct {
	ExternalReference  string `json:"external_reference"`
	BookID             string `json:"book_id"`
	AvailableAccountID string `json:"available_account_id"`
	HeldAccountID      string `json:"held_account_id"`
	StartingBalance    string `json:"starting_balance_atoms"`
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(logger); err != nil {
		logger.Error("dev seed failed", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	var (
		region    = flag.String("region", "test-a", "authority region for the seeded accounts")
		assetID   = flag.String("asset", "usd-demo", "demo asset identifier")
		assetCode = flag.String("asset-code", "USDD", "demo asset display code")
		scale     = flag.Int64("asset-scale", 2, "atomic scale of the demo asset")
		principal = flag.String("payment-principal", "", "SPIFFE identity that will authorize payments")
		issuer    = flag.String("issuer", "pay-a", "durable ID issuer prefix")
		wallets   = flag.Int("wallets", 5, "number of demo customer wallets")
		balance   = flag.String("starting-balance", "100000", "atoms deposited into each wallet")
		shards    = flag.Int("book-shards", 4, "number of regional books to spread wallets over")
		output    = flag.String("output", "", "path to write the JSON manifest (default stdout)")
	)
	flag.Parse()

	if *principal == "" {
		return errors.New("-payment-principal is required")
	}
	if *wallets <= 0 || *wallets > 1000 {
		return errors.New("-wallets must be between 1 and 1000")
	}
	startingBalance, err := ledger.ParseAmount(*balance)
	if err != nil || startingBalance.Sign() <= 0 {
		return errors.New("-starting-balance must be a positive integer number of atoms")
	}
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return errors.New("DATABASE_URL is required")
	}
	// A fixture tool that silently reached a production cluster would be a
	// serious incident, so refuse the one environment name that means it.
	if strings.EqualFold(os.Getenv("ENVIRONMENT"), "production") {
		return errors.New("dev-seed must never run with ENVIRONMENT=production")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer pool.Close()
	probeContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(probeContext); err != nil {
		return fmt.Errorf("database readiness: %w", err)
	}

	if _, err := pool.Exec(ctx,
		`INSERT INTO id_issuers (issuer_prefix, incarnation) VALUES ($1,1)
         ON CONFLICT (issuer_prefix) DO NOTHING`, *issuer); err != nil {
		return fmt.Errorf("ensure ID issuer: %w", err)
	}
	generator, err := idgen.New(pool, *issuer, 1024)
	if err != nil {
		return err
	}
	transactions := store.NewRunner(pool)
	journal := ledger.NewService(transactions, generator)
	if err := journal.RegisterAsset(ctx, ledger.Asset{
		AssetID: *assetID, DisplayCode: *assetCode, AtomicScale: *scale,
	}); err != nil {
		return fmt.Errorf("register demo asset: %w", err)
	}

	fundingAccountID := "funding-" + *region
	config := provisioning.Config{
		Region: *region, LegalEntityID: "demo-entity", Jurisdiction: "KZ",
		BookShards: *shards, PolicyVersion: "dev-seed-v1", GrantedBy: "dev-seed",
		FundingAccountID: fundingAccountID,
	}
	accounts, err := provisioning.New(transactions, journal, generator, config)
	if err != nil {
		return err
	}

	manifest := Manifest{
		GeneratedAt: time.Now().UTC(), Fixture: true, Region: *region,
		AssetID: *assetID, AssetScale: *scale, PaymentPrincipalID: *principal,
		FundingAccountID: fundingAccountID,
	}

	// The funding source must exist in every book a wallet may land in,
	// because all lines of one ledger transaction belong to one book.
	// Every shard is materialised, not just the ones this run's wallets land
	// in: wallets provisioned later by the production API must find a merchant
	// account already present in whichever book they are assigned.
	books := make(map[string]struct{})
	for shard := range *shards {
		books[fmt.Sprintf("book-%s-%s-%d", config.LegalEntityID, *region, shard)] = struct{}{}
	}
	for bookID := range books {
		// EnsureBook rather than CreateBook: seeding is expected to be run
		// repeatedly against a database whose books already have activity.
		if err := journal.EnsureBook(ctx, ledger.Book{
			BookID: bookID, LegalEntityID: config.LegalEntityID, Jurisdiction: config.Jurisdiction,
		}); err != nil {
			return fmt.Errorf("ensure book %s: %w", bookID, err)
		}
		if err := journal.CreateAccount(ctx, ledger.Account{
			AccountID: provisioning.FundingAccountFor(fundingAccountID, bookID), BookID: bookID,
			AssetID: *assetID, AccountType: "CASH", NormalSide: ledger.Debit,
		}); err != nil {
			return fmt.Errorf("create funding account in %s: %w", bookID, err)
		}
	}

	// A merchant gets an account in every book. Wallets are spread over books
	// so no single book becomes a hot range, and a ledger transaction may not
	// span books, so a merchant reachable from only one book would be
	// unpayable for most customers.
	for _, merchant := range demoMerchants {
		for bookID := range books {
			accountID := "merchant-" + merchant.id + "-" + bookID
			if err := accounts.ProvisionMerchantAccount(ctx, provisioning.MerchantAccountRequest{
				AccountID: accountID, AssetID: *assetID, BookID: bookID,
				PaymentPrincipalID: *principal,
			}); err != nil {
				return fmt.Errorf("provision merchant %s in %s: %w", merchant.id, bookID, err)
			}
			manifest.Merchants = append(manifest.Merchants, ManifestEntry{
				ID: merchant.id, AccountID: accountID, BookID: bookID, DisplayName: merchant.name,
			})
		}
		logger.Info("merchant provisioned in every book",
			"merchant", merchant.id, "books", len(books))
	}

	for index := range *wallets {
		reference := walletReference(index)
		bookID := accounts.BookIDFor(reference)
		// Each wallet is funded from the source account inside its own book.
		walletAccounts, err := provisioning.New(transactions, journal, generator, withFundingAccount(
			config, provisioning.FundingAccountFor(fundingAccountID, bookID)))
		if err != nil {
			return err
		}
		provisioned, err := walletAccounts.ProvisionCustomerAccount(ctx, provisioning.CustomerAccountRequest{
			ExternalReference: reference, AssetID: *assetID, PaymentPrincipalID: *principal,
		})
		if err != nil {
			return fmt.Errorf("provision wallet %s: %w", reference, err)
		}
		if _, err := walletAccounts.Deposit(ctx, provisioning.DepositRequest{
			ExternalReference: "fixture-deposit-" + reference,
			AccountID:         provisioned.AvailableAccountID, AssetID: *assetID,
			AmountAtoms:            startingBalance,
			FundingSourceReference: "dev-seed-fixture",
		}); err != nil {
			return fmt.Errorf("fund wallet %s: %w", reference, err)
		}
		manifest.Customers = append(manifest.Customers, ManifestWallet{
			ExternalReference: reference, BookID: provisioned.BookID,
			AvailableAccountID: provisioned.AvailableAccountID,
			HeldAccountID:      provisioned.HeldAccountID,
			StartingBalance:    startingBalance.String(),
		})
		logger.Info("wallet provisioned and funded",
			"reference", reference, "available", provisioned.AvailableAccountID)
	}

	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if *output == "" {
		_, err = os.Stdout.Write(encoded)
		return err
	}
	// The manifest holds fixture account identifiers and no secrets, and is
	// meant to be read by the developer and by whatever consumes the fixtures.
	if err := os.WriteFile(*output, encoded, 0o644); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}
	logger.Info("manifest written", "path", *output,
		"wallets", len(manifest.Customers), "merchants", len(manifest.Merchants))
	return nil
}

var demoMerchants = []struct{ id, name string }{
	{"coffee", "Demo Coffee House"},
	{"books", "Demo Bookstore"},
	{"grocery", "Demo Grocery"},
}

func walletReference(index int) string {
	return fmt.Sprintf("demo-wallet-%03d", index+1)
}

func withFundingAccount(config provisioning.Config, accountID string) provisioning.Config {
	config.FundingAccountID = accountID
	return config
}
