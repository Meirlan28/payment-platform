// Command account-provisioning-api opens customer and merchant ledger
// accounts for one authority region.
//
// It is a separate deployment from payment-api on purpose. Opening an account
// grants spending capability; moving money spends it. Splitting them means a
// compromised payment credential cannot mint entitlements and a compromised
// provisioning credential cannot move value. The two run under different
// database roles and accept different client certificates.
package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strconv"
	"time"

	provisioningv1 "github.com/example/payment-platform/gen/go/provisioning/v1"
	grpcapi "github.com/example/payment-platform/internal/api"
	"github.com/example/payment-platform/internal/idgen"
	"github.com/example/payment-platform/internal/ledger"
	"github.com/example/payment-platform/internal/provisioning"
	"github.com/example/payment-platform/internal/servicehost"
	"github.com/example/payment-platform/internal/store"
	"google.golang.org/grpc"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(logger); err != nil {
		logger.Error("account provisioning API stopped", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	config, err := servicehost.LoadConfig(":8444", true)
	if err != nil {
		return err
	}
	provisioningConfig, err := loadProvisioningConfig(config.RegionID)
	if err != nil {
		return err
	}
	allowlist, err := provisioning.LoadAllowlistFile(os.Getenv("PROVISIONING_ALLOWLIST_FILE"))
	if err != nil {
		return err
	}

	ctx := context.Background()
	pool, err := servicehost.OpenPool(ctx, config, "account-provisioning-api")
	if err != nil {
		return err
	}
	defer pool.Close()

	generator, err := idgen.New(pool, config.Issuer, 1024)
	if err != nil {
		return err
	}
	transactions := store.NewRunner(pool)
	accounts, err := provisioning.New(transactions,
		ledger.NewService(transactions, generator), generator, provisioningConfig)
	if err != nil {
		return err
	}

	return servicehost.Serve(ctx, servicehost.Options{
		Config: config, Pool: pool, Logger: logger,
		ServiceName: "account-provisioning-api",
		// Provisioning opens a book, two accounts, escrow rows and capability
		// grants in one serializable transaction, so it is given more headroom
		// than a single-row payment command.
		RequestDeadline: 10 * time.Second,
		Register: func(server *grpc.Server) {
			provisioningv1.RegisterAccountProvisioningServiceServer(server,
				&provisioning.AccountProvisioningServer{
					Accounts:         accounts,
					Allowlist:        allowlist,
					ResolvePrincipal: grpcapi.SPIFFEPrincipal,
					Logger:           logger,
				})
		},
	})
}

func loadProvisioningConfig(regionID string) (provisioning.Config, error) {
	config := provisioning.Config{
		Region:        regionID,
		LegalEntityID: os.Getenv("LEGAL_ENTITY_ID"),
		Jurisdiction:  os.Getenv("JURISDICTION"),
		PolicyVersion: os.Getenv("CAPABILITY_POLICY_VERSION"),
		GrantedBy:     os.Getenv("CAPABILITY_GRANTED_BY"),
		BookShards:    16,
	}
	if raw := os.Getenv("BOOK_SHARDS"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value <= 0 || value > 4096 {
			return provisioning.Config{}, errors.New("BOOK_SHARDS must be between 1 and 4096")
		}
		config.BookShards = value
	}
	if config.LegalEntityID == "" || config.Jurisdiction == "" ||
		config.PolicyVersion == "" || config.GrantedBy == "" {
		return provisioning.Config{}, errors.New(
			"LEGAL_ENTITY_ID, JURISDICTION, CAPABILITY_POLICY_VERSION and CAPABILITY_GRANTED_BY are required")
	}
	return config, nil
}
