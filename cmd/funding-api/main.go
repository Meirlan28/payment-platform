// Command funding-api credits provisioned customer accounts for one authority
// region.
//
// This is the only service that brings new value into a customer wallet, so it
// is deliberately the narrowest surface in the platform: one RPC, an explicit
// allowlist of rail and settlement identities permitted to call it, and a
// database role that can post a balanced journal transaction and raise escrow
// but cannot open accounts or grant capability.
//
// Every deposit raises the ledger balance and the regional escrow right in one
// transaction and enqueues the notification in that same transaction, so a
// credited wallet is always spendable and always announced.
package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
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
		logger.Error("funding API stopped", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	config, err := servicehost.LoadConfig(":8445", true)
	if err != nil {
		return err
	}
	fundingConfig := provisioning.Config{
		Region:           config.RegionID,
		LegalEntityID:    os.Getenv("LEGAL_ENTITY_ID"),
		Jurisdiction:     os.Getenv("JURISDICTION"),
		PolicyVersion:    os.Getenv("POSTING_RULE_VERSION"),
		GrantedBy:        os.Getenv("CAPABILITY_GRANTED_BY"),
		BookShards:       1, // unused by Deposit; the account names its own book
		FundingAccountID: os.Getenv("FUNDING_ACCOUNT_ID"),
	}
	if fundingConfig.LegalEntityID == "" || fundingConfig.Jurisdiction == "" ||
		fundingConfig.PolicyVersion == "" || fundingConfig.GrantedBy == "" ||
		fundingConfig.FundingAccountID == "" {
		return errors.New("LEGAL_ENTITY_ID, JURISDICTION, POSTING_RULE_VERSION, " +
			"CAPABILITY_GRANTED_BY and FUNDING_ACCOUNT_ID are required")
	}
	callers, err := permittedCallers()
	if err != nil {
		return err
	}

	ctx := context.Background()
	pool, err := servicehost.OpenPool(ctx, config, "funding-api")
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
		ledger.NewService(transactions, generator), generator, fundingConfig)
	if err != nil {
		return err
	}

	return servicehost.Serve(ctx, servicehost.Options{
		Config: config, Pool: pool, Logger: logger,
		ServiceName:     "funding-api",
		RequestDeadline: 5 * time.Second,
		Register: func(server *grpc.Server) {
			provisioningv1.RegisterFundingServiceServer(server, &provisioning.FundingServer{
				Accounts:         accounts,
				ResolvePrincipal: grpcapi.SPIFFEPrincipal,
				PermittedCallers: callers,
				Logger:           logger,
			})
		},
	})
}

// permittedCallers reads the comma-separated SPIFFE identities allowed to
// create value. It fails closed: an unset or empty list is a configuration
// error, never an open door.
func permittedCallers() (map[string]struct{}, error) {
	raw := os.Getenv("FUNDING_PERMITTED_CALLERS")
	callers := make(map[string]struct{})
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry != "" {
			callers[entry] = struct{}{}
		}
	}
	if len(callers) == 0 {
		return nil, errors.New("FUNDING_PERMITTED_CALLERS must list at least one client identity")
	}
	return callers, nil
}
