// Command transfer-api moves value directly between two customer accounts for
// one authority region.
//
// It is a separate deployable from payment-api, with its own database role and
// its own client allowlist, because moving a customer's money to another
// person is a different authority from authorizing their payment to a
// merchant. A credential for one must never be usable for the other.
//
// Its database role can post balanced journal transactions and move escrow
// rights only through the linkage-checked function — it cannot open accounts,
// cannot create value, and cannot touch the payment lifecycle.
package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"time"

	transferv1 "github.com/example/payment-platform/gen/go/transfer/v1"
	grpcapi "github.com/example/payment-platform/internal/api"
	"github.com/example/payment-platform/internal/authz"
	"github.com/example/payment-platform/internal/idgen"
	"github.com/example/payment-platform/internal/ledger"
	"github.com/example/payment-platform/internal/servicehost"
	"github.com/example/payment-platform/internal/store"
	"github.com/example/payment-platform/internal/transfer"
	"google.golang.org/grpc"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(logger); err != nil {
		logger.Error("transfer API stopped", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	config, err := servicehost.LoadConfig(":8447", true)
	if err != nil {
		return err
	}
	policyVersion := os.Getenv("POSTING_RULE_VERSION")
	if policyVersion == "" {
		return errors.New("POSTING_RULE_VERSION is required")
	}
	callers, err := permittedCallers()
	if err != nil {
		return err
	}

	ctx := context.Background()
	pool, err := servicehost.OpenPool(ctx, config, "transfer-api")
	if err != nil {
		return err
	}
	defer pool.Close()

	generator, err := idgen.New(pool, config.Issuer, 1024)
	if err != nil {
		return err
	}
	transactions := store.NewRunner(pool)
	capabilities, err := authz.New(pool)
	if err != nil {
		return err
	}
	transfers, err := transfer.New(transactions,
		ledger.NewService(transactions, generator), capabilities, generator,
		transfer.Config{Region: config.RegionID, PolicyVersion: policyVersion})
	if err != nil {
		return err
	}

	return servicehost.Serve(ctx, servicehost.Options{
		Config: config, Pool: pool, Logger: logger,
		ServiceName: "transfer-api",
		// A cross-book transfer writes two journal entries and two escrow
		// movements in one transaction, and may be retried on serialization
		// conflict, so it is given more room than a single-hop read.
		RequestDeadline: 15 * time.Second,
		Register: func(server *grpc.Server) {
			transferv1.RegisterTransferServiceServer(server, &transfer.Server{
				Transfers:        transfers,
				ResolvePrincipal: grpcapi.SPIFFEPrincipal,
				PermittedCallers: callers,
				Logger:           logger,
			})
		},
	})
}

// permittedCallers reads the comma-separated SPIFFE identities allowed to move
// customer money. It fails closed: an unset list is a configuration error,
// never an open door.
func permittedCallers() (map[string]struct{}, error) {
	raw := os.Getenv("TRANSFER_PERMITTED_CALLERS")
	callers := make(map[string]struct{})
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry != "" {
			callers[entry] = struct{}{}
		}
	}
	if len(callers) == 0 {
		return nil, errors.New("TRANSFER_PERMITTED_CALLERS must list at least one client identity")
	}
	return callers, nil
}
