// Command ledger-query-api serves authoritative, read-only account snapshots
// at a caller-supplied past timestamp.
//
// It exists so an external read model can prove itself correct against the
// ledger. Reading at a shared past watermark is what makes that comparison
// meaningful: everything committed before the watermark has had time to
// propagate, so a remaining difference is a real defect rather than ordinary
// pipeline lag.
//
// The service holds no write capability whatsoever. Its database identity is
// granted only SELECT, so it adds a network surface over privileges the
// platform's ledger_reader role already has, not a new privilege.
package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"time"

	provisioningv1 "github.com/example/payment-platform/gen/go/provisioning/v1"
	grpcapi "github.com/example/payment-platform/internal/api"
	"github.com/example/payment-platform/internal/provisioning"
	"github.com/example/payment-platform/internal/servicehost"
	"google.golang.org/grpc"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(logger); err != nil {
		logger.Error("ledger query API stopped", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	// No ID issuer: this service allocates no durable identifiers because it
	// writes nothing.
	config, err := servicehost.LoadConfig(":8446", false)
	if err != nil {
		return err
	}
	minimumAge, err := durationOr("SNAPSHOT_MIN_AGE", time.Second)
	if err != nil {
		return err
	}
	// CockroachDB garbage collects old MVCC versions, so a snapshot older than
	// the cluster's retention is refused rather than served incorrectly.
	maximumAge, err := durationOr("SNAPSHOT_MAX_AGE", 4*time.Hour)
	if err != nil {
		return err
	}
	if minimumAge >= maximumAge {
		return errors.New("SNAPSHOT_MIN_AGE must be smaller than SNAPSHOT_MAX_AGE")
	}

	ctx := context.Background()
	pool, err := servicehost.OpenPool(ctx, config, "ledger-query-api")
	if err != nil {
		return err
	}
	defer pool.Close()

	return servicehost.Serve(ctx, servicehost.Options{
		Config: config, Pool: pool, Logger: logger,
		ServiceName:     "ledger-query-api",
		RequestDeadline: 5 * time.Second,
		Register: func(server *grpc.Server) {
			provisioningv1.RegisterLedgerQueryServiceServer(server, &provisioning.LedgerQueryServer{
				DB:               pool,
				ResolvePrincipal: grpcapi.SPIFFEPrincipal,
				Logger:           logger,
				MinSnapshotAge:   minimumAge,
				MaxSnapshotAge:   maximumAge,
			})
		},
	})
}

func durationOr(name string, fallback time.Duration) (time.Duration, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback, nil
	}
	value, err := time.ParseDuration(raw)
	if err != nil || value <= 0 {
		return 0, errors.New(name + " must be a positive Go duration")
	}
	return value, nil
}
