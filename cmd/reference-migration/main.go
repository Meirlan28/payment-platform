package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/example/payment-platform/internal/schemamigration"
	"github.com/example/payment-platform/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
)

type options struct {
	action          string
	generation      int64
	expectedVersion int64
	batchSize       int
	maxBatches      int64
	consumerID      string
	required        bool
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(); err != nil {
		logger.Error("reference migration failed", "error", err)
		os.Exit(1)
	}
}

func run() error {
	var command options
	flag.StringVar(&command.action, "action", "status",
		"status|start|backfill|verify|cutover|register-consumer|ack-consumer|contract")
	flag.Int64Var(&command.generation, "generation", 0, "active migration generation")
	flag.Int64Var(&command.expectedVersion, "expected-version", -1,
		"required durable control state_version for a phase transition")
	flag.IntVar(&command.batchSize, "batch-size", 1000, "rows per serializable backfill transaction")
	flag.Int64Var(&command.maxBatches, "max-batches", 0, "bounded batch count; zero runs through watermark")
	flag.StringVar(&command.consumerID, "consumer", "", "deployment consumer identifier")
	flag.BoolVar(&command.required, "required", true, "consumer is a required contract barrier")
	flag.Parse()

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return errors.New("DATABASE_URL is required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return fmt.Errorf("parse DATABASE_URL: %w", err)
	}
	if (config.ConnConfig.TLSConfig == nil || config.ConnConfig.TLSConfig.InsecureSkipVerify) &&
		os.Getenv("ALLOW_INSECURE_DATABASE") != "true" {
		return errors.New("verified TLS is required; set ALLOW_INSECURE_DATABASE=true only in an isolated integration environment")
	}
	config.MaxConns = 4
	config.MinConns = 1
	config.MaxConnLifetime = 30 * time.Minute
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return fmt.Errorf("connect database: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("ping database: %w", err)
	}
	workflow, err := schemamigration.NewWorkflow(store.NewRunner(pool), command.batchSize)
	if err != nil {
		return err
	}

	switch command.action {
	case "status":
		status, err := workflow.Status(ctx)
		return emit(status, err)
	case "start":
		if command.expectedVersion < 0 {
			return errors.New("--expected-version is required for start")
		}
		status, err := workflow.Start(ctx, command.expectedVersion)
		return emit(status, err)
	case "backfill":
		if command.generation <= 0 || command.maxBatches < 0 {
			return errors.New("positive --generation and non-negative --max-batches are required")
		}
		report, err := workflow.Backfill(ctx, command.generation, command.maxBatches)
		return emit(report, err)
	case "verify":
		if err := requireTransition(command); err != nil {
			return err
		}
		verification, status, err := workflow.Verify(ctx, command.generation, command.expectedVersion)
		if err != nil {
			return err
		}
		return emit(map[string]any{
			"status":           status,
			"generation":       verification.Generation,
			"source_rows":      verification.SourceRows,
			"projected_rows":   verification.ProjectedRows,
			"source_digest":    hex.EncodeToString(verification.SourceDigest[:]),
			"projected_digest": hex.EncodeToString(verification.ProjectedDigest[:]),
		}, nil)
	case "cutover":
		if err := requireTransition(command); err != nil {
			return err
		}
		status, err := workflow.Cutover(ctx, command.generation, command.expectedVersion)
		return emit(status, err)
	case "register-consumer":
		if command.consumerID == "" {
			return errors.New("--consumer is required")
		}
		return workflow.RegisterConsumer(ctx, command.consumerID, command.required)
	case "ack-consumer":
		if command.consumerID == "" || command.generation <= 0 {
			return errors.New("--consumer and positive --generation are required")
		}
		return workflow.AcknowledgeConsumer(ctx, command.consumerID, command.generation)
	case "contract":
		if err := requireTransition(command); err != nil {
			return err
		}
		status, err := workflow.Contract(ctx, command.generation, command.expectedVersion)
		return emit(status, err)
	default:
		return fmt.Errorf("unknown --action %q", command.action)
	}
}

func requireTransition(command options) error {
	if command.generation <= 0 || command.expectedVersion < 0 {
		return errors.New("positive --generation and non-negative --expected-version are required")
	}
	return nil
}

func emit(value any, err error) error {
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}
