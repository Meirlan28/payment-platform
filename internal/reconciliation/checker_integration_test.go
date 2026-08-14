//go:build integration

package reconciliation

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/example/payment-platform/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRuntimeRolePersistsAConsistentFinancialReport(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL is not set")
	}
	ctx := context.Background()
	configuration, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	configuration.MaxConns = 2
	configuration.AfterConnect = func(ctx context.Context, connection *pgx.Conn) error {
		_, err := connection.Exec(ctx, `SET ROLE reconciliation_runtime`)
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, configuration)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	checker, err := NewChecker(store.NewRunner(pool))
	if err != nil {
		t.Fatal(err)
	}
	report, err := checker.Run(ctx, fmt.Sprintf("runtime-role-%d", time.Now().UnixNano()))
	if err != nil {
		t.Fatal(err)
	}
	if !report.Safe() || report.Status != "PASSED" {
		t.Fatalf("financial reconciliation found a P0 break: %#v", report.Findings)
	}
	if len(report.Watermarks) == 0 {
		t.Fatal("report did not persist any closed ledger watermark")
	}
}
