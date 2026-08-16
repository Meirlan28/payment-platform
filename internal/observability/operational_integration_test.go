//go:build integration

package observability

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
)

func TestReconciliationRuntimeCanCollectOperationalSnapshot(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL is not set")
	}
	configuration, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	configuration.MaxConns = 1
	configuration.AfterConnect = func(ctx context.Context, connection *pgx.Conn) error {
		_, err := connection.Exec(ctx, `SET ROLE reconciliation_runtime`)
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, configuration)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	collector, err := NewOperationalCollector(pool, NewFinancialMetrics(prometheus.NewRegistry()))
	if err != nil {
		t.Fatal(err)
	}
	if err := collector.Collect(ctx, "integration-region"); err != nil {
		t.Fatal(err)
	}
}
