//go:build integration

package saga

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCoordinatorCrashResumeAndCompensation(t *testing.T) {
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
	if _, err := pool.Exec(ctx, `
CREATE TABLE IF NOT EXISTS saga_test_effects (
  effect_id STRING PRIMARY KEY,
  kind STRING NOT NULL
)`); err != nil {
		t.Fatal(err)
	}
	definition := Definition{Name: "failing-payment", Steps: []Step{
		{
			Name: "reserve",
			Execute: func(ctx context.Context, tx pgx.Tx, action ActionContext) (ActionResult, error) {
				_, err := tx.Exec(ctx, `INSERT INTO saga_test_effects(effect_id,kind) VALUES($1,'RESERVE') ON CONFLICT DO NOTHING`, action.Step.EffectID)
				return Done([]byte("reserved")), err
			},
			Compensate: func(ctx context.Context, tx pgx.Tx, action ActionContext) (ActionResult, error) {
				_, err := tx.Exec(ctx, `INSERT INTO saga_test_effects(effect_id,kind) VALUES($1,'RELEASE') ON CONFLICT DO NOTHING`, action.Step.EffectID+"/compensate")
				return Done(nil), err
			},
		},
		{
			Name: "settle",
			Execute: func(context.Context, pgx.Tx, ActionContext) (ActionResult, error) {
				return ActionResult{}, Permanent(errors.New("bank rejected settlement"))
			},
		},
	}}
	orchestrator, err := New(pool, definition)
	if err != nil {
		t.Fatal(err)
	}
	sagaID := "saga-" + sagaSuffix(t)
	if _, err := orchestrator.Start(ctx, sagaID, "PAYMENT", definition.Name, []byte(`{"amount":"10"}`)); err != nil {
		t.Fatal(err)
	}
	if tick, err := orchestrator.Tick(ctx, sagaID); err != nil || !tick.Progress || tick.Instance.CurrentStep != 1 {
		t.Fatalf("reserve tick = %#v, %v", tick, err)
	}
	// Drop the coordinator object: all restart state must come from SQL.
	orchestrator, err = New(pool, definition)
	if err != nil {
		t.Fatal(err)
	}
	tick, err := orchestrator.Tick(ctx, sagaID)
	if err == nil || tick.Instance.Status != Compensating {
		t.Fatalf("permanent failure = %#v, %v", tick, err)
	}
	if tick, err = orchestrator.Tick(ctx, sagaID); err != nil || !tick.Progress {
		t.Fatalf("compensation = %#v, %v", tick, err)
	}
	if tick, err = orchestrator.Tick(ctx, sagaID); err != nil || tick.Instance.Status != Compensated {
		t.Fatalf("terminal compensation = %#v, %v", tick, err)
	}
	var reserve, release int
	if err := pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE kind='RESERVE'), count(*) FILTER (WHERE kind='RELEASE') FROM saga_test_effects WHERE effect_id LIKE $1`, "saga/"+sagaID+"/%").Scan(&reserve, &release); err != nil {
		t.Fatal(err)
	}
	if reserve != 1 || release != 1 {
		t.Fatalf("effects reserve=%d release=%d", reserve, release)
	}
}

func sagaSuffix(t *testing.T) string {
	t.Helper()
	var value [12]byte
	if _, err := rand.Read(value[:]); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(value[:])
}
