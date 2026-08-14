//go:build integration

package authz

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCapabilitiesAreExactRevocableAndReadOnlyAtRuntime(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	suffix := fmt.Sprintf("authz-%d", time.Now().UnixNano())
	assetID, bookID, accountID := "asset-"+suffix, "book-"+suffix, "account-"+suffix
	principal := "spiffe://payments.test/tenant/" + suffix
	zeroHash, evidence := make([]byte, 32), make([]byte, 32)
	evidence[0] = 1
	if _, err := pool.Exec(ctx, `INSERT INTO assets (asset_id, display_code, atomic_scale) VALUES ($1,$2,0)`,
		assetID, "AUTHZ-"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO books
 (book_id, legal_entity_id, jurisdiction, last_entry_hash) VALUES ($1,'entity','KZ',$2)`,
		bookID, zeroHash); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO accounts
 (account_id, book_id, asset_id, account_type, normal_side) VALUES ($1,$2,$3,'ASSET','DEBIT')`,
		accountID, bookID, assetID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO payment_account_capabilities
 (capability_id, principal_id, book_id, account_id, permission, policy_version, granted_by, evidence_hash)
VALUES ($1,$2,$3,$4,$5,'policy-v1','security-admin',$6)`,
		"capability-"+suffix, principal, bookID, accountID, AuthorizePayerAvailable, evidence); err != nil {
		t.Fatal(err)
	}

	connection, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Release()
	tx, err := connection.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE payment_authorizer`); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	service, err := New(tx)
	if err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if err := service.Authorize(ctx, Request{Principal: principal, BookID: bookID, Accounts: []AccountPermission{{
		AccountID: accountID, Permission: AuthorizePayerAvailable,
	}}}); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("exact active capability rejected: %v", err)
	}
	if !errors.Is(service.Authorize(ctx, Request{Principal: principal + "-attacker", BookID: bookID, Accounts: []AccountPermission{{
		AccountID: accountID, Permission: AuthorizePayerAvailable,
	}}}), ErrDenied) {
		_ = tx.Rollback(ctx)
		t.Fatal("different principal inherited another principal's capability")
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	restricted, err := connection.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restricted.Exec(ctx, `SET LOCAL ROLE payment_authorizer`); err != nil {
		_ = restricted.Rollback(ctx)
		t.Fatal(err)
	}
	if _, err := restricted.Exec(ctx, `INSERT INTO payment_account_capabilities
 (capability_id, principal_id, book_id, account_id, permission, policy_version, granted_by, evidence_hash)
 VALUES ('forged',$1,$2,$3,$4,'v','attacker',$5)`, principal, bookID, accountID, CaptureFee, evidence); err == nil {
		_ = restricted.Rollback(ctx)
		t.Fatal("read-only payment_authorizer forged a capability")
	}
	_ = restricted.Rollback(ctx)

	if _, err := pool.Exec(ctx, `INSERT INTO payment_account_capability_revocations
 (capability_id, revoked_by, reason_code, evidence_hash) VALUES ($1,'security-admin','ACCESS_REVOKED',$2)`,
		"capability-"+suffix, evidence); err != nil {
		t.Fatal(err)
	}
	service, err = New(pool)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(service.Authorize(ctx, Request{Principal: principal, BookID: bookID, Accounts: []AccountPermission{{
		AccountID: accountID, Permission: AuthorizePayerAvailable,
	}}}), ErrDenied) {
		t.Fatal("revoked capability remained active")
	}
	if _, err := pool.Exec(ctx, `UPDATE payment_account_capabilities SET policy_version='tampered' WHERE capability_id=$1`, "capability-"+suffix); err == nil {
		t.Fatal("append-only capability was mutable")
	}
}
