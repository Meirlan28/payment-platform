package pii

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/example/payment-platform/internal/ledger"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrIdentityDeleted    = errors.New("identity mapping was deleted")
	ErrDeletionInProgress = errors.New("identity deletion is owned by another request")
)

type Identity struct {
	IdentityID   string
	Jurisdiction string
	Attributes   map[string]string
}

type Service struct {
	// RegionalDB must contain physically separate, jurisdiction-local
	// clusters. A shared global pool is deliberately not accepted: choosing a
	// KMS region alone does not prove ciphertext or metadata residency.
	RegionalDB map[string]*pgxpool.Pool
	Regional   map[string]KeyManager
	IDs        ledger.IDGenerator
}

func (s *Service) Create(ctx context.Context, jurisdiction string, attributes map[string]string) (string, error) {
	if s == nil || s.IDs == nil || jurisdiction == "" || attributes == nil {
		return "", errors.New("PII service is not fully configured")
	}
	db, err := s.database(jurisdiction)
	if err != nil {
		return "", err
	}
	kms, ok := s.Regional[jurisdiction]
	if !ok {
		return "", fmt.Errorf("no jurisdiction-local KMS configured for %q", jurisdiction)
	}
	identitySuffix, err := s.IDs.Next(ctx)
	if err != nil {
		return "", err
	}
	keySuffix, err := s.IDs.Next(ctx)
	if err != nil {
		return "", err
	}
	if identitySuffix == "" || keySuffix == "" {
		return "", errors.New("PII ID generator returned an empty id")
	}
	identityID := "pty_" + identitySuffix
	keyName := "pii-" + keySuffix
	plaintext, err := json.Marshal(attributes)
	if err != nil {
		return "", fmt.Errorf("marshal PII attributes: %w", err)
	}
	aad := []byte(jurisdiction + "\x00" + identityID)
	ciphertext, err := kms.Encrypt(ctx, keyName, plaintext, aad)
	if err != nil {
		return "", fmt.Errorf("encrypt PII: %w", err)
	}
	_, err = db.Exec(ctx, `
		INSERT INTO pii.identity_mappings
		  (identity_id, jurisdiction, vault_key_name, ciphertext, state)
		VALUES ($1, $2, $3, $4, 'ACTIVE')`, identityID, jurisdiction, keyName, ciphertext)
	if err != nil {
		// Do not leave live orphaned subject keys when the mapping cannot commit.
		_ = kms.DestroyKey(ctx, keyName)
		return "", fmt.Errorf("store PII mapping: %w", err)
	}
	return identityID, nil
}

func (s *Service) Get(ctx context.Context, jurisdiction, identityID string) (*Identity, error) {
	if s == nil || jurisdiction == "" || identityID == "" {
		return nil, errors.New("PII service is not fully configured")
	}
	db, err := s.database(jurisdiction)
	if err != nil {
		return nil, err
	}
	kms, ok := s.Regional[jurisdiction]
	if !ok {
		return nil, fmt.Errorf("no jurisdiction-local KMS configured for %q", jurisdiction)
	}
	var storedJurisdiction, keyName, ciphertext, state string
	err = db.QueryRow(ctx, `
		SELECT jurisdiction, vault_key_name, ciphertext, state
		FROM pii.identity_mappings
		WHERE identity_id = $1 AND jurisdiction = $2`, identityID, jurisdiction).
		Scan(&storedJurisdiction, &keyName, &ciphertext, &state)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrIdentityDeleted
	}
	if err != nil {
		return nil, err
	}
	if state != "ACTIVE" {
		return nil, ErrIdentityDeleted
	}
	plaintext, err := kms.Decrypt(ctx, keyName, ciphertext, []byte(storedJurisdiction+"\x00"+identityID))
	if err != nil {
		return nil, fmt.Errorf("decrypt PII: %w", err)
	}
	var attributes map[string]string
	if err := json.Unmarshal(plaintext, &attributes); err != nil {
		return nil, fmt.Errorf("decode PII: %w", err)
	}
	return &Identity{IdentityID: identityID, Jurisdiction: storedJurisdiction, Attributes: attributes}, nil
}

// RequestDeletion is a restart-safe three-state crypto-shredding workflow.
// The financial journal is not touched and contains only the opaque identity ID.
func (s *Service) RequestDeletion(ctx context.Context, jurisdiction, identityID, requestID string) error {
	if s == nil || jurisdiction == "" || identityID == "" || requestID == "" {
		return errors.New("PII deletion request is incomplete")
	}
	db, err := s.database(jurisdiction)
	if err != nil {
		return err
	}
	kms, ok := s.Regional[jurisdiction]
	if !ok {
		return fmt.Errorf("no jurisdiction-local KMS configured for %q", jurisdiction)
	}
	var keyName string
	err = db.QueryRow(ctx, `
		UPDATE pii.identity_mappings
		SET state = 'DELETION_PENDING',
		    deletion_request_id = CASE WHEN state='ACTIVE' THEN $3 ELSE deletion_request_id END
		WHERE identity_id = $1 AND jurisdiction = $2
		  AND (state='ACTIVE' OR (state='DELETION_PENDING' AND deletion_request_id=$3))
		RETURNING vault_key_name`, identityID, jurisdiction, requestID).Scan(&keyName)
	if errors.Is(err, pgx.ErrNoRows) {
		// A completed retry is idempotent if its receipt exists.
		var exists bool
		if scanErr := db.QueryRow(ctx, `SELECT true FROM pii.deletion_receipts WHERE request_id = $1`, requestID).Scan(&exists); scanErr == nil && exists {
			return nil
		}
		var state, owner string
		scanErr := db.QueryRow(ctx, `
SELECT state, coalesce(deletion_request_id,'')
FROM pii.identity_mappings WHERE identity_id=$1 AND jurisdiction=$2`,
			identityID, jurisdiction).Scan(&state, &owner)
		if scanErr == nil && state == "DELETION_PENDING" && owner != requestID {
			return ErrDeletionInProgress
		}
		return ErrIdentityDeleted
	}
	if err != nil {
		return fmt.Errorf("mark deletion pending: %w", err)
	}
	if err := kms.DestroyKey(ctx, keyName); err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	commandTag, err := tx.Exec(ctx, `
		DELETE FROM pii.identity_mappings
		WHERE identity_id = $1 AND jurisdiction = $2 AND deletion_request_id = $3`, identityID, jurisdiction, requestID)
	if err != nil {
		return err
	}
	if commandTag.RowsAffected() == 0 {
		return errors.New("PII deletion lost its fencing request")
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO pii.deletion_receipts(request_id, jurisdiction, result)
		VALUES ($1, $2, 'KEY_DESTROYED_AND_MAPPING_DELETED')
		ON CONFLICT (request_id) DO NOTHING`, requestID, jurisdiction); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Service) database(jurisdiction string) (*pgxpool.Pool, error) {
	if s == nil || jurisdiction == "" || s.RegionalDB == nil {
		return nil, errors.New("PII jurisdiction-local database routing is not configured")
	}
	db, ok := s.RegionalDB[jurisdiction]
	if !ok || db == nil {
		return nil, fmt.Errorf("no jurisdiction-local PII database configured for %q", jurisdiction)
	}
	return db, nil
}
