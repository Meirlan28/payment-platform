package escrow

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Allocate moves authority from the unallocated bucket into one region. The
// effect ID is a durable economic identifier supplied by the caller; it must
// be reused after every timeout or ambiguous commit result.
func (s *Service) Allocate(ctx context.Context, request EffectRequest) (EffectReceipt, error) {
	var receipt EffectReceipt
	if err := request.validate(); err != nil {
		return receipt, err
	}
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var err error
		receipt, err = AllocateInTx(ctx, tx, request)
		return err
	})
	if err != nil {
		return EffectReceipt{}, mapEffectDatabaseError(err)
	}
	return receipt, nil
}

// AllocateInTx is provided for workflows that must allocate authority and
// persist another durable fact atomically.
func AllocateInTx(ctx context.Context, tx pgx.Tx, request EffectRequest) (EffectReceipt, error) {
	return applyEffect(ctx, tx, EffectAllocate, request, func() error {
		tag, err := tx.Exec(ctx, `
UPDATE escrow_authorities
SET unallocated=unallocated-$3, version=version+1
WHERE account_id=$1 AND asset_id=$2 AND unallocated >= $3`,
			request.AccountID, request.AssetID, request.Amount.String())
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrInsufficientRights
		}
		_, err = tx.Exec(ctx, `
INSERT INTO escrow_regional_rights (account_id, asset_id, region, available)
VALUES ($1, $2, $3, $4)
ON CONFLICT (account_id, asset_id, region) DO UPDATE
SET available=escrow_regional_rights.available+excluded.available,
    version=escrow_regional_rights.version+1,
    updated_at=transaction_timestamp()`, request.AccountID, request.AssetID,
			request.Region, request.Amount.String())
		return err
	})
}

// Spend is the entire partition-time authorization decision: no read replica
// or cached balance participates in it.
func (s *Service) Spend(ctx context.Context, request EffectRequest) (EffectReceipt, error) {
	var receipt EffectReceipt
	if err := request.validate(); err != nil {
		return receipt, err
	}
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var err error
		receipt, err = SpendInTx(ctx, tx, request)
		return err
	})
	if err != nil {
		return EffectReceipt{}, mapEffectDatabaseError(err)
	}
	return receipt, nil
}

// SpendInTx consumes rights in the same SERIALIZABLE transaction as the
// corresponding ledger debit. The same stable effect ID must identify both
// facts so a retry cannot apply either half twice.
func SpendInTx(ctx context.Context, tx pgx.Tx, request EffectRequest) (EffectReceipt, error) {
	return applyEffect(ctx, tx, EffectSpend, request, func() error {
		tag, err := tx.Exec(ctx, `
UPDATE escrow_regional_rights
SET available=available-$4, version=version+1, updated_at=transaction_timestamp()
WHERE account_id=$1 AND asset_id=$2 AND region=$3 AND available >= $4`,
			request.AccountID, request.AssetID, request.Region, request.Amount.String())
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrInsufficientRights
		}
		// total_authority tracks current, not historical, spendable authority.
		// Decreasing it preserves unallocated + regional + in_transit = total.
		tag, err = tx.Exec(ctx, `
UPDATE escrow_authorities
SET total_authority=total_authority-$3, version=version+1
WHERE account_id=$1 AND asset_id=$2 AND total_authority >= $3`,
			request.AccountID, request.AssetID, request.Amount.String())
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("escrow authority inconsistent: %w", ErrInsufficientRights)
		}
		return nil
	})
}

// Return restores previously consumed regional authority. Its receipt is
// committed with the associated reversal/refund when ReturnInTx is used.
func (s *Service) Return(ctx context.Context, request EffectRequest) (EffectReceipt, error) {
	var receipt EffectReceipt
	if err := request.validate(); err != nil {
		return receipt, err
	}
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var err error
		receipt, err = ReturnInTx(ctx, tx, request)
		return err
	})
	if err != nil {
		return EffectReceipt{}, mapEffectDatabaseError(err)
	}
	return receipt, nil
}

func ReturnInTx(ctx context.Context, tx pgx.Tx, request EffectRequest) (EffectReceipt, error) {
	return applyEffect(ctx, tx, EffectReturn, request, func() error {
		tag, err := tx.Exec(ctx, `
UPDATE escrow_regional_rights
SET available=available+$4, version=version+1, updated_at=transaction_timestamp()
WHERE account_id=$1 AND asset_id=$2 AND region=$3`,
			request.AccountID, request.AssetID, request.Region, request.Amount.String())
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrInvalidArgument
		}
		tag, err = tx.Exec(ctx, `
UPDATE escrow_authorities
SET total_authority=total_authority+$3, version=version+1
WHERE account_id=$1 AND asset_id=$2`,
			request.AccountID, request.AssetID, request.Amount.String())
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errors.New("escrow authority disappeared during return")
		}
		return nil
	})
}

func applyEffect(ctx context.Context, tx pgx.Tx, kind EffectKind, request EffectRequest, mutate func() error) (EffectReceipt, error) {
	if tx == nil || mutate == nil || !kind.valid() {
		return EffectReceipt{}, ErrInvalidArgument
	}
	if err := request.validate(); err != nil {
		return EffectReceipt{}, err
	}
	hash := hashEffect(kind, request)
	receipt := EffectReceipt{EffectID: request.EffectID, Kind: kind, RequestHash: hash}
	tag, err := tx.Exec(ctx, `
INSERT INTO escrow_effect_receipts
    (effect_id, effect_kind, account_id, asset_id, region, amount, request_hash)
VALUES ($1,$2,$3,$4,$5,$6,$7)
ON CONFLICT (effect_id) DO NOTHING`, request.EffectID, string(kind), request.AccountID,
		request.AssetID, request.Region, request.Amount.String(), hash[:])
	if err != nil {
		return EffectReceipt{}, err
	}
	if tag.RowsAffected() == 0 {
		var storedKind, accountID, assetID, region, amountText string
		var storedHash []byte
		if err := tx.QueryRow(ctx, `
SELECT effect_kind, account_id, asset_id, region, amount::STRING, request_hash
FROM escrow_effect_receipts
WHERE effect_id=$1`, request.EffectID).Scan(&storedKind, &accountID, &assetID,
			&region, &amountText, &storedHash); err != nil {
			return EffectReceipt{}, err
		}
		if storedKind != string(kind) || accountID != request.AccountID || assetID != request.AssetID ||
			region != request.Region || amountText != request.Amount.String() || !bytes.Equal(storedHash, hash[:]) {
			return EffectReceipt{}, ErrEffectConflict
		}
		receipt.Duplicate = true
		return receipt, nil
	}
	if err := mutate(); err != nil {
		return EffectReceipt{}, err
	}
	return receipt, nil
}

func hashEffect(kind EffectKind, request EffectRequest) [sha256.Size]byte {
	h := sha256.New()
	h.Write([]byte("payment-platform/escrow-effect/v1\x00"))
	for _, value := range []string{string(kind), request.EffectID, request.AccountID,
		request.AssetID, request.Region, request.Amount.String()} {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(value)))
		h.Write(length[:])
		h.Write([]byte(value))
	}
	var result [sha256.Size]byte
	copy(result[:], h.Sum(nil))
	return result
}

func mapEffectDatabaseError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23503" {
		return ErrInsufficientRights
	}
	return err
}
