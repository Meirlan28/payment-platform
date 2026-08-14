package offline

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/example/payment-platform/internal/ledger"
	"github.com/example/payment-platform/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	statePrepared = "PREPARED"
	stateIssued   = "ISSUED"
	stateRedeemed = "REDEEMED"
	stateRevoked  = "REVOKED"
	stateExpired  = "EXPIRED"
)

type Service struct {
	transactions *store.Runner
	ids          ledger.IDGenerator
	signer       Signer
	verifier     Verifier
	presentationVerifier PresentationVerifier
	closureVerifier      ClosureVerifier
}

func NewService(
	transactions *store.Runner,
	ids ledger.IDGenerator,
	signer Signer,
	verifier Verifier,
	presentationVerifier PresentationVerifier,
	closureVerifier ClosureVerifier,
) *Service {
	return &Service{
		transactions: transactions, ids: ids, signer: signer, verifier: verifier,
		presentationVerifier: presentationVerifier, closureVerifier: closureVerifier,
	}
}

// ConfigureAcceptanceDomain installs immutable closure-key coverage. In
// production this method is exposed only through the ledger-admin control
// plane; the payment runtime has SELECT-only privileges on the table.
func (s *Service) ConfigureAcceptanceDomain(ctx context.Context, domain AcceptanceDomain) error {
	if s == nil || s.transactions == nil {
		return ErrInvalidArgument
	}
	if err := domain.validate(); err != nil {
		return err
	}
	first, _ := checkedInt64(domain.FirstSettlementEpoch)
	var last *int64
	if domain.LastSettlementEpoch != 0 {
		value, _ := checkedInt64(domain.LastSettlementEpoch)
		last = &value
	}
	return s.transactions.RunSerializable(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
INSERT INTO offline_acceptance_domains
 (acceptance_domain, closure_key_id, first_settlement_epoch, last_settlement_epoch)
VALUES ($1,$2,$3,$4)
ON CONFLICT (acceptance_domain) DO NOTHING`, domain.Name, domain.ClosureKeyID, first, last)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 1 {
			return nil
		}
		var key string
		var storedFirst int64
		var storedLast *int64
		if err := tx.QueryRow(ctx, `
SELECT closure_key_id, first_settlement_epoch, last_settlement_epoch
FROM offline_acceptance_domains WHERE acceptance_domain=$1`, domain.Name).Scan(
			&key, &storedFirst, &storedLast); err != nil {
			return err
		}
		if key != domain.ClosureKeyID || storedFirst != first || !sameNullableInt64(storedLast, last) {
			return ErrAcceptanceDomain
		}
		return nil
	})
}

// NewAllowanceID delegates uniqueness to the durable issuer-prefix /
// incarnation / counter generator. It never derives uniqueness from a clock.
func (s *Service) NewAllowanceID(ctx context.Context) (string, error) {
	if s == nil || s.ids == nil {
		return "", fmt.Errorf("%w: durable ID generator is not configured", ErrInvalidArgument)
	}
	return s.ids.Next(ctx)
}

// EnrollDevice creates the durable issuer epoch and counter namespace. The
// referenced region must already own escrow rights; enrollment is explicit so
// an authorization request cannot silently enroll an attacker-controlled key.
func (s *Service) EnrollDevice(ctx context.Context, device Device) error {
	if s == nil || s.transactions == nil {
		return ErrInvalidArgument
	}
	if err := device.validate(); err != nil {
		return err
	}
	epoch, _ := checkedInt64(device.IssuerEpoch)
	return s.transactions.RunSerializable(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
INSERT INTO offline_device_counters
 (account_id, asset_id, origin_region, device_identity_hash, issuer_epoch)
VALUES ($1,$2,$3,$4,$5)
ON CONFLICT (account_id, asset_id, origin_region, device_identity_hash) DO NOTHING`,
			device.AccountID, device.AssetID, device.OriginRegion,
			device.DeviceIdentityHash[:], epoch)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 1 {
			return nil
		}
		var storedEpoch int64
		if err := tx.QueryRow(ctx, `
SELECT issuer_epoch FROM offline_device_counters
WHERE account_id=$1 AND asset_id=$2 AND origin_region=$3 AND device_identity_hash=$4`,
			device.AccountID, device.AssetID, device.OriginRegion,
			device.DeviceIdentityHash[:]).Scan(&storedEpoch); err != nil {
			return err
		}
		if storedEpoch != epoch {
			return ErrDeviceConflict
		}
		return nil
	})
}

// AdvanceIssuerEpoch establishes a new monotonic fencing namespace and resets
// its per-device counter. Existing signed allowances retain their old epoch
// and remain governed by their individual durable state.
func (s *Service) AdvanceIssuerEpoch(ctx context.Context, device Device, nextEpoch uint64) error {
	if s == nil || s.transactions == nil {
		return ErrInvalidArgument
	}
	if err := device.validate(); err != nil {
		return err
	}
	current, _ := checkedInt64(device.IssuerEpoch)
	next, err := checkedInt64(nextEpoch)
	if err != nil || next != current+1 {
		return ErrInvalidArgument
	}
	return s.transactions.RunSerializable(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
UPDATE offline_device_counters
SET issuer_epoch=$5, last_counter=0, fence_version=fence_version+1,
    updated_at=transaction_timestamp()
WHERE account_id=$1 AND asset_id=$2 AND origin_region=$3
  AND device_identity_hash=$4 AND issuer_epoch=$6`,
			device.AccountID, device.AssetID, device.OriginRegion,
			device.DeviceIdentityHash[:], next, current)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 1 {
			return nil
		}
		var stored int64
		err = tx.QueryRow(ctx, `
SELECT issuer_epoch FROM offline_device_counters
WHERE account_id=$1 AND asset_id=$2 AND origin_region=$3 AND device_identity_hash=$4`,
			device.AccountID, device.AssetID, device.OriginRegion,
			device.DeviceIdentityHash[:]).Scan(&stored)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrDeviceConflict
		}
		if err != nil {
			return err
		}
		if stored == next {
			return nil
		}
		return ErrDeviceConflict
	})
}

// Issue is crash recoverable when retried with the same AllowanceID. First it
// durably reserves a never-reused device counter without moving authority,
// then calls the HSM outside a database transaction, and finally performs the
// financial issuance transition in one SERIALIZABLE transaction.
func (s *Service) Issue(ctx context.Context, request IssueRequest) (Allowance, error) {
	if s == nil || s.transactions == nil || s.signer == nil || s.verifier == nil {
		return Allowance{}, ErrInvalidArgument
	}
	if err := request.validate(); err != nil {
		return Allowance{}, err
	}
	// The durable certificate is checked before contacting the HSM. Therefore
	// a successful issuance whose ACK was lost remains retryable even while the
	// signer control plane is unavailable.
	existing, state, found, err := s.lookupExisting(ctx, request)
	if err != nil {
		return Allowance{}, err
	}
	if found && state != statePrepared {
		return existing, nil
	}
	if found {
		return s.signAndActivate(ctx, existing)
	}
	activeKeyID, err := s.signer.ActiveKeyID(ctx)
	if err != nil {
		return Allowance{}, fmt.Errorf("offline: resolve active signing key: %w", err)
	}
	if !validText(activeKeyID) {
		return Allowance{}, fmt.Errorf("%w: HSM returned an invalid key id", ErrInvalidArgument)
	}
	prepared, state, err := s.prepare(ctx, request, activeKeyID)
	if err != nil {
		return Allowance{}, err
	}
	if state != statePrepared {
		return prepared, nil
	}
	return s.signAndActivate(ctx, prepared)
}

func (s *Service) signAndActivate(ctx context.Context, prepared Allowance) (Allowance, error) {
	payload, err := prepared.CanonicalPayload()
	if err != nil {
		return Allowance{}, err
	}
	signature, err := s.signer.Sign(ctx, prepared.KeyID, payload)
	if err != nil {
		return Allowance{}, fmt.Errorf("offline: HSM sign allowance: %w", err)
	}
	prepared.Signature = append([]byte(nil), signature...)
	verified, err := s.Verify(ctx, prepared)
	if err != nil {
		return Allowance{}, err
	}
	return s.activate(ctx, verified)
}

func (s *Service) Verify(ctx context.Context, allowance Allowance) (VerifiedAllowance, error) {
	if s == nil {
		return VerifiedAllowance{}, ErrInvalidArgument
	}
	return verifyAllowance(ctx, s.verifier, allowance)
}

func (s *Service) VerifyPresentation(
	ctx context.Context,
	presentation Presentation,
) (VerifiedPresentation, error) {
	if s == nil {
		return VerifiedPresentation{}, ErrInvalidArgument
	}
	return verifyPresentation(ctx, s.verifier, s.presentationVerifier, presentation)
}

func (s *Service) lookupExisting(ctx context.Context, request IssueRequest) (Allowance, string, bool, error) {
	var result Allowance
	var state string
	var found bool
	err := s.transactions.RunSerializable(ctx, func(tx pgx.Tx) error {
		var err error
		result, state, found, err = loadAllowance(ctx, tx, request.AllowanceID, false)
		if err != nil || !found {
			return err
		}
		if !matchesIssueRequest(result, request) {
			return ErrAllowanceConflict
		}
		return nil
	})
	return result, state, found, err
}

func (s *Service) prepare(ctx context.Context, request IssueRequest, activeKeyID string) (Allowance, string, error) {
	var result Allowance
	var resultState string
	err := s.transactions.RunSerializable(ctx, func(tx pgx.Tx) error {
		stored, state, found, err := loadAllowance(ctx, tx, request.AllowanceID, true)
		if err != nil {
			return err
		}
		if found {
			if !matchesIssueRequest(stored, request) {
				return ErrAllowanceConflict
			}
			result, resultState = stored, state
			return nil
		}

		var epoch, lastCounter int64
		err = tx.QueryRow(ctx, `
SELECT issuer_epoch, last_counter FROM offline_device_counters
WHERE account_id=$1 AND asset_id=$2 AND origin_region=$3 AND device_identity_hash=$4
FOR UPDATE`, request.AccountID, request.AssetID, request.OriginRegion,
			request.DeviceIdentityHash[:]).Scan(&epoch, &lastCounter)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrDeviceConflict
		}
		if err != nil {
			return err
		}
		var acceptanceDomains int64
		if err := tx.QueryRow(ctx, `
SELECT count(*) FROM offline_acceptance_domains
WHERE first_settlement_epoch <= $1
  AND (last_settlement_epoch IS NULL OR last_settlement_epoch >= $1)`, epoch).Scan(
			&acceptanceDomains); err != nil {
			return err
		}
		if acceptanceDomains == 0 {
			return ErrAcceptanceDomain
		}
		if lastCounter == math.MaxInt64 {
			return ErrCounterExhausted
		}
		counter := lastCounter + 1
		tag, err := tx.Exec(ctx, `
UPDATE offline_device_counters
SET last_counter=$5, updated_at=transaction_timestamp()
WHERE account_id=$1 AND asset_id=$2 AND origin_region=$3
  AND device_identity_hash=$4 AND last_counter=$6`,
			request.AccountID, request.AssetID, request.OriginRegion,
			request.DeviceIdentityHash[:], counter, lastCounter)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrDeviceConflict
		}
		candidate := Allowance{
			Version: AllowanceVersion, AllowanceID: request.AllowanceID,
			AccountID: request.AccountID, AssetID: request.AssetID,
			OriginRegion: request.OriginRegion, DeviceIdentityHash: request.DeviceIdentityHash,
			Counter: uint64(counter), Amount: request.Amount, IssuerEpoch: uint64(epoch),
			KeyID: activeKeyID,
		}
		payload, err := candidate.CanonicalPayload()
		if err != nil {
			return err
		}
		hash := allowanceHash(payload)
		_, err = tx.Exec(ctx, `
INSERT INTO offline_allowances
 (allowance_id, account_id, asset_id, origin_region, device_identity_hash,
  device_counter, amount, issuer_epoch, key_id, canonical_payload, payload_hash)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
			candidate.AllowanceID, candidate.AccountID, candidate.AssetID,
			candidate.OriginRegion, candidate.DeviceIdentityHash[:], counter,
			candidate.Amount.String(), epoch, candidate.KeyID, payload, hash[:])
		if err != nil {
			return err
		}
		result, resultState = candidate, statePrepared
		return nil
	})
	return result, resultState, err
}

// activate contains the complete economic issuance commit. PREPARED rows are
// harmless counter reservations and are deliberately outside conservation.
func (s *Service) activate(ctx context.Context, verified VerifiedAllowance) (Allowance, error) {
	var result Allowance
	err := s.transactions.RunSerializable(ctx, func(tx pgx.Tx) error {
		stored, state, found, err := loadAllowance(ctx, tx, verified.allowance.AllowanceID, true)
		if err != nil {
			return err
		}
		if !found {
			return ErrAllowanceNotFound
		}
		if !sameVerifiedAllowance(stored, verified) {
			return ErrAllowanceConflict
		}
		if state != statePrepared {
			result = stored
			return nil
		}
		var currentEpoch int64
		err = tx.QueryRow(ctx, `
SELECT issuer_epoch FROM offline_device_counters
WHERE account_id=$1 AND asset_id=$2 AND origin_region=$3 AND device_identity_hash=$4
FOR UPDATE`, stored.AccountID, stored.AssetID, stored.OriginRegion,
			stored.DeviceIdentityHash[:]).Scan(&currentEpoch)
		if err != nil {
			return err
		}
		if currentEpoch != int64(stored.IssuerEpoch) {
			return ErrFenceConflict
		}

		tag, err := tx.Exec(ctx, `
UPDATE escrow_regional_rights
SET available=available-$4, version=version+1, updated_at=transaction_timestamp()
WHERE account_id=$1 AND asset_id=$2 AND region=$3 AND available >= $4`,
			stored.AccountID, stored.AssetID, stored.OriginRegion, stored.Amount.String())
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrInsufficientRights
		}
		_, err = tx.Exec(ctx, `
INSERT INTO escrow_offline_issued (account_id, asset_id, origin_region, amount)
VALUES ($1,$2,$3,$4)
ON CONFLICT (account_id, asset_id, origin_region) DO UPDATE
SET amount=escrow_offline_issued.amount+excluded.amount,
    version=escrow_offline_issued.version+1,
    updated_at=transaction_timestamp()`,
			stored.AccountID, stored.AssetID, stored.OriginRegion, stored.Amount.String())
		if err != nil {
			return err
		}
		tag, err = tx.Exec(ctx, `
UPDATE offline_allowances
SET signature=$2, state='ISSUED', issued_at=transaction_timestamp()
WHERE allowance_id=$1 AND state='PREPARED'`, stored.AllowanceID, verified.allowance.Signature)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrAllowanceConflict
		}
		stored.Signature = append([]byte(nil), verified.allowance.Signature...)
		result = stored
		return nil
	})
	return result, err
}

// RedeemAndPost is the only standalone redemption entry point. It accepts an
// opaque value previously returned by VerifyPresentation; a bare/copyable
// allowance is never sufficient. The immutable ledger effect, permanent
// presentation/challenge receipt, and authority consumption commit together.
func (s *Service) RedeemAndPost(
	ctx context.Context,
	verified VerifiedPresentation,
	journal *ledger.Service,
	posting ledger.PostRequest,
) (AtomicRedemption, error) {
	if s == nil || s.transactions == nil || journal == nil {
		return AtomicRedemption{}, ErrInvalidArgument
	}
	if err := posting.Validate(); err != nil {
		return AtomicRedemption{}, err
	}
	if err := validateVerifiedPresentation(verified); err != nil {
		return AtomicRedemption{}, err
	}
	if err := validatePostingForPresentation(verified, posting); err != nil {
		return AtomicRedemption{}, err
	}
	effect := RedemptionEffect{
		EffectID: posting.EffectID, LedgerTransactionID: posting.TransactionID,
		PostingRequestHash: posting.RequestHash,
	}
	var result AtomicRedemption
	err = s.transactions.RunSerializable(ctx, func(tx pgx.Tx) error {
		ledgerReceipt, inner := journal.PostInTx(ctx, tx, posting)
		if inner != nil {
			return inner
		}
		allowanceReceipt, inner := s.RedeemPresentationInTx(ctx, tx, verified, effect)
		if inner != nil {
			return inner
		}
		result = AtomicRedemption{Allowance: allowanceReceipt, Ledger: ledgerReceipt}
		return nil
	})
	return result, err
}

// RedeemPresentationInTx is intended to run immediately after
// ledger.Service.PostInTx in the same transaction. Its receipt insert is
// rejected by the database unless that matching effect is already POSTED. The
// allowance and device signatures were verified outside the retryable
// transaction; the opaque type prevents HSM calls or bypasses in-tx.
func (s *Service) RedeemPresentationInTx(
	ctx context.Context,
	tx pgx.Tx,
	verified VerifiedPresentation,
	effect RedemptionEffect,
) (Redemption, error) {
	if s == nil || tx == nil {
		return Redemption{}, ErrInvalidArgument
	}
	if err := validateVerifiedPresentation(verified); err != nil {
		return Redemption{}, err
	}
	effectHash, err := effect.Hash()
	if err != nil {
		return Redemption{}, err
	}
	result := Redemption{AllowanceID: verified.presentation.Allowance.AllowanceID, EffectHash: effectHash}
	stored, state, found, err := loadAllowance(ctx, tx, verified.presentation.Allowance.AllowanceID, true)
	if err != nil {
		return Redemption{}, err
	}
	if !found {
		return Redemption{}, ErrAllowanceNotFound
	}
	if !sameVerifiedAllowance(stored, verified.allowance) {
		return Redemption{}, ErrAllowanceConflict
	}

	storedReceipt, receiptFound, err := loadRedemptionReceipt(ctx, tx, stored.AllowanceID)
	if err != nil {
		return Redemption{}, err
	}
	if receiptFound {
		if !sameRedemption(storedReceipt, verified, effectHash, effect) {
			return Redemption{}, ErrRedemptionConflict
		}
		result.Duplicate = true
		return result, nil
	}
	if state == stateRedeemed {
		return Redemption{}, fmt.Errorf("%w: receipt missing", ErrConservationViolation)
	}
	if state == stateRevoked || state == stateExpired {
		return Redemption{}, ErrAllowanceTerminal
	}
	if state != stateIssued {
		return Redemption{}, ErrNotIssued
	}

	_, err = tx.Exec(ctx, `
INSERT INTO offline_redemption_receipts
 (allowance_id, payload_hash, effect_hash, effect_id,
  ledger_transaction_id, posting_request_hash, presentation_payload_hash,
  presentation_hash, merchant_account_id, acceptance_domain, challenge_hash,
  settlement_epoch, upload_fence, presentation_counter, device_identity_hash,
  device_key_id, presentation_payload, presentation_signature)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
		stored.AllowanceID, verified.allowance.payloadHash[:], effectHash[:],
		effect.EffectID, effect.LedgerTransactionID, effect.PostingRequestHash[:],
		verified.payloadHash[:], verified.presentationHash[:],
		verified.presentation.MerchantAccountID, verified.presentation.AcceptanceDomain,
		verified.challengeHash[:], int64(verified.presentation.SettlementEpoch),
		int64(verified.presentation.UploadFence), int64(verified.presentation.PresentationCounter),
		verified.presentation.Allowance.DeviceIdentityHash[:], verified.presentation.DeviceKeyID,
		verified.payload, verified.presentation.Signature)
	if err != nil {
		var databaseError *pgconn.PgError
		if errors.As(err, &databaseError) && databaseError.Code == "23505" {
			return Redemption{}, ErrRedemptionConflict
		}
		return Redemption{}, err
	}
	tag, err := tx.Exec(ctx, `
UPDATE escrow_offline_issued
SET amount=amount-$4, version=version+1, updated_at=transaction_timestamp()
WHERE account_id=$1 AND asset_id=$2 AND origin_region=$3 AND amount >= $4`,
		stored.AccountID, stored.AssetID, stored.OriginRegion, stored.Amount.String())
	if err != nil {
		return Redemption{}, err
	}
	if tag.RowsAffected() != 1 {
		return Redemption{}, ErrConservationViolation
	}
	tag, err = tx.Exec(ctx, `
UPDATE escrow_authorities
SET total_authority=total_authority-$3, version=version+1
WHERE account_id=$1 AND asset_id=$2 AND total_authority >= $3`,
		stored.AccountID, stored.AssetID, stored.Amount.String())
	if err != nil {
		return Redemption{}, err
	}
	if tag.RowsAffected() != 1 {
		return Redemption{}, ErrConservationViolation
	}
	tag, err = tx.Exec(ctx, `
UPDATE offline_allowances
SET state='REDEEMED', redeemed_at=transaction_timestamp()
WHERE allowance_id=$1 AND state='ISSUED'`, stored.AllowanceID)
	if err != nil {
		return Redemption{}, err
	}
	if tag.RowsAffected() != 1 {
		return Redemption{}, ErrConservationViolation
	}
	return result, nil
}

// Terminate returns an outstanding allowance to its origin region only after
// every configured acceptance domain independently signs a logical closure
// watermark covering the allowance. Absence of a database receipt alone is
// never treated as proof: a presentation may still be delayed offline.
func (s *Service) Terminate(ctx context.Context, request FenceRequest) (NonRedemptionProof, error) {
	if s == nil || s.transactions == nil || s.closureVerifier == nil {
		return NonRedemptionProof{}, ErrInvalidArgument
	}
	if err := request.validate(); err != nil {
		return NonRedemptionProof{}, err
	}
	canonicalClosures, err := canonicalizeClosureSet(request)
	if err != nil {
		return NonRedemptionProof{}, err
	}
	// A lost-ACK retry of an already committed termination does not depend on
	// the HSM control plane. Only exact durable proof semantics are accepted.
	var existing NonRedemptionProof
	var found bool
	err = s.transactions.RunSerializable(ctx, func(tx pgx.Tx) error {
		var inner error
		existing, found, inner = loadProof(ctx, tx, request.AllowanceID)
		return inner
	})
	if err != nil {
		return NonRedemptionProof{}, err
	}
	if found {
		if !matchesProof(existing, request, canonicalClosures.setHash) {
			return NonRedemptionProof{}, ErrFenceConflict
		}
		existing.Duplicate = true
		return existing, nil
	}
	closures, err := verifyClosureSet(ctx, s.closureVerifier, request)
	if err != nil {
		return NonRedemptionProof{}, err
	}
	var result NonRedemptionProof
	err = s.transactions.RunSerializable(ctx, func(tx pgx.Tx) error {
		var inner error
		result, inner = s.terminateVerifiedInTx(ctx, tx, request, closures)
		return inner
	})
	return result, err
}

func (s *Service) terminateVerifiedInTx(
	ctx context.Context,
	tx pgx.Tx,
	request FenceRequest,
	closures verifiedClosureSet,
) (NonRedemptionProof, error) {
	if s == nil || tx == nil {
		return NonRedemptionProof{}, ErrInvalidArgument
	}
	if err := request.validate(); err != nil {
		return NonRedemptionProof{}, err
	}
	if len(closures.byDomain) == 0 || closures.setHash == ([32]byte{}) {
		return NonRedemptionProof{}, ErrIncompleteClosure
	}
	stored, state, found, err := loadAllowance(ctx, tx, request.AllowanceID, true)
	if err != nil {
		return NonRedemptionProof{}, err
	}
	if !found {
		return NonRedemptionProof{}, ErrAllowanceNotFound
	}
	if stored.IssuerEpoch != request.ExpectedIssuerEpoch ||
		stored.Counter != request.ExpectedDeviceCounter {
		return NonRedemptionProof{}, ErrFenceConflict
	}
	payloadHash, err := stored.PayloadHash()
	if err != nil || payloadHash != request.ExpectedPayloadHash {
		return NonRedemptionProof{}, ErrFenceConflict
	}
	if proof, proofFound, err := loadProof(ctx, tx, request.AllowanceID); err != nil {
		return NonRedemptionProof{}, err
	} else if proofFound {
		if !matchesProof(proof, request, closures.setHash) {
			return NonRedemptionProof{}, ErrFenceConflict
		}
		proof.Duplicate = true
		return proof, nil
	}
	if state == stateRedeemed {
		return NonRedemptionProof{}, ErrAlreadyRedeemed
	}
	if state == stateRevoked || state == stateExpired {
		return NonRedemptionProof{}, ErrConservationViolation
	}
	if state != stateIssued {
		return NonRedemptionProof{}, ErrNotIssued
	}
	if err := validateAndPersistClosures(ctx, tx, stored, closures); err != nil {
		return NonRedemptionProof{}, err
	}
	if _, receiptFound, err := loadRedemptionReceipt(ctx, tx, stored.AllowanceID); err != nil {
		return NonRedemptionProof{}, err
	} else if receiptFound {
		return NonRedemptionProof{}, ErrAlreadyRedeemed
	}

	var epoch, lastCounter, fenceVersion int64
	err = tx.QueryRow(ctx, `
SELECT issuer_epoch, last_counter, fence_version
FROM offline_device_counters
WHERE account_id=$1 AND asset_id=$2 AND origin_region=$3 AND device_identity_hash=$4
FOR UPDATE`, stored.AccountID, stored.AssetID, stored.OriginRegion,
		stored.DeviceIdentityHash[:]).Scan(&epoch, &lastCounter, &fenceVersion)
	if err != nil {
		return NonRedemptionProof{}, err
	}
	if lastCounter < int64(stored.Counter) || epoch < int64(stored.IssuerEpoch) || fenceVersion == math.MaxInt64 {
		return NonRedemptionProof{}, ErrFenceConflict
	}
	nextFence := fenceVersion + 1
	tag, err := tx.Exec(ctx, `
UPDATE offline_device_counters
SET fence_version=$5, updated_at=transaction_timestamp()
WHERE account_id=$1 AND asset_id=$2 AND origin_region=$3
  AND device_identity_hash=$4 AND fence_version=$6`,
		stored.AccountID, stored.AssetID, stored.OriginRegion,
		stored.DeviceIdentityHash[:], nextFence, fenceVersion)
	if err != nil {
		return NonRedemptionProof{}, err
	}
	if tag.RowsAffected() != 1 {
		return NonRedemptionProof{}, ErrFenceConflict
	}
	tag, err = tx.Exec(ctx, `
UPDATE escrow_offline_issued
SET amount=amount-$4, version=version+1, updated_at=transaction_timestamp()
WHERE account_id=$1 AND asset_id=$2 AND origin_region=$3 AND amount >= $4`,
		stored.AccountID, stored.AssetID, stored.OriginRegion, stored.Amount.String())
	if err != nil {
		return NonRedemptionProof{}, err
	}
	if tag.RowsAffected() != 1 {
		return NonRedemptionProof{}, ErrConservationViolation
	}
	tag, err = tx.Exec(ctx, `
UPDATE escrow_regional_rights
SET available=available+$4, version=version+1, updated_at=transaction_timestamp()
WHERE account_id=$1 AND asset_id=$2 AND region=$3`,
		stored.AccountID, stored.AssetID, stored.OriginRegion, stored.Amount.String())
	if err != nil {
		return NonRedemptionProof{}, err
	}
	if tag.RowsAffected() != 1 {
		return NonRedemptionProof{}, ErrConservationViolation
	}
	tag, err = tx.Exec(ctx, `
UPDATE offline_allowances
SET state=$2, terminal_at=transaction_timestamp()
WHERE allowance_id=$1 AND state='ISSUED'`, stored.AllowanceID, string(request.Kind))
	if err != nil {
		return NonRedemptionProof{}, err
	}
	if tag.RowsAffected() != 1 {
		return NonRedemptionProof{}, ErrConservationViolation
	}
	proofHash := hashProof(request, uint64(nextFence), closures.setHash)
	_, err = tx.Exec(ctx, `
INSERT INTO offline_non_redemption_proofs
 (allowance_id, terminal_kind, payload_hash, issuer_epoch, device_counter,
  fence_version, policy_evidence_hash, closure_set_hash, proof_hash)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, stored.AllowanceID, string(request.Kind),
		request.ExpectedPayloadHash[:], int64(request.ExpectedIssuerEpoch),
		int64(request.ExpectedDeviceCounter), nextFence,
		request.PolicyEvidenceHash[:], closures.setHash[:], proofHash[:])
	if err != nil {
		return NonRedemptionProof{}, err
	}
	return NonRedemptionProof{
		AllowanceID: stored.AllowanceID, Kind: request.Kind,
		PayloadHash: request.ExpectedPayloadHash, IssuerEpoch: request.ExpectedIssuerEpoch,
		DeviceCounter: request.ExpectedDeviceCounter, FenceVersion: uint64(nextFence),
		PolicyEvidenceHash: request.PolicyEvidenceHash, ClosureSetHash: closures.setHash,
		ProofHash: proofHash,
	}, nil
}

func validateAndPersistClosures(
	ctx context.Context,
	tx pgx.Tx,
	allowance Allowance,
	closures verifiedClosureSet,
) error {
	rows, err := tx.Query(ctx, `
SELECT acceptance_domain, closure_key_id
FROM offline_acceptance_domains
WHERE first_settlement_epoch <= $1
  AND (last_settlement_epoch IS NULL OR last_settlement_epoch >= $1)
ORDER BY acceptance_domain`, int64(allowance.IssuerEpoch))
	if err != nil {
		return err
	}
	defer rows.Close()
	required := 0
	for rows.Next() {
		var domain, keyID string
		if err := rows.Scan(&domain, &keyID); err != nil {
			return err
		}
		required++
		value, ok := closures.byDomain[domain]
		if !ok || value.closure.KeyID != keyID ||
			value.closure.ClosedSettlementEpoch < allowance.IssuerEpoch ||
			(value.closure.ClosedSettlementEpoch == allowance.IssuerEpoch &&
				value.closure.ClosedUploadFence < allowance.Counter) {
			return ErrIncompleteClosure
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()
	if required == 0 || required != len(closures.byDomain) {
		return ErrIncompleteClosure
	}
	for domain, value := range closures.byDomain {
		_, err := tx.Exec(ctx, `
INSERT INTO offline_domain_closure_evidence
 (evidence_hash, acceptance_domain, closed_settlement_epoch,
  closed_upload_fence, key_id, payload_hash, canonical_payload, signature)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
ON CONFLICT (evidence_hash) DO NOTHING`, value.evidenceHash[:], domain,
			int64(value.closure.ClosedSettlementEpoch), int64(value.closure.ClosedUploadFence),
			value.closure.KeyID, value.payloadHash[:], value.payload, value.closure.Signature)
		if err != nil {
			return err
		}
		var storedDomain, storedKey string
		var storedEpoch, storedFence int64
		var storedPayloadHash, storedPayload, storedSignature []byte
		if err := tx.QueryRow(ctx, `
SELECT acceptance_domain, closed_settlement_epoch, closed_upload_fence,
       key_id, payload_hash, canonical_payload, signature
FROM offline_domain_closure_evidence WHERE evidence_hash=$1`, value.evidenceHash[:]).Scan(
			&storedDomain, &storedEpoch, &storedFence, &storedKey, &storedPayloadHash,
			&storedPayload, &storedSignature); err != nil {
			return err
		}
		if storedDomain != domain || storedKey != value.closure.KeyID ||
			storedEpoch != int64(value.closure.ClosedSettlementEpoch) ||
			storedFence != int64(value.closure.ClosedUploadFence) ||
			!bytes.Equal(storedPayloadHash, value.payloadHash[:]) ||
			!bytes.Equal(storedPayload, value.payload) ||
			!bytes.Equal(storedSignature, value.closure.Signature) {
			return ErrFenceConflict
		}
		_, err = tx.Exec(ctx, `
INSERT INTO offline_termination_closure_links
 (allowance_id, acceptance_domain, evidence_hash)
VALUES ($1,$2,$3)`, allowance.AllowanceID, domain, value.evidenceHash[:])
		if err != nil {
			return err
		}
	}
	return nil
}

// Snapshot reads all five authority buckets and an independent fold of
// outstanding allowance facts at one SERIALIZABLE snapshot.
func (s *Service) Snapshot(ctx context.Context, accountID, assetID string) (ConservationSnapshot, error) {
	if s == nil || s.transactions == nil || !validText(accountID) || !validText(assetID) {
		return ConservationSnapshot{}, ErrInvalidArgument
	}
	result := ConservationSnapshot{AccountID: accountID, AssetID: assetID}
	err := s.transactions.RunSerializable(ctx, func(tx pgx.Tx) error {
		var total, unallocated, regional, transit, offlineIssued, folded string
		err := tx.QueryRow(ctx, `
SELECT total_authority::STRING, unallocated::STRING, regional::STRING,
       in_transit::STRING, offline_issued::STRING, folded_offline_issued::STRING
FROM escrow_authority_conservation
WHERE account_id=$1 AND asset_id=$2`, accountID, assetID).Scan(
			&total, &unallocated, &regional, &transit, &offlineIssued, &folded)
		if err != nil {
			return err
		}
		values := []*ledger.Amount{
			&result.TotalAuthority, &result.Unallocated, &result.Regional,
			&result.InTransit, &result.OfflineIssued, &result.FoldedOutstanding,
		}
		for index, raw := range []string{total, unallocated, regional, transit, offlineIssued, folded} {
			parsed, err := ledger.ParseAmount(raw)
			if err != nil {
				return err
			}
			*values[index] = parsed
		}
		return nil
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ConservationSnapshot{}, ErrAllowanceNotFound
	}
	return result, err
}

func (s *Service) CheckConservation(ctx context.Context, accountID, assetID string) error {
	snapshot, err := s.Snapshot(ctx, accountID, assetID)
	if err != nil {
		return err
	}
	if !snapshot.Conserved() {
		return fmt.Errorf("%w: total=%s unallocated=%s regional=%s in_transit=%s offline=%s folded=%s",
			ErrConservationViolation, snapshot.TotalAuthority.String(), snapshot.Unallocated.String(),
			snapshot.Regional.String(), snapshot.InTransit.String(), snapshot.OfflineIssued.String(),
			snapshot.FoldedOutstanding.String())
	}
	return nil
}

type storedReceipt struct {
	payloadHash         [32]byte
	effectHash          [32]byte
	presentationPayloadHash [32]byte
	presentationHash    [32]byte
	challengeHash       [32]byte
	effectID            string
	ledgerTransactionID string
	postingRequestHash  [32]byte
	merchantAccountID   string
	acceptanceDomain    string
	settlementEpoch     uint64
	uploadFence         uint64
	presentationCounter uint64
	deviceIdentityHash  [32]byte
	deviceKeyID         string
}

func loadAllowance(ctx context.Context, tx pgx.Tx, allowanceID string, lock bool) (Allowance, string, bool, error) {
	query := `
SELECT account_id, asset_id, origin_region, device_identity_hash,
       device_counter, amount::STRING, issuer_epoch, key_id,
       canonical_payload, payload_hash, signature, state
FROM offline_allowances WHERE allowance_id=$1`
	if lock {
		query += " FOR UPDATE"
	}
	var result Allowance
	var deviceHash, payload, hash, signature []byte
	var counter, epoch int64
	var amountText, state string
	err := tx.QueryRow(ctx, query, allowanceID).Scan(
		&result.AccountID, &result.AssetID, &result.OriginRegion, &deviceHash,
		&counter, &amountText, &epoch, &result.KeyID, &payload, &hash, &signature, &state)
	if errors.Is(err, pgx.ErrNoRows) {
		return Allowance{}, "", false, nil
	}
	if err != nil {
		return Allowance{}, "", false, err
	}
	if len(deviceHash) != 32 || len(hash) != 32 || counter <= 0 || epoch <= 0 {
		return Allowance{}, "", false, ErrConservationViolation
	}
	result.Version = AllowanceVersion
	result.AllowanceID = allowanceID
	copy(result.DeviceIdentityHash[:], deviceHash)
	result.Counter, result.IssuerEpoch = uint64(counter), uint64(epoch)
	result.Signature = append([]byte(nil), signature...)
	result.Amount, err = ledger.ParseAmount(amountText)
	if err != nil {
		return Allowance{}, "", false, err
	}
	actualPayload, err := result.CanonicalPayload()
	if err != nil || !bytes.Equal(actualPayload, payload) {
		return Allowance{}, "", false, ErrConservationViolation
	}
	actualHash := allowanceHash(actualPayload)
	if !bytes.Equal(actualHash[:], hash) {
		return Allowance{}, "", false, ErrConservationViolation
	}
	return result, state, true, nil
}

func loadRedemptionReceipt(ctx context.Context, tx pgx.Tx, allowanceID string) (storedReceipt, bool, error) {
	var result storedReceipt
	var payloadHash, effectHash, postingHash, presentationPayloadHash,
		presentationHash, challengeHash, deviceIdentityHash []byte
	var settlementEpoch, uploadFence, presentationCounter int64
	err := tx.QueryRow(ctx, `
SELECT payload_hash, effect_hash, effect_id, ledger_transaction_id, posting_request_hash,
       presentation_payload_hash, presentation_hash, merchant_account_id,
       acceptance_domain, challenge_hash, settlement_epoch, upload_fence,
       presentation_counter, device_identity_hash, device_key_id
FROM offline_redemption_receipts WHERE allowance_id=$1`, allowanceID).Scan(
		&payloadHash, &effectHash, &result.effectID, &result.ledgerTransactionID, &postingHash,
		&presentationPayloadHash, &presentationHash, &result.merchantAccountID,
		&result.acceptanceDomain, &challengeHash, &settlementEpoch, &uploadFence,
		&presentationCounter, &deviceIdentityHash, &result.deviceKeyID)
	if errors.Is(err, pgx.ErrNoRows) {
		return storedReceipt{}, false, nil
	}
	if err != nil {
		return storedReceipt{}, false, err
	}
	if len(payloadHash) != 32 || len(effectHash) != 32 || len(postingHash) != 32 ||
		len(presentationPayloadHash) != 32 || len(presentationHash) != 32 ||
		len(challengeHash) != 32 || len(deviceIdentityHash) != 32 ||
		settlementEpoch <= 0 || uploadFence <= 0 || presentationCounter <= 0 ||
		!validText(result.merchantAccountID) || !validText(result.acceptanceDomain) ||
		!validText(result.deviceKeyID) {
		return storedReceipt{}, false, ErrConservationViolation
	}
	copy(result.payloadHash[:], payloadHash)
	copy(result.effectHash[:], effectHash)
	copy(result.postingRequestHash[:], postingHash)
	copy(result.presentationPayloadHash[:], presentationPayloadHash)
	copy(result.presentationHash[:], presentationHash)
	copy(result.challengeHash[:], challengeHash)
	copy(result.deviceIdentityHash[:], deviceIdentityHash)
	result.settlementEpoch = uint64(settlementEpoch)
	result.uploadFence = uint64(uploadFence)
	result.presentationCounter = uint64(presentationCounter)
	return result, true, nil
}

func loadProof(ctx context.Context, tx pgx.Tx, allowanceID string) (NonRedemptionProof, bool, error) {
	var result NonRedemptionProof
	var kind string
	var payloadHash, evidenceHash, closureSetHash, proofHash []byte
	var epoch, counter, fence int64
	err := tx.QueryRow(ctx, `
SELECT terminal_kind, payload_hash, issuer_epoch, device_counter,
       fence_version, policy_evidence_hash, closure_set_hash, proof_hash
FROM offline_non_redemption_proofs WHERE allowance_id=$1`, allowanceID).Scan(
		&kind, &payloadHash, &epoch, &counter, &fence, &evidenceHash, &closureSetHash, &proofHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return NonRedemptionProof{}, false, nil
	}
	if err != nil {
		return NonRedemptionProof{}, false, err
	}
	if len(payloadHash) != 32 || len(evidenceHash) != 32 || len(closureSetHash) != 32 ||
		len(proofHash) != 32 ||
		epoch <= 0 || counter <= 0 || fence <= 0 {
		return NonRedemptionProof{}, false, ErrConservationViolation
	}
	result.AllowanceID, result.Kind = allowanceID, TerminalKind(kind)
	result.IssuerEpoch, result.DeviceCounter, result.FenceVersion = uint64(epoch), uint64(counter), uint64(fence)
	copy(result.PayloadHash[:], payloadHash)
	copy(result.PolicyEvidenceHash[:], evidenceHash)
	copy(result.ClosureSetHash[:], closureSetHash)
	copy(result.ProofHash[:], proofHash)
	return result, true, nil
}

func matchesProof(proof NonRedemptionProof, request FenceRequest, closureHash [32]byte) bool {
	return proof.Kind == request.Kind && proof.PayloadHash == request.ExpectedPayloadHash &&
		proof.IssuerEpoch == request.ExpectedIssuerEpoch &&
		proof.DeviceCounter == request.ExpectedDeviceCounter &&
		proof.PolicyEvidenceHash == request.PolicyEvidenceHash &&
		proof.ClosureSetHash == closureHash &&
		proof.ProofHash == hashProof(request, proof.FenceVersion, closureHash)
}

func matchesIssueRequest(allowance Allowance, request IssueRequest) bool {
	return allowance.AllowanceID == request.AllowanceID && allowance.AccountID == request.AccountID &&
		allowance.AssetID == request.AssetID && allowance.OriginRegion == request.OriginRegion &&
		allowance.DeviceIdentityHash == request.DeviceIdentityHash && allowance.Amount.Cmp(request.Amount) == 0
}

func sameVerifiedAllowance(stored Allowance, verified VerifiedAllowance) bool {
	hash, err := stored.PayloadHash()
	return err == nil && hash == verified.payloadHash
}

func sameRedemption(
	stored storedReceipt,
	verified VerifiedPresentation,
	effectHash [32]byte,
	effect RedemptionEffect,
) bool {
	p := verified.presentation
	return stored.payloadHash == verified.allowance.payloadHash && stored.effectHash == effectHash &&
		stored.effectID == effect.EffectID && stored.ledgerTransactionID == effect.LedgerTransactionID &&
		stored.postingRequestHash == effect.PostingRequestHash &&
		stored.presentationPayloadHash == verified.payloadHash &&
		stored.presentationHash == verified.presentationHash &&
		stored.challengeHash == verified.challengeHash &&
		stored.merchantAccountID == p.MerchantAccountID &&
		stored.acceptanceDomain == p.AcceptanceDomain &&
		stored.settlementEpoch == p.SettlementEpoch && stored.uploadFence == p.UploadFence &&
		stored.presentationCounter == p.PresentationCounter &&
		stored.deviceIdentityHash == p.Allowance.DeviceIdentityHash &&
		stored.deviceKeyID == p.DeviceKeyID
}

func validateVerifiedPresentation(verified VerifiedPresentation) error {
	if len(verified.payload) == 0 || verified.payloadHash == ([32]byte{}) ||
		verified.presentationHash == ([32]byte{}) || verified.challengeHash == ([32]byte{}) ||
		verified.allowance.payloadHash == ([32]byte{}) ||
		verified.presentation.AllowancePayloadHash != verified.allowance.payloadHash {
		return ErrInvalidPresentation
	}
	return nil
}

func validatePostingForPresentation(verified VerifiedPresentation, posting ledger.PostRequest) error {
	allowance := verified.presentation.Allowance
	var debited ledger.Amount
	var credited ledger.Amount
	for _, line := range posting.Lines {
		if line.AssetID == allowance.AssetID && line.AccountID == allowance.AccountID &&
			line.Side == ledger.Debit {
			var err error
			debited, err = debited.Add(line.AmountAtoms)
			if err != nil {
				return fmt.Errorf("%w: source debit overflow", ErrPostingMismatch)
			}
		}
		if line.AssetID == allowance.AssetID &&
			line.AccountID == verified.presentation.MerchantAccountID &&
			line.Side == ledger.Credit {
			var err error
			credited, err = credited.Add(line.AmountAtoms)
			if err != nil {
				return fmt.Errorf("%w: merchant credit overflow", ErrPostingMismatch)
			}
		}
	}
	if debited.Cmp(allowance.Amount) != 0 || credited.Cmp(allowance.Amount) != 0 {
		return fmt.Errorf("%w: debit=%s merchant_credit=%s allowance=%s merchant=%s",
			ErrPostingMismatch, debited.String(), credited.String(), allowance.Amount.String(),
			verified.presentation.MerchantAccountID)
	}
	return nil
}

func sameNullableInt64(left, right *int64) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
