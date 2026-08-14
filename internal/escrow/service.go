package escrow

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/example/payment-platform/internal/ledger"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const defaultSerializableRetries = 8

type Service struct {
	db            DB
	signer        CertificateSigner
	receiptSigner ConsumptionReceiptSigner
	verifier      KeyResolver
	retries       int
}

// NewService constructs a local authority service or a source-side transfer
// service. Destination consumption is deliberately disabled unless a bound
// destination receipt signer is supplied through NewTransferService.
func NewService(db DB, signer CertificateSigner, verifier KeyResolver) *Service {
	return NewTransferService(db, signer, nil, verifier)
}

func NewTransferService(
	db DB,
	signer CertificateSigner,
	receiptSigner ConsumptionReceiptSigner,
	verifier KeyResolver,
) *Service {
	return &Service{
		db: db, signer: signer, receiptSigner: receiptSigner,
		verifier: verifier, retries: defaultSerializableRetries,
	}
}

func (s *Service) CreateAuthority(ctx context.Context, accountID, assetID string, total ledger.Amount) error {
	if s.db == nil || accountID == "" || assetID == "" || total.Sign() < 0 {
		return ErrInvalidArgument
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
INSERT INTO escrow_authorities (account_id, asset_id, total_authority, unallocated)
VALUES ($1, $2, $3, $3)
ON CONFLICT (account_id, asset_id) DO NOTHING`, accountID, assetID, total.String())
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 1 {
			return nil
		}
		var existingText string
		if err := tx.QueryRow(ctx, `
SELECT total_authority::STRING FROM escrow_authorities
WHERE account_id=$1 AND asset_id=$2`, accountID, assetID).Scan(&existingText); err != nil {
			return err
		}
		existing, err := ledger.ParseAmount(existingText)
		if err != nil {
			return err
		}
		if existing.Cmp(total) != 0 {
			return ErrAuthorityConflict
		}
		return nil
	})
}

// InitiateTransfer reserves the source issuance tuple and moves authority into
// IN_TRANSIT in one SERIALIZABLE transaction. HSM/KMS signing intentionally
// happens after that commit; a crash leaves an unsigned durable draft which a
// retry of the same TransferID signs without burning rights again.
func (s *Service) InitiateTransfer(ctx context.Context, request TransferRequest) (Certificate, error) {
	if err := validateTransferRequest(request); err != nil || s.signer == nil || s.verifier == nil {
		return Certificate{}, ErrInvalidArgument
	}
	binding := s.signer.Binding()
	if !binding.validFor(KeyPurposeTransferCertificate) ||
		binding.Region != request.SourceRegion ||
		binding.LegalEntityID != request.SourceLegalEntityID {
		return Certificate{}, ErrCertificateInvalid
	}

	var draft Certificate
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		record, found, err := loadTransferRecord(ctx, tx, request.TransferID)
		if err != nil {
			return err
		}
		if found {
			if !sameTransfer(record.Certificate, request) {
				return ErrCertificateConflict
			}
			draft = record.Certificate
			return nil
		}

		var availableText string
		var version int64
		err = tx.QueryRow(ctx, `
SELECT available::STRING, version FROM escrow_regional_rights
WHERE account_id=$1 AND asset_id=$2 AND region=$3
FOR UPDATE`, request.AccountID, request.AssetID, request.SourceRegion).
			Scan(&availableText, &version)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInsufficientRights
		}
		if err != nil {
			return err
		}
		available, err := ledger.ParseAmount(availableText)
		if err != nil {
			return err
		}
		if available.Cmp(request.Amount) < 0 || version == math.MaxInt64 {
			return ErrInsufficientRights
		}
		epoch := version + 1
		draft = Certificate{
			Version: certificateVersion, TransferID: request.TransferID,
			AccountID: request.AccountID, AssetID: request.AssetID,
			SourceRegion:             request.SourceRegion,
			DestinationRegion:        request.DestinationRegion,
			SourceLegalEntityID:      request.SourceLegalEntityID,
			DestinationLegalEntityID: request.DestinationLegalEntityID,
			Amount:                   request.Amount, SourceEpoch: uint64(epoch),
			KeyID: binding.KeyID, KeyEpoch: binding.Epoch,
		}
		payload, err := draft.Payload()
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `
UPDATE escrow_regional_rights
SET available=available-$4, version=$5, updated_at=transaction_timestamp()
WHERE account_id=$1 AND asset_id=$2 AND region=$3
  AND version=$6 AND available >= $4`,
			request.AccountID, request.AssetID, request.SourceRegion,
			request.Amount.String(), epoch, version)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrInsufficientRights
		}
		_, err = tx.Exec(ctx, `
INSERT INTO escrow_transfers
 (transfer_id, account_id, asset_id, source_region, destination_region,
  source_legal_entity_id, destination_legal_entity_id, amount, source_epoch,
  key_id, source_key_epoch, certificate_payload, certificate_sig)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NULL)`,
			draft.TransferID, draft.AccountID, draft.AssetID, draft.SourceRegion,
			draft.DestinationRegion, draft.SourceLegalEntityID,
			draft.DestinationLegalEntityID, draft.Amount.String(), draft.SourceEpoch,
			draft.KeyID, draft.KeyEpoch, payload)
		return err
	})
	if err != nil {
		return Certificate{}, err
	}
	if len(draft.Signature) == 0 {
		signed, err := s.signer.Sign(draft)
		if err != nil {
			return Certificate{}, err
		}
		if err := VerifyCertificate(signed, s.verifier); err != nil {
			return Certificate{}, err
		}
		if err := s.attachCertificateSignature(ctx, &draft, signed); err != nil {
			return Certificate{}, err
		}
	}
	if err := VerifyCertificate(draft, s.verifier); err != nil {
		return Certificate{}, err
	}
	return draft, nil
}

func validateTransferRequest(request TransferRequest) error {
	if request.TransferID == "" || request.AccountID == "" || request.AssetID == "" ||
		request.SourceRegion == "" || request.DestinationRegion == "" ||
		request.SourceRegion == request.DestinationRegion ||
		request.SourceLegalEntityID == "" || request.DestinationLegalEntityID == "" ||
		request.Amount.Sign() <= 0 {
		return ErrInvalidArgument
	}
	return nil
}

func (s *Service) attachCertificateSignature(ctx context.Context, result *Certificate, signed Certificate) error {
	payload, err := signed.Payload()
	if err != nil {
		return err
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		record, found, err := loadTransferRecord(ctx, tx, signed.TransferID)
		if err != nil {
			return err
		}
		if !found {
			return ErrCertificateConflict
		}
		storedPayload, err := record.Certificate.Payload()
		if err != nil || !bytes.Equal(storedPayload, payload) {
			return ErrCertificateConflict
		}
		if len(record.Certificate.Signature) == 0 {
			tag, err := tx.Exec(ctx, `
UPDATE escrow_transfers SET certificate_sig=$2
WHERE transfer_id=$1 AND certificate_sig IS NULL`, signed.TransferID, signed.Signature)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return ErrCertificateConflict
			}
			record.Certificate.Signature = append([]byte(nil), signed.Signature...)
		}
		*result = record.Certificate
		return nil
	})
}

// ConsumeCertificate performs the destination economic effect exactly once.
// The first transaction commits the rights and a durable unsigned receipt
// draft. Only after that commit is the draft signed and the signature attached
// by a second SERIALIZABLE transaction. A retry completes either phase.
func (s *Service) ConsumeCertificate(
	ctx context.Context,
	certificate Certificate,
	destinationRegion string,
) (Consumption, error) {
	if s.receiptSigner == nil || destinationRegion == "" ||
		certificate.DestinationRegion != destinationRegion {
		return Consumption{}, ErrCertificateInvalid
	}
	if err := VerifyCertificate(certificate, s.verifier); err != nil {
		return Consumption{}, err
	}
	binding := s.receiptSigner.Binding()
	if !binding.validFor(KeyPurposeConsumptionReceipt) ||
		binding.Region != destinationRegion ||
		binding.LegalEntityID != certificate.DestinationLegalEntityID {
		return Consumption{}, ErrConsumptionReceiptInvalid
	}
	certificateHash, err := certificate.PayloadHash()
	if err != nil {
		return Consumption{}, err
	}

	result := Consumption{TransferID: certificate.TransferID}
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		result.Duplicate = false
		if err := lockConsumptionIdentity(ctx, tx, certificate); err != nil {
			return err
		}
		stored, found, err := loadConsumptionByTransfer(ctx, tx, certificate.TransferID)
		if err != nil {
			return err
		}
		if found {
			if !receiptMatchesCertificate(stored, certificate, certificateHash) {
				return ErrCertificateConflict
			}
			result.Duplicate, result.Receipt = true, stored
			return nil
		}
		stored, found, err = loadConsumptionByIssuance(ctx, tx, certificate)
		if err != nil {
			return err
		}
		if found {
			return ErrCertificateConflict
		}

		watermark, err := nextConsumptionWatermark(ctx, tx, binding)
		if err != nil {
			return err
		}
		result.Receipt = ConsumptionReceipt{
			Version: consumptionReceiptVersion, TransferID: certificate.TransferID,
			CertificateHash: certificateHash, AccountID: certificate.AccountID,
			AssetID: certificate.AssetID, Amount: certificate.Amount,
			SourceRegion:        certificate.SourceRegion,
			SourceLegalEntityID: certificate.SourceLegalEntityID,
			SourceEpoch:         certificate.SourceEpoch, SourceKeyEpoch: certificate.KeyEpoch,
			DestinationRegion:          certificate.DestinationRegion,
			DestinationLegalEntityID:   certificate.DestinationLegalEntityID,
			DestinationCommitWatermark: watermark,
			KeyID:                      binding.KeyID, KeyEpoch: binding.Epoch,
		}
		receiptPayload, err := result.Receipt.Payload()
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `
INSERT INTO escrow_consumed_certificates
 (transfer_id, account_id, asset_id, source_region, destination_region, amount,
  payload_hash, source_legal_entity_id, source_key_epoch, source_epoch,
  destination_legal_entity_id, destination_key_id, destination_key_epoch,
  destination_watermark, receipt_payload, receipt_sig)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,NULL)`,
			certificate.TransferID, certificate.AccountID, certificate.AssetID,
			certificate.SourceRegion, certificate.DestinationRegion,
			certificate.Amount.String(), certificateHash[:],
			certificate.SourceLegalEntityID, certificate.KeyEpoch,
			certificate.SourceEpoch, certificate.DestinationLegalEntityID,
			binding.KeyID, binding.Epoch, watermark, receiptPayload)
		if err != nil {
			return err
		}
		// Each database owns its local authority total. During hand-off the
		// amount exists in source IN_TRANSIT and destination total; source ACK
		// atomically removes the former after verifying the signed receipt.
		_, err = tx.Exec(ctx, `
INSERT INTO escrow_authorities
 (account_id, asset_id, total_authority, unallocated)
VALUES ($1,$2,$3,0)
ON CONFLICT (account_id, asset_id) DO UPDATE
SET total_authority=escrow_authorities.total_authority+excluded.total_authority,
    version=escrow_authorities.version+1`,
			certificate.AccountID, certificate.AssetID, certificate.Amount.String())
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `
INSERT INTO escrow_regional_rights (account_id, asset_id, region, available)
VALUES ($1,$2,$3,$4)
ON CONFLICT (account_id, asset_id, region) DO UPDATE
SET available=escrow_regional_rights.available+excluded.available,
    version=escrow_regional_rights.version+1,
    updated_at=transaction_timestamp()`, certificate.AccountID, certificate.AssetID,
			certificate.DestinationRegion, certificate.Amount.String())
		return err
	})
	if err != nil {
		return Consumption{}, err
	}

	if len(result.Receipt.Signature) == 0 {
		signed, err := s.receiptSigner.SignReceipt(result.Receipt)
		if err != nil {
			return Consumption{}, err
		}
		if err := VerifyConsumptionReceipt(signed, certificate, s.verifier); err != nil {
			return Consumption{}, err
		}
		if err := s.attachReceiptSignature(ctx, certificate, &result.Receipt, signed); err != nil {
			return Consumption{}, err
		}
	}
	if err := VerifyConsumptionReceipt(result.Receipt, certificate, s.verifier); err != nil {
		return Consumption{}, err
	}
	return result, nil
}

func lockConsumptionIdentity(ctx context.Context, tx pgx.Tx, certificate Certificate) error {
	if _, err := tx.Exec(ctx, `
INSERT INTO escrow_consumption_transfer_locks (transfer_id)
VALUES ($1) ON CONFLICT (transfer_id) DO NOTHING`, certificate.TransferID); err != nil {
		return err
	}
	var transferID string
	if err := tx.QueryRow(ctx, `
SELECT transfer_id FROM escrow_consumption_transfer_locks
WHERE transfer_id=$1 FOR UPDATE`, certificate.TransferID).Scan(&transferID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO escrow_consumption_issuance_locks
 (source_legal_entity_id, source_region, source_key_epoch,
  account_id, asset_id, source_epoch)
VALUES ($1,$2,$3,$4,$5,$6)
ON CONFLICT (source_legal_entity_id, source_region, source_key_epoch,
             account_id, asset_id, source_epoch) DO NOTHING`,
		certificate.SourceLegalEntityID, certificate.SourceRegion, certificate.KeyEpoch,
		certificate.AccountID, certificate.AssetID, certificate.SourceEpoch); err != nil {
		return err
	}
	var epoch int64
	return tx.QueryRow(ctx, `
SELECT source_epoch FROM escrow_consumption_issuance_locks
WHERE source_legal_entity_id=$1 AND source_region=$2 AND source_key_epoch=$3
  AND account_id=$4 AND asset_id=$5 AND source_epoch=$6
FOR UPDATE`, certificate.SourceLegalEntityID, certificate.SourceRegion,
		certificate.KeyEpoch, certificate.AccountID, certificate.AssetID,
		certificate.SourceEpoch).Scan(&epoch)
}

func nextConsumptionWatermark(ctx context.Context, tx pgx.Tx, binding KeyBinding) (uint64, error) {
	if _, err := tx.Exec(ctx, `
INSERT INTO escrow_consumption_watermarks
 (destination_legal_entity_id, destination_region, next_watermark)
VALUES ($1,$2,0)
ON CONFLICT (destination_legal_entity_id, destination_region) DO NOTHING`,
		binding.LegalEntityID, binding.Region); err != nil {
		return 0, err
	}
	var watermark int64
	err := tx.QueryRow(ctx, `
UPDATE escrow_consumption_watermarks
SET next_watermark=next_watermark+1
WHERE destination_legal_entity_id=$1 AND destination_region=$2
  AND next_watermark < $3
RETURNING next_watermark`, binding.LegalEntityID, binding.Region, int64(math.MaxInt64)).Scan(&watermark)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrConsumptionReceiptInvalid
	}
	if err != nil {
		return 0, err
	}
	return uint64(watermark), nil
}

func (s *Service) attachReceiptSignature(
	ctx context.Context,
	certificate Certificate,
	result *ConsumptionReceipt,
	signed ConsumptionReceipt,
) error {
	payload, err := signed.Payload()
	if err != nil {
		return err
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		stored, found, err := loadConsumptionByTransfer(ctx, tx, certificate.TransferID)
		if err != nil {
			return err
		}
		if !found || !receiptMatchesCertificate(stored, certificate, signed.CertificateHash) {
			return ErrCertificateConflict
		}
		storedPayload, err := stored.Payload()
		if err != nil || !bytes.Equal(storedPayload, payload) {
			return ErrConsumptionReceiptInvalid
		}
		if len(stored.Signature) == 0 {
			tag, err := tx.Exec(ctx, `
UPDATE escrow_consumed_certificates
SET receipt_sig=$2, receipt_signed_at=transaction_timestamp()
WHERE transfer_id=$1 AND receipt_sig IS NULL`, certificate.TransferID, signed.Signature)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return ErrConsumptionReceiptInvalid
			}
			stored.Signature = append([]byte(nil), signed.Signature...)
		}
		*result = stored
		return nil
	})
}

// AcknowledgeTransfer settles source IN_TRANSIT authority using only the
// destination-signed receipt. No destination table is read or joined, so the
// two authorities may live in independent sovereign databases.
func (s *Service) AcknowledgeTransfer(
	ctx context.Context,
	certificate Certificate,
	receipt ConsumptionReceipt,
) error {
	if receipt.TransferID == "" {
		return ErrConsumptionProofMissing
	}
	if err := VerifyCertificate(certificate, s.verifier); err != nil {
		return err
	}
	if err := VerifyConsumptionReceipt(receipt, certificate, s.verifier); err != nil {
		return err
	}
	certificatePayload, _ := certificate.Payload()
	receiptPayload, _ := receipt.Payload()
	receiptHash, _ := receipt.PayloadHash()
	return s.inTx(ctx, func(tx pgx.Tx) error {
		record, found, err := loadTransferRecord(ctx, tx, certificate.TransferID)
		if err != nil {
			return err
		}
		if !found {
			return ErrConsumptionProofMissing
		}
		storedPayload, err := record.Certificate.Payload()
		if err != nil || !bytes.Equal(storedPayload, certificatePayload) ||
			!bytes.Equal(record.Certificate.Signature, certificate.Signature) {
			return ErrCertificateConflict
		}
		if record.Status == "ACKNOWLEDGED" {
			if !bytes.Equal(record.ReceiptPayload, receiptPayload) ||
				!bytes.Equal(record.ReceiptSignature, receipt.Signature) ||
				!bytes.Equal(record.ReceiptHash, receiptHash[:]) {
				return ErrCertificateConflict
			}
			return nil
		}
		if record.Status != "IN_TRANSIT" || len(record.Certificate.Signature) == 0 {
			return ErrConsumptionProofMissing
		}
		tag, err := tx.Exec(ctx, `
UPDATE escrow_authorities
SET total_authority=total_authority-$3, version=version+1
WHERE account_id=$1 AND asset_id=$2 AND total_authority >= $3`,
			certificate.AccountID, certificate.AssetID, certificate.Amount.String())
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("escrow source authority inconsistent: %w", ErrInsufficientRights)
		}
		tag, err = tx.Exec(ctx, `
UPDATE escrow_transfers
SET status='ACKNOWLEDGED', acknowledged_at=transaction_timestamp(),
    consumption_receipt_payload=$2, consumption_receipt_sig=$3,
    consumption_receipt_hash=$4, destination_watermark=$5,
    receipt_key_id=$6, receipt_key_epoch=$7
WHERE transfer_id=$1 AND status='IN_TRANSIT'`, certificate.TransferID,
			receiptPayload, receipt.Signature, receiptHash[:],
			receipt.DestinationCommitWatermark, receipt.KeyID, receipt.KeyEpoch)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrCertificateConflict
		}
		return nil
	})
}

func (s *Service) Snapshot(ctx context.Context, accountID, assetID string) (Authority, error) {
	var result Authority
	result.AccountID, result.AssetID = accountID, assetID
	result.RegionalRights = make(map[string]ledger.Amount)
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var totalText, unallocatedText string
		if err := tx.QueryRow(ctx, `
SELECT total_authority::STRING, unallocated::STRING, version FROM escrow_authorities
WHERE account_id=$1 AND asset_id=$2`, accountID, assetID).
			Scan(&totalText, &unallocatedText, &result.Version); err != nil {
			return err
		}
		var parseErr error
		result.Total, parseErr = ledger.ParseAmount(totalText)
		if parseErr != nil {
			return parseErr
		}
		result.Unallocated, parseErr = ledger.ParseAmount(unallocatedText)
		if parseErr != nil {
			return parseErr
		}
		rows, err := tx.Query(ctx, `
SELECT region, available::STRING FROM escrow_regional_rights
WHERE account_id=$1 AND asset_id=$2`, accountID, assetID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var region, amountText string
			if err := rows.Scan(&region, &amountText); err != nil {
				return err
			}
			amount, err := ledger.ParseAmount(amountText)
			if err != nil {
				return err
			}
			result.RegionalRights[region] = amount
		}
		if err := rows.Err(); err != nil {
			return err
		}
		var transitText string
		if err := tx.QueryRow(ctx, `
SELECT coalesce(sum(amount), 0)::STRING FROM escrow_transfers
WHERE account_id=$1 AND asset_id=$2 AND status='IN_TRANSIT'`, accountID, assetID).
			Scan(&transitText); err != nil {
			return err
		}
		result.InTransit, parseErr = ledger.ParseAmount(transitText)
		if parseErr != nil {
			return parseErr
		}
		var offlineText, foldedText string
		if err := tx.QueryRow(ctx, `
SELECT offline_issued::STRING, folded_offline_issued::STRING
FROM escrow_authority_conservation
WHERE account_id=$1 AND asset_id=$2`, accountID, assetID).
			Scan(&offlineText, &foldedText); err != nil {
			return err
		}
		result.OfflineIssued, parseErr = ledger.ParseAmount(offlineText)
		if parseErr != nil {
			return parseErr
		}
		result.FoldedOffline, parseErr = ledger.ParseAmount(foldedText)
		return parseErr
	})
	return result, err
}

type transferRecord struct {
	Certificate      Certificate
	Status           string
	ReceiptPayload   []byte
	ReceiptSignature []byte
	ReceiptHash      []byte
}

func loadTransferRecord(ctx context.Context, tx pgx.Tx, transferID string) (transferRecord, bool, error) {
	var record transferRecord
	var payload []byte
	var amountText string
	var sourceKeyEpoch int64
	err := tx.QueryRow(ctx, `
SELECT account_id, asset_id, source_region, destination_region,
       coalesce(source_legal_entity_id, ''), coalesce(destination_legal_entity_id, ''),
       amount::STRING, source_epoch, key_id, coalesce(source_key_epoch, 0),
       certificate_payload, certificate_sig, status,
       consumption_receipt_payload, consumption_receipt_sig, consumption_receipt_hash
FROM escrow_transfers WHERE transfer_id=$1 FOR UPDATE`, transferID).Scan(
		&record.Certificate.AccountID, &record.Certificate.AssetID,
		&record.Certificate.SourceRegion, &record.Certificate.DestinationRegion,
		&record.Certificate.SourceLegalEntityID, &record.Certificate.DestinationLegalEntityID,
		&amountText, &record.Certificate.SourceEpoch, &record.Certificate.KeyID,
		&sourceKeyEpoch, &payload, &record.Certificate.Signature, &record.Status,
		&record.ReceiptPayload, &record.ReceiptSignature, &record.ReceiptHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return transferRecord{}, false, nil
	}
	if err != nil {
		return transferRecord{}, false, err
	}
	record.Certificate.KeyEpoch = uint64(sourceKeyEpoch)
	record.Certificate.TransferID = transferID
	record.Certificate.Amount, err = ledger.ParseAmount(amountText)
	if err != nil {
		return transferRecord{}, false, err
	}
	record.Certificate.Version = certificateVersion
	actual, err := record.Certificate.Payload()
	if err != nil || !bytes.Equal(payload, actual) {
		return transferRecord{}, false, fmt.Errorf("stored transfer certificate corrupt: %w", ErrCertificateInvalid)
	}
	return record, true, nil
}

func sameTransfer(c Certificate, request TransferRequest) bool {
	return c.TransferID == request.TransferID && c.AccountID == request.AccountID &&
		c.AssetID == request.AssetID && c.SourceRegion == request.SourceRegion &&
		c.DestinationRegion == request.DestinationRegion &&
		c.SourceLegalEntityID == request.SourceLegalEntityID &&
		c.DestinationLegalEntityID == request.DestinationLegalEntityID &&
		c.Amount.Cmp(request.Amount) == 0
}

func loadConsumptionByTransfer(
	ctx context.Context,
	tx pgx.Tx,
	transferID string,
) (ConsumptionReceipt, bool, error) {
	return loadConsumption(ctx, tx, `transfer_id=$1`, transferID)
}

func loadConsumptionByIssuance(
	ctx context.Context,
	tx pgx.Tx,
	certificate Certificate,
) (ConsumptionReceipt, bool, error) {
	return loadConsumption(ctx, tx, `
source_legal_entity_id=$1 AND source_region=$2 AND source_key_epoch=$3
AND account_id=$4 AND asset_id=$5 AND source_epoch=$6`,
		certificate.SourceLegalEntityID, certificate.SourceRegion, certificate.KeyEpoch,
		certificate.AccountID, certificate.AssetID, certificate.SourceEpoch)
}

func loadConsumption(ctx context.Context, tx pgx.Tx, predicate string, args ...any) (ConsumptionReceipt, bool, error) {
	var receipt ConsumptionReceipt
	var certificateHash, receiptPayload []byte
	var amountText string
	var sourceEpoch, sourceKeyEpoch, watermark, keyEpoch int64
	query := `
SELECT transfer_id, payload_hash, account_id, asset_id, amount::STRING,
       source_region, coalesce(source_legal_entity_id, ''), coalesce(source_epoch, 0),
       coalesce(source_key_epoch, 0), destination_region,
       coalesce(destination_legal_entity_id, ''), coalesce(destination_watermark, 0),
       coalesce(destination_key_id, ''), coalesce(destination_key_epoch, 0),
       receipt_payload, receipt_sig
FROM escrow_consumed_certificates WHERE ` + predicate + ` FOR UPDATE`
	err := tx.QueryRow(ctx, query, args...).Scan(
		&receipt.TransferID, &certificateHash, &receipt.AccountID, &receipt.AssetID,
		&amountText, &receipt.SourceRegion, &receipt.SourceLegalEntityID, &sourceEpoch,
		&sourceKeyEpoch, &receipt.DestinationRegion, &receipt.DestinationLegalEntityID,
		&watermark, &receipt.KeyID, &keyEpoch, &receiptPayload, &receipt.Signature)
	if errors.Is(err, pgx.ErrNoRows) {
		return ConsumptionReceipt{}, false, nil
	}
	if err != nil {
		return ConsumptionReceipt{}, false, err
	}
	if len(certificateHash) != len(receipt.CertificateHash) {
		return ConsumptionReceipt{}, false, ErrConsumptionReceiptInvalid
	}
	copy(receipt.CertificateHash[:], certificateHash)
	receipt.Version = consumptionReceiptVersion
	receipt.SourceEpoch, receipt.SourceKeyEpoch = uint64(sourceEpoch), uint64(sourceKeyEpoch)
	receipt.DestinationCommitWatermark = uint64(watermark)
	receipt.KeyEpoch = uint64(keyEpoch)
	receipt.Amount, err = ledger.ParseAmount(amountText)
	if err != nil {
		return ConsumptionReceipt{}, false, err
	}
	actual, err := receipt.Payload()
	if err != nil || !bytes.Equal(actual, receiptPayload) {
		return ConsumptionReceipt{}, false, ErrConsumptionReceiptInvalid
	}
	return receipt, true, nil
}

func receiptMatchesCertificate(
	receipt ConsumptionReceipt,
	certificate Certificate,
	certificateHash [32]byte,
) bool {
	return receipt.CertificateHash == certificateHash &&
		receipt.TransferID == certificate.TransferID &&
		receipt.AccountID == certificate.AccountID && receipt.AssetID == certificate.AssetID &&
		receipt.Amount.Cmp(certificate.Amount) == 0 &&
		receipt.SourceRegion == certificate.SourceRegion &&
		receipt.SourceLegalEntityID == certificate.SourceLegalEntityID &&
		receipt.SourceEpoch == certificate.SourceEpoch &&
		receipt.SourceKeyEpoch == certificate.KeyEpoch &&
		receipt.DestinationRegion == certificate.DestinationRegion &&
		receipt.DestinationLegalEntityID == certificate.DestinationLegalEntityID
}

func (s *Service) inTx(ctx context.Context, fn func(pgx.Tx) error) error {
	if s.db == nil || fn == nil {
		return ErrInvalidArgument
	}
	retries := s.retries
	if retries <= 0 {
		retries = defaultSerializableRetries
	}
	var last error
	for attempt := 0; attempt < retries; attempt++ {
		tx, err := s.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
		if err != nil {
			return err
		}
		err = fn(tx)
		if err == nil {
			err = tx.Commit(ctx)
		} else {
			_ = tx.Rollback(ctx)
		}
		if !isSerializationFailure(err) {
			return err
		}
		_ = tx.Rollback(ctx)
		last = err
	}
	return fmt.Errorf("escrow transaction retry limit: %w", last)
}

func isSerializationFailure(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "40001"
}
