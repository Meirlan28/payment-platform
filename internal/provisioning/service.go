// Package provisioning opens customer and merchant accounts and credits
// customer accounts with funds.
//
// Opening an account and creating money are deliberately separate capabilities
// backed by separate database roles. A credential that can open accounts must
// not be able to create value, and a credential that can create value must not
// be able to grant spending capability to a principal of its choosing.
//
// Both operations are idempotent on a caller-supplied external reference, so a
// client whose request times out may retry indefinitely without opening a
// second account or crediting the same deposit twice. A replay carrying a
// different payload for an already-used reference is rejected rather than
// silently treated as a duplicate.
//
// Funding raises ledger balance and escrow spending rights in one transaction.
// This is not a convenience: payment.Hold spends regional escrow rights, so a
// credited balance without matching rights would be unspendable, and rights
// without a balance would let a customer overdraw. The escrow conservation
// invariant (unallocated + regional + in_transit + offline = total_authority)
// is preserved by raising total_authority and the regional right together.
package provisioning

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"strconv"
	"strings"
	"time"

	"github.com/example/payment-platform/internal/authz"
	"github.com/example/payment-platform/internal/idempotency"
	"github.com/example/payment-platform/internal/ledger"
	"github.com/example/payment-platform/internal/store"
	"github.com/example/payment-platform/internal/transfer"
	"github.com/jackc/pgx/v5"
)

var (
	ErrInvalidRequest  = errors.New("provisioning: invalid request")
	ErrRequestConflict = errors.New("provisioning: external reference reused with a different request")
	ErrNotProvisioned  = errors.New("provisioning: account is not provisioned")
	ErrEscrowMissing   = errors.New("provisioning: account has no escrow authority for this asset and region")
	ErrPrincipalDenied = errors.New("provisioning: caller may not grant capability to this payment principal")
)

// FundingEventTopic carries deposits to consumers. It is separate from
// payment-events because a deposit is not a payment lifecycle transition and
// its aggregate is an account rather than a payment.
const FundingEventTopic = "ledger-funding-events"

// FundingEventType is the headers.event_type discriminator for a deposit.
const FundingEventType = "funding.credited"

// Config is the deployment-fixed identity of one provisioning cell. Nothing
// here is caller-supplied at request time.
type Config struct {
	// Region is this cell's authority region. It becomes the region of every
	// account this instance opens and must equal the region of the payment-api
	// that will serve those accounts.
	Region string
	// LegalEntityID and Jurisdiction identify the books this cell owns.
	LegalEntityID string
	Jurisdiction  string
	// BookShards spreads customers over several regional books so no single
	// book becomes a global hot range. It must never shrink for a live cell:
	// an account's book is derived from its external reference.
	BookShards int
	// PolicyVersion and GrantedBy are recorded on every capability grant as
	// immutable policy provenance.
	PolicyVersion string
	GrantedBy     string
	// FundingAccountID is the base name of the cell's funding source. The
	// account actually debited is derived per book by FundingAccountFor,
	// because every line of a ledger transaction must belong to one book and
	// customer accounts are spread across several.
	FundingAccountID string
}

func (c Config) validate() error {
	if c.Region == "" || c.LegalEntityID == "" || c.Jurisdiction == "" ||
		c.PolicyVersion == "" || c.GrantedBy == "" {
		return fmt.Errorf("%w: incomplete provisioning configuration", ErrInvalidRequest)
	}
	if c.BookShards <= 0 {
		return fmt.Errorf("%w: book shard count must be positive", ErrInvalidRequest)
	}
	return nil
}

type Service struct {
	transactions *store.Runner
	journal      *ledger.Service
	ids          ledger.IDGenerator
	config       Config
}

func New(transactions *store.Runner, journal *ledger.Service, ids ledger.IDGenerator, config Config) (*Service, error) {
	if transactions == nil || journal == nil || ids == nil {
		return nil, fmt.Errorf("%w: transactions, journal and ID generator are required", ErrInvalidRequest)
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	return &Service{transactions: transactions, journal: journal, ids: ids, config: config}, nil
}

// Region reports the authority region this instance provisions into.
func (s *Service) Region() string { return s.config.Region }

// FundingAccountFor names the funding source inside one book.
//
// It is exported and used by every caller, including the fixture tool, so the
// production deposit path and the seeding path can never disagree about which
// account funds a book.
func FundingAccountFor(base, bookID string) string { return base + "-" + bookID }

// BookIDFor is the deterministic customer-to-book mapping. It is exported
// because operational tooling must be able to locate an account's book without
// querying, and because the mapping must be stable across restarts.
//
// The identifier is namespaced by legal entity as well as region: a book
// belongs to exactly one legal entity, so two entities operating in the same
// region must never derive the same book identifier.
func (s *Service) BookIDFor(externalReference string) string {
	digest := fnv.New64a()
	_, _ = digest.Write([]byte(externalReference))
	shard := digest.Sum64() % uint64(s.config.BookShards)
	return "book-" + s.config.LegalEntityID + "-" + s.config.Region + "-" +
		strconv.FormatUint(shard, 10)
}

// CustomerAccountRequest opens one customer wallet: an available account, a
// held account for authorization holds, zero-value escrow rows and the
// capability grants that let PaymentPrincipalID authorize against them.
type CustomerAccountRequest struct {
	ExternalReference string `json:"external_reference"`
	AssetID           string `json:"asset_id"`
	// TransferPrincipalID may move this customer's money to another person.
	// Empty grants no transfer capability, which is the safe default: a wallet
	// that cannot yet send is a smaller problem than a payment principal that
	// silently gained the ability to.
	TransferPrincipalID string `json:"transfer_principal_id"`
	// PaymentPrincipalID is the SPIFFE identity that will be permitted to
	// authorize payments against these accounts. Callers of this package do
	// not choose it freely; the gRPC layer resolves it from a server-side
	// allowlist keyed by the authenticated caller.
	PaymentPrincipalID string `json:"payment_principal_id"`
}

type CustomerAccountResult struct {
	Region             string `json:"region"`
	BookID             string `json:"book_id"`
	AvailableAccountID string `json:"available_account_id"`
	HeldAccountID      string `json:"held_account_id"`
	// Duplicate reports that this reference was already provisioned and the
	// stored result was returned unchanged.
	Duplicate bool `json:"duplicate"`
}

func (r CustomerAccountRequest) validate() error {
	if !boundedID(r.ExternalReference) || !boundedID(r.AssetID) || !boundedID(r.PaymentPrincipalID) {
		return fmt.Errorf("%w: external reference, asset and payment principal are required", ErrInvalidRequest)
	}
	return nil
}

// ProvisionCustomerAccount is idempotent on ExternalReference. Book, accounts,
// escrow rows, capability grants and the receipt share one commit outcome, so
// a partially provisioned wallet is not representable.
func (s *Service) ProvisionCustomerAccount(ctx context.Context, request CustomerAccountRequest) (CustomerAccountResult, error) {
	if s == nil {
		return CustomerAccountResult{}, fmt.Errorf("%w: service is not configured", ErrInvalidRequest)
	}
	if err := request.validate(); err != nil {
		return CustomerAccountResult{}, err
	}
	hash, err := idempotency.RequestHash(request)
	if err != nil {
		return CustomerAccountResult{}, err
	}
	bookID := s.BookIDFor(request.ExternalReference)

	// IDs are allocated before the transaction because the durable generator
	// runs its own transaction. A serialization retry burns the candidates
	// rather than reusing them, exactly as the payment path does.
	availableID, err := s.nextID(ctx, "available_")
	if err != nil {
		return CustomerAccountResult{}, err
	}
	heldID, err := s.nextID(ctx, "held_")
	if err != nil {
		return CustomerAccountResult{}, err
	}

	result := CustomerAccountResult{Region: s.config.Region, BookID: bookID}
	err = s.transactions.RunSerializable(ctx, func(tx pgx.Tx) error {
		stored, found, err := loadCustomerRecord(ctx, tx, request.ExternalReference)
		if err != nil {
			return err
		}
		if found {
			if stored.requestHash != hash {
				return ErrRequestConflict
			}
			result = CustomerAccountResult{
				Region: stored.region, BookID: stored.bookID,
				AvailableAccountID: stored.availableAccountID,
				HeldAccountID:      stored.heldAccountID,
				Duplicate:          true,
			}
			return nil
		}

		if err := s.journal.EnsureBookInTx(ctx, tx, ledger.Book{
			BookID: bookID, LegalEntityID: s.config.LegalEntityID,
			Jurisdiction: s.config.Jurisdiction,
		}); err != nil {
			return err
		}
		// Every book needs its inter-book settlement account before anyone in
		// it can be sent money from another book. Creating it with the book
		// rather than on first use means a transfer never fails because the
		// recipient happened to be the first person in their shard.
		if err := s.ensureSettlementAccount(ctx, tx, bookID, request.AssetID); err != nil {
			return err
		}
		// Both customer accounts enforce the spend limit, so an unfunded or
		// overdrawn posting is refused by the balance trigger even if every
		// layer above it were wrong.
		for _, account := range []ledger.Account{
			{
				AccountID: availableID, BookID: bookID, AssetID: request.AssetID,
				AccountType: "CUSTOMER_AVAILABLE", NormalSide: ledger.Credit,
				EnforceSpendLimit: true,
			},
			{
				AccountID: heldID, BookID: bookID, AssetID: request.AssetID,
				AccountType: "CUSTOMER_HELD", NormalSide: ledger.Credit,
				EnforceSpendLimit: true,
			},
		} {
			if err := s.journal.CreateAccountInTx(ctx, tx, account); err != nil {
				return err
			}
		}

		// Escrow starts at zero. Only a deposit raises spending rights, so a
		// freshly opened wallet can hold no payment until it is funded.
		if err := insertZeroEscrow(ctx, tx, availableID, request.AssetID, s.config.Region); err != nil {
			return err
		}

		for _, grant := range []struct{ accountID, permission string }{
			{availableID, authz.AuthorizePayerAvailable},
			{heldID, authz.AuthorizePayerHeld},
		} {
			if err := s.grantCapability(ctx, tx, request.PaymentPrincipalID, bookID,
				grant.accountID, grant.permission, hash); err != nil {
				return err
			}
		}
		// Transfer authority goes to its own principal, and only when one was
		// named. Sending and receiving are granted separately so a credential
		// able to debit this account cannot thereby credit another of its
		// choosing.
		if request.TransferPrincipalID != "" {
			for _, permission := range []string{
				authz.TransferDebitAvailable, authz.TransferCreditAvailable,
			} {
				if err := s.grantCapability(ctx, tx, request.TransferPrincipalID, bookID,
					availableID, permission, hash); err != nil {
					return err
				}
			}
		}

		if _, err := tx.Exec(ctx, `
INSERT INTO account_provisioning_records (
    external_reference, payment_principal_id, asset_id, region, book_id,
    available_account_id, held_account_id, request_hash
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			request.ExternalReference, request.PaymentPrincipalID, request.AssetID,
			s.config.Region, bookID, availableID, heldID, hash[:]); err != nil {
			return err
		}
		result.AvailableAccountID = availableID
		result.HeldAccountID = heldID
		return nil
	})
	if err != nil {
		return CustomerAccountResult{}, err
	}
	return result, nil
}

// MerchantAccountRequest opens a merchant account and permits
// PaymentPrincipalID to credit it during capture. The account identifier is
// caller-supplied and stable, which makes the whole operation naturally
// idempotent without a separate receipt.
type MerchantAccountRequest struct {
	AccountID          string
	AssetID            string
	BookID             string
	PaymentPrincipalID string
}

// ProvisionMerchantAccount is idempotent on AccountID. Without it a wallet has
// nobody to pay: Authorize requires AUTHORIZE_MERCHANT on the merchant account
// under the same principal that holds the payer capabilities.
func (s *Service) ProvisionMerchantAccount(ctx context.Context, request MerchantAccountRequest) error {
	if s == nil {
		return fmt.Errorf("%w: service is not configured", ErrInvalidRequest)
	}
	if !boundedID(request.AccountID) || !boundedID(request.AssetID) ||
		!boundedID(request.BookID) || !boundedID(request.PaymentPrincipalID) {
		return fmt.Errorf("%w: merchant account, asset, book and principal are required", ErrInvalidRequest)
	}
	hash, err := idempotency.RequestHash(request)
	if err != nil {
		return err
	}
	return s.transactions.RunSerializable(ctx, func(tx pgx.Tx) error {
		if err := s.journal.EnsureBookInTx(ctx, tx, ledger.Book{
			BookID: request.BookID, LegalEntityID: s.config.LegalEntityID,
			Jurisdiction: s.config.Jurisdiction,
		}); err != nil {
			return err
		}
		if err := s.journal.CreateAccountInTx(ctx, tx, ledger.Account{
			AccountID: request.AccountID, BookID: request.BookID, AssetID: request.AssetID,
			AccountType: "MERCHANT", NormalSide: ledger.Credit,
		}); err != nil {
			return err
		}
		return s.grantCapability(ctx, tx, request.PaymentPrincipalID, request.BookID,
			request.AccountID, authz.AuthorizeMerchant, hash)
	})
}

// DepositRequest credits a provisioned customer account. FundingSourceReference
// is the caller's evidence that value actually arrived (a settlement or rail
// reference); this package does not invent value, it records value that a rail
// adapter has already proven.
type DepositRequest struct {
	ExternalReference      string        `json:"external_reference"`
	AccountID              string        `json:"account_id"`
	AssetID                string        `json:"asset_id"`
	AmountAtoms            ledger.Amount `json:"amount_atoms"`
	FundingSourceReference string        `json:"funding_source_reference"`
}

type DepositResult struct {
	LedgerTransactionID string `json:"ledger_transaction_id"`
	Duplicate           bool   `json:"duplicate"`
}

func (r DepositRequest) validate() error {
	if !boundedID(r.ExternalReference) || !boundedID(r.AccountID) || !boundedID(r.AssetID) ||
		!boundedID(r.FundingSourceReference) {
		return fmt.Errorf("%w: external reference, account, asset and funding source are required", ErrInvalidRequest)
	}
	if r.AmountAtoms.Sign() <= 0 {
		return fmt.Errorf("%w: deposit amount must be positive", ErrInvalidRequest)
	}
	return nil
}

// Deposit posts the balanced credit, raises escrow authority and the regional
// right by the same amount, enqueues the notification and writes the receipt,
// all in one serializable transaction. Either the customer can spend the money
// and the world will hear about it, or nothing happened.
func (s *Service) Deposit(ctx context.Context, request DepositRequest) (DepositResult, error) {
	if s == nil {
		return DepositResult{}, fmt.Errorf("%w: service is not configured", ErrInvalidRequest)
	}
	if s.config.FundingAccountID == "" {
		return DepositResult{}, fmt.Errorf("%w: funding source account is not configured", ErrInvalidRequest)
	}
	if err := request.validate(); err != nil {
		return DepositResult{}, err
	}
	hash, err := idempotency.RequestHash(request)
	if err != nil {
		return DepositResult{}, err
	}
	transactionID, err := s.nextID(ctx, "funding_transaction_")
	if err != nil {
		return DepositResult{}, err
	}
	operationID, err := s.nextID(ctx, "funding_operation_")
	if err != nil {
		return DepositResult{}, err
	}
	effectID, err := s.nextID(ctx, "funding_effect_")
	if err != nil {
		return DepositResult{}, err
	}
	eventID, err := s.nextID(ctx, "funding_event_")
	if err != nil {
		return DepositResult{}, err
	}

	var result DepositResult
	err = s.transactions.RunSerializable(ctx, func(tx pgx.Tx) error {
		storedTransactionID, storedHash, found, err := loadFundingRecord(ctx, tx, request.ExternalReference)
		if err != nil {
			return err
		}
		if found {
			if storedHash != hash {
				return ErrRequestConflict
			}
			result = DepositResult{LedgerTransactionID: storedTransactionID, Duplicate: true}
			return nil
		}

		bookID, err := accountBook(ctx, tx, request.AccountID)
		if err != nil {
			return err
		}
		metadata, err := json.Marshal(map[string]string{
			"external_reference":       request.ExternalReference,
			"funding_source_reference": request.FundingSourceReference,
		})
		if err != nil {
			return err
		}
		fundingAccountID := FundingAccountFor(s.config.FundingAccountID, bookID)
		receipt, err := s.journal.PostInTx(ctx, tx, ledger.PostRequest{
			TransactionID: transactionID, BookID: bookID,
			OperationID: operationID, EffectID: effectID,
			Kind: "DEPOSIT", PostingRuleVersion: s.config.PolicyVersion,
			SchemaVersion: 1, RequestHash: hash, Metadata: metadata,
			Lines: []ledger.Line{
				{
					AccountID: fundingAccountID, AssetID: request.AssetID,
					Side: ledger.Debit, AmountAtoms: request.AmountAtoms, Memo: "funding source",
				},
				{
					AccountID: request.AccountID, AssetID: request.AssetID,
					Side: ledger.Credit, AmountAtoms: request.AmountAtoms, Memo: "customer deposit",
				},
			},
		})
		if err != nil {
			return err
		}

		rightsVersion, err := raiseEscrow(ctx, tx, request.AccountID, request.AssetID,
			s.config.Region, request.AmountAtoms)
		if err != nil {
			return err
		}

		payload, err := json.Marshal(fundingEvent{
			EventType:              FundingEventType,
			ExternalReference:      request.ExternalReference,
			AccountID:              request.AccountID,
			AssetID:                request.AssetID,
			Region:                 s.config.Region,
			AmountAtoms:            request.AmountAtoms.String(),
			LedgerTransactionID:    receipt.TransactionID,
			LedgerSequenceNo:       receipt.SequenceNo,
			EscrowRightsVersion:    rightsVersion,
			FundingSourceReference: request.FundingSourceReference,
		})
		if err != nil {
			return err
		}
		canonical, err := ledger.CanonicalJSON(payload)
		if err != nil {
			return err
		}
		headers, err := json.Marshal(map[string]string{"event_type": FundingEventType})
		if err != nil {
			return err
		}
		// The outbox row is written here, in the financial transaction, so a
		// committed deposit always has a durable intent to publish and an
		// aborted one leaves no orphan notification.
		if _, err := tx.Exec(ctx, `
INSERT INTO outbox_messages (
    event_id, topic, message_key, payload, headers, aggregate_id,
    aggregate_version, parent_transaction_id
) VALUES ($1,$2,$3,$4,$5::JSONB,$6,$7,$8)`,
			eventID, FundingEventTopic, []byte(request.AccountID), canonical,
			string(headers), request.AccountID, rightsVersion, receipt.TransactionID); err != nil {
			return err
		}

		if _, err := tx.Exec(ctx, `
INSERT INTO funding_records (
    external_reference, account_id, asset_id, region, amount_atoms,
    funding_source_reference, ledger_transaction_id, request_hash
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			request.ExternalReference, request.AccountID, request.AssetID, s.config.Region,
			request.AmountAtoms.String(), request.FundingSourceReference,
			receipt.TransactionID, hash[:]); err != nil {
			return err
		}
		result = DepositResult{LedgerTransactionID: receipt.TransactionID}
		return nil
	})
	if err != nil {
		return DepositResult{}, err
	}
	return result, nil
}

type fundingEvent struct {
	EventType              string `json:"event_type"`
	ExternalReference      string `json:"external_reference"`
	AccountID              string `json:"account_id"`
	AssetID                string `json:"asset_id"`
	Region                 string `json:"region"`
	AmountAtoms            string `json:"amount_atoms"`
	LedgerTransactionID    string `json:"ledger_transaction_id"`
	LedgerSequenceNo       int64  `json:"ledger_sequence_no"`
	EscrowRightsVersion    int64  `json:"escrow_rights_version"`
	FundingSourceReference string `json:"funding_source_reference"`
}

// Snapshot is an authoritative point-in-time view of one account, used by
// external read models to verify themselves against the ledger.
type Snapshot struct {
	AccountID            string        `json:"account_id"`
	AssetID              string        `json:"asset_id"`
	Region               string        `json:"region"`
	BalanceAtoms         ledger.Amount `json:"balance_atoms"`
	EscrowAvailableAtoms ledger.Amount `json:"escrow_available_atoms"`
	LastSequenceNo       int64         `json:"last_sequence_no"`
	AsOf                 time.Time     `json:"as_of"`
}

// AccountSnapshot reads the account as it existed at asOf, using CockroachDB's
// historical read. Comparing a read model against the ledger at a shared past
// watermark is what makes reconciliation free of false positives: everything
// committed before asOf has had time to propagate, so a difference is a real
// defect rather than ordinary replication lag.
//
// The caller needs only SELECT on account_balances and escrow_regional_rights,
// both of which ledger_reader already holds.
func AccountSnapshot(ctx context.Context, db store.Beginner, accountID, assetID, region string, asOf time.Time) (Snapshot, error) {
	if db == nil || !boundedID(accountID) || !boundedID(assetID) || !boundedID(region) {
		return Snapshot{}, fmt.Errorf("%w: account, asset and region are required", ErrInvalidRequest)
	}
	if asOf.IsZero() {
		return Snapshot{}, fmt.Errorf("%w: as-of timestamp is required", ErrInvalidRequest)
	}
	tx, err := db.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return Snapshot{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// asOf is a time.Time rendered by this function, never caller text, so the
	// literal cannot carry SQL. CockroachDB does not accept a placeholder in
	// this position on every supported version, hence the formatted literal.
	if _, err := tx.Exec(ctx, "SET TRANSACTION AS OF SYSTEM TIME '"+
		asOf.UTC().Format("2006-01-02 15:04:05.999999999-07:00")+"'"); err != nil {
		return Snapshot{}, fmt.Errorf("historical read at %s: %w", asOf.UTC().Format(time.RFC3339Nano), err)
	}

	snapshot := Snapshot{AccountID: accountID, AssetID: assetID, Region: region, AsOf: asOf.UTC()}
	var balanceText, storedAsset string
	if err := tx.QueryRow(ctx, `
SELECT balance.current_balance_atoms::STRING, account.asset_id, balance.last_sequence_no
  FROM account_balances AS balance
  JOIN accounts AS account ON account.account_id = balance.account_id
 WHERE balance.account_id = $1`, accountID).Scan(
		&balanceText, &storedAsset, &snapshot.LastSequenceNo); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Snapshot{}, fmt.Errorf("%w: %s", ErrNotProvisioned, accountID)
		}
		return Snapshot{}, err
	}
	if storedAsset != assetID {
		return Snapshot{}, fmt.Errorf("%w: account %s holds %s", ledger.ErrAssetMismatch, accountID, storedAsset)
	}
	if snapshot.BalanceAtoms, err = ledger.ParseAmount(balanceText); err != nil {
		return Snapshot{}, err
	}

	var escrowText string
	err = tx.QueryRow(ctx, `
SELECT available::STRING FROM escrow_regional_rights
 WHERE account_id=$1 AND asset_id=$2 AND region=$3`,
		accountID, assetID, region).Scan(&escrowText)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return Snapshot{}, fmt.Errorf("%w: %s/%s/%s", ErrEscrowMissing, accountID, assetID, region)
	case err != nil:
		return Snapshot{}, err
	}
	if snapshot.EscrowAvailableAtoms, err = ledger.ParseAmount(escrowText); err != nil {
		return Snapshot{}, err
	}
	return snapshot, tx.Rollback(ctx)
}

type customerRecord struct {
	region             string
	bookID             string
	availableAccountID string
	heldAccountID      string
	requestHash        [32]byte
}

func loadCustomerRecord(ctx context.Context, tx pgx.Tx, reference string) (customerRecord, bool, error) {
	var record customerRecord
	var hash []byte
	err := tx.QueryRow(ctx, `
SELECT region, book_id, available_account_id, held_account_id, request_hash
  FROM account_provisioning_records WHERE external_reference=$1`, reference).Scan(
		&record.region, &record.bookID, &record.availableAccountID,
		&record.heldAccountID, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return customerRecord{}, false, nil
	}
	if err != nil {
		return customerRecord{}, false, err
	}
	if len(hash) != len(record.requestHash) {
		return customerRecord{}, false, errors.New("provisioning: stored request hash is corrupt")
	}
	copy(record.requestHash[:], hash)
	return record, true, nil
}

func loadFundingRecord(ctx context.Context, tx pgx.Tx, reference string) (string, [32]byte, bool, error) {
	var transactionID string
	var stored [32]byte
	var hash []byte
	err := tx.QueryRow(ctx, `
SELECT ledger_transaction_id, request_hash FROM funding_records
 WHERE external_reference=$1`, reference).Scan(&transactionID, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", stored, false, nil
	}
	if err != nil {
		return "", stored, false, err
	}
	if len(hash) != len(stored) {
		return "", stored, false, errors.New("provisioning: stored request hash is corrupt")
	}
	copy(stored[:], hash)
	return transactionID, stored, true, nil
}

func accountBook(ctx context.Context, tx pgx.Tx, accountID string) (string, error) {
	var bookID string
	err := tx.QueryRow(ctx, `SELECT book_id FROM accounts WHERE account_id=$1`, accountID).Scan(&bookID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("%w: %s", ErrNotProvisioned, accountID)
	}
	if err != nil {
		return "", err
	}
	return bookID, nil
}

func insertZeroEscrow(ctx context.Context, tx pgx.Tx, accountID, assetID, region string) error {
	if _, err := tx.Exec(ctx, `
INSERT INTO escrow_authorities (account_id, asset_id, total_authority, unallocated)
VALUES ($1,$2,0,0) ON CONFLICT (account_id, asset_id) DO NOTHING`, accountID, assetID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `
INSERT INTO escrow_regional_rights (account_id, asset_id, region, available)
VALUES ($1,$2,$3,0) ON CONFLICT (account_id, asset_id, region) DO NOTHING`,
		accountID, assetID, region)
	return err
}

// raiseEscrow moves total_authority and the regional right up together. Both
// updates are conditional on the row existing, so funding an account that was
// never provisioned fails instead of quietly creating spending rights.
func raiseEscrow(ctx context.Context, tx pgx.Tx, accountID, assetID, region string, amount ledger.Amount) (int64, error) {
	tag, err := tx.Exec(ctx, `
UPDATE escrow_authorities
   SET total_authority = total_authority + $3::DECIMAL,
       version = version + 1
 WHERE account_id=$1 AND asset_id=$2`, accountID, assetID, amount.String())
	if err != nil {
		return 0, err
	}
	if tag.RowsAffected() != 1 {
		return 0, fmt.Errorf("%w: %s/%s", ErrEscrowMissing, accountID, assetID)
	}
	var version int64
	err = tx.QueryRow(ctx, `
UPDATE escrow_regional_rights
   SET available = available + $4::DECIMAL,
       version = version + 1,
       updated_at = transaction_timestamp()
 WHERE account_id=$1 AND asset_id=$2 AND region=$3
RETURNING version`, accountID, assetID, region, amount.String()).Scan(&version)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, fmt.Errorf("%w: %s/%s/%s", ErrEscrowMissing, accountID, assetID, region)
	}
	if err != nil {
		return 0, err
	}
	return version, nil
}

// grantCapability writes an immutable authorization fact. The capability id is
// derived from the grant itself, so replaying the same grant is a no-op while a
// different grant can never collide with it.
func (s *Service) grantCapability(ctx context.Context, tx pgx.Tx, principal, bookID, accountID, permission string, evidence [32]byte) error {
	_, err := tx.Exec(ctx, `
INSERT INTO payment_account_capabilities (
    capability_id, principal_id, book_id, account_id, permission,
    policy_version, granted_by, evidence_hash
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
ON CONFLICT (capability_id) DO NOTHING`,
		capabilityID(principal, bookID, accountID, permission), principal, bookID,
		accountID, permission, s.config.PolicyVersion, s.config.GrantedBy, evidence[:])
	return err
}

func capabilityID(principal, bookID, accountID, permission string) string {
	digest := sha256.Sum256([]byte(strings.Join(
		[]string{principal, bookID, accountID, permission}, "\x00")))
	return "capability-" + hex.EncodeToString(digest[:16])
}

func (s *Service) nextID(ctx context.Context, prefix string) (string, error) {
	value, err := s.ids.Next(ctx)
	if err != nil {
		return "", err
	}
	return prefix + value, nil
}

func boundedID(value string) bool {
	return value != "" && len(value) <= 512 && strings.TrimSpace(value) == value
}

// ensureSettlementAccount creates and registers a book's inter-book settlement
// account, idempotently.
//
// It is an ordinary ledger account with no special posting rules — what makes
// it a settlement account is the registry row, which is also what lets the
// zero-sum invariant know exactly which accounts to add up. Its spend limit is
// deliberately not enforced: it represents a position against peer books and
// is expected to be negative in the book that has sent more than it received.
func (s *Service) ensureSettlementAccount(ctx context.Context, tx pgx.Tx, bookID, assetID string) error {
	accountID := transfer.SettlementAccountFor(bookID, assetID)
	if err := s.journal.CreateAccountInTx(ctx, tx, ledger.Account{
		AccountID: accountID, BookID: bookID, AssetID: assetID,
		AccountType: "INTERBOOK_SETTLEMENT", NormalSide: ledger.Credit,
		EnforceSpendLimit: false,
	}); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `
INSERT INTO interbook_settlement_accounts (book_id, asset_id, account_id)
VALUES ($1,$2,$3) ON CONFLICT (book_id, asset_id) DO NOTHING`, bookID, assetID, accountID)
	return err
}
