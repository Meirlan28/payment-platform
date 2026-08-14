// Package failuresim is a deterministic executable model of the payment
// protocols. It is intentionally not a production persistence adapter: the
// production authority is CockroachDB. The model keeps the same atomicity,
// idempotency, escrow, and failure boundaries so tests can explore adverse
// interleavings without wall-clock sleeps or probabilistic assertions.
package failuresim

import (
	"crypto/sha256"
	"errors"

	"github.com/example/payment-platform/internal/ledger"
)

var (
	ErrInvalidConfiguration = errors.New("failuresim: invalid configuration")
	ErrRegionDown           = errors.New("failuresim: region is down")
	ErrNoQuorum             = errors.New("failuresim: durable write quorum unavailable")
	ErrStaleEpoch           = errors.New("failuresim: stale epoch")
	ErrInsufficientFunds    = errors.New("failuresim: insufficient funds")
	ErrInsufficientRights   = errors.New("failuresim: insufficient regional spending rights")
	ErrIdempotencyConflict  = errors.New("failuresim: idempotency key reused with different request")
	ErrEffectConflict       = errors.New("failuresim: economic effect reused with different request")
	ErrResponseLost         = errors.New("failuresim: committed, response lost")
	ErrCrashBeforeCommit    = errors.New("failuresim: process crashed before commit")
	ErrCrashAfterCommit     = errors.New("failuresim: process crashed after commit before response")
	ErrPaymentNotFound      = errors.New("failuresim: payment not found")
	ErrRefundExceeded       = errors.New("failuresim: refund or reversal exceeds captured amount")
	ErrTransferInvalid      = errors.New("failuresim: invalid transfer certificate")
	ErrTransferConflict     = errors.New("failuresim: transfer identifier conflict")
	ErrConsumerCrash        = errors.New("failuresim: consumer crashed after atomic effect before ack")
	ErrCoordinatorDown      = errors.New("failuresim: saga coordinator is down")
	ErrCoordinatorCrash     = errors.New("failuresim: coordinator crashed after effect before progress update")
	ErrExternalTimeout      = errors.New("failuresim: external success response timed out")
	ErrCashbackExceeded     = errors.New("failuresim: cashback exceeds immutable rule")
)

const (
	UserAccount                 = "wallet:customer"
	MerchantAccount             = "payable:merchant"
	FundingAccount              = "clearing:funding"
	CashbackExpenseAccount      = "expense:cashback"
	AuthorityIssuerAccount      = "authority:issuer"
	AuthorityConsumedAccount    = "authority:consumed"
	AuthorityTransitAccount     = "authority:in-transit"
	AuthorityUnallocatedAccount = "authority:unallocated"
)

func RegionalAuthorityAccount(region string) string { return "authority:region:" + region }

type Config struct {
	Asset          string
	InitialBalance ledger.Amount
	CreditLimit    ledger.Amount
	Unallocated    ledger.Amount
	RegionalRights map[string]ledger.Amount
	CertificateKey []byte
}

type Fence struct {
	Region string
	Epoch  uint64
}

type RegionSnapshot struct {
	Region  string
	Epoch   uint64
	Running bool
	Rights  ledger.Amount
}

type JournalLine struct {
	Account string
	Asset   string
	Side    ledger.Side
	Amount  ledger.Amount
}

type JournalTransaction struct {
	Sequence     uint64
	ID           string
	EffectID     string
	Kind         string
	RequestHash  [32]byte
	PreviousHash [32]byte
	Hash         [32]byte
	Lines        []JournalLine
}

type Receipt struct {
	IdempotencyKey string
	EffectID       string
	TransactionID  string
	CommitSequence uint64
	Duplicate      bool
}

type PaymentState string

const (
	PaymentCaptured          PaymentState = "CAPTURED"
	PaymentPartiallyRefunded PaymentState = "PARTIALLY_REFUNDED"
	PaymentRefunded          PaymentState = "REFUNDED"
	PaymentReversed          PaymentState = "REVERSED"
	PaymentDisputed          PaymentState = "DISPUTED"
)

type PaymentSnapshot struct {
	OperationID string
	Region      string
	Authorized  ledger.Amount
	Captured    ledger.Amount
	Refunded    ledger.Amount
	Reversed    ledger.Amount
	ChargedBack ledger.Amount
	State       PaymentState
	Receipt     Receipt
}

type TransferCertificate struct {
	TransferID        string        `json:"transfer_id"`
	Asset             string        `json:"asset"`
	SourceRegion      string        `json:"source_region"`
	DestinationRegion string        `json:"destination_region"`
	Amount            ledger.Amount `json:"amount"`
	SourceEpoch       uint64        `json:"source_epoch"`
	CommitSequence    uint64        `json:"commit_sequence"`
	CommitProof       [32]byte      `json:"commit_proof"`
}

type TransferSnapshot struct {
	Certificate        TransferCertificate
	InTransit          bool
	Consumed           bool
	SourceAcknowledged bool
	ConsumeReceipt     Receipt
}

type OutboxRecord struct {
	MessageID           string
	Kind                string
	SourceRegion        string
	DestinationRegion   string
	ParentTransactionID string
	Payload             []byte
	Attempts            uint64
	Acknowledged        bool
}

type InboxRecord struct {
	MessageID           string
	PayloadHash         [32]byte
	EffectID            string
	DuplicateDeliveries uint64
}

type SagaSnapshot struct {
	SagaID         string
	Region         string
	OperationID    string
	Amount         ledger.Amount
	NextStep       int
	Completed      bool
	PaymentReceipt Receipt
}

type FraudVerdictSnapshot struct {
	EventID    string
	PaymentID  string
	Fraudulent bool
	DueTick    uint64
	Processed  bool
}

type ExternalResult struct {
	OperationID string
	Amount      ledger.Amount
	Succeeded   bool
	Duplicate   bool
	Proof       [32]byte
}

func payloadHash(payload []byte) [32]byte { return sha256.Sum256(payload) }
