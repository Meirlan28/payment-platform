// Package transfer moves value directly between two customer accounts.
//
// A payment is customer → merchant and never leaves one book, because merchant
// accounts are replicated into every book. A transfer is customer → customer,
// and customers are deliberately spread across books so that no single journal
// becomes a global hot range — so the two parties usually sit in different
// books.
//
// A ledger transaction may not span books. That is not an incidental limit: it
// is what lets each book balance on its own and carry its own hash chain, and
// weakening it would cost the property the whole ledger exists to provide. A
// cross-book transfer is therefore two balanced transactions joined by each
// book's inter-book settlement account:
//
//	book A:  DEBIT payer.available X   CREDIT settlement.A X
//	book B:  DEBIT settlement.B    X   CREDIT payee.available X
//
// Both books balance, and across books the settlement accounts net to zero for
// every asset — an invariant the reconciliation path can check. Both legs are
// written inside one SERIALIZABLE transaction, so the transfer is atomic:
// there is no saga, no compensating entry, and no interval in which one side
// has moved and the other has not.
//
// A same-book transfer is the same operation with one leg.
package transfer

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/example/payment-platform/internal/authz"
	"github.com/example/payment-platform/internal/idempotency"
	"github.com/example/payment-platform/internal/ledger"
	"github.com/example/payment-platform/internal/store"
	"github.com/jackc/pgx/v5"
)

var (
	ErrInvalidRequest    = errors.New("transfer: invalid request")
	ErrRequestConflict   = errors.New("transfer: idempotency key reused with a different request")
	ErrAccountNotFound   = errors.New("transfer: account not found")
	ErrAccountNotUsable  = errors.New("transfer: account cannot take part in a transfer")
	ErrAssetMismatch     = errors.New("transfer: accounts hold different assets")
	ErrSameAccount       = errors.New("transfer: payer and payee are the same account")
	ErrSettlementMissing = errors.New("transfer: a book has no inter-book settlement account")
	ErrInsufficientFunds = errors.New("transfer: the payer cannot cover this amount")
	ErrDenied            = errors.New("transfer: capability denied")
	ErrTransferNotFound  = errors.New("transfer: no such transfer")
)

// The permissions a transfer needs. They are separate from the payment
// permissions and from each other: a credential that may debit a sender must
// not thereby be able to credit an account of its choosing.
const (
	PermissionDebit  = "TRANSFER_DEBIT_AVAILABLE"
	PermissionCredit = "TRANSFER_CREDIT_AVAILABLE"
)

// The kind recorded on the ledger transactions a transfer writes.
const (
	kindTransfer           = "TRANSFER"
	kindTransferSettlement = "TRANSFER_SETTLEMENT"
)

// TransferEventTopic and TransferEventType name the outbox fact a settled
// transfer publishes. Downstream read models learn about transfers only from
// this event, never by reading these tables.
const (
	TransferEventTopic = "ledger-transfer-events"
	TransferEventType  = "transfer.settled"
)

// Request is one transfer.
//
// The identifiers are supplied by the caller so that a retry after an
// ambiguous outcome reproduces exactly the same request — the same discipline
// the payment path uses, and the reason a repeated transfer cannot become a
// second one.
type Request struct {
	TransferID       string        `json:"transfer_id"`
	IdempotencyScope string        `json:"idempotency_scope"`
	IdempotencyKey   string        `json:"idempotency_key"`
	PrincipalID      string        `json:"principal_id"`
	AssetID          string        `json:"asset_id"`
	PayerAccountID   string        `json:"payer_account_id"`
	PayeeAccountID   string        `json:"payee_account_id"`
	AmountAtoms      ledger.Amount `json:"amount_atoms"`
	Memo             string        `json:"memo"`
}

// Receipt is what actually happened.
type Receipt struct {
	TransferID string `json:"transfer_id"`
	// PayerTransactionID and PayeeTransactionID name the ledger transactions
	// written. For a same-book transfer both hold the same identifier, because
	// one transaction moved both sides.
	PayerTransactionID string `json:"payer_transaction_id"`
	PayeeTransactionID string `json:"payee_transaction_id"`
	PayerBookID        string `json:"payer_book_id"`
	PayeeBookID        string `json:"payee_book_id"`
	CrossBook          bool   `json:"cross_book"`
	// Duplicate is true when this request had already been executed. The
	// receipt then describes the original transfer, not a new one.
	Duplicate bool `json:"duplicate"`
}

// Config is the cell's identity, used the same way the provisioning service
// uses it.
type Config struct {
	Region        string
	PolicyVersion string
}

type Service struct {
	transactions *store.Runner
	journal      *ledger.Service
	capabilities *authz.Service
	ids          IDGenerator
	config       Config
}

// IDGenerator issues the durable identifiers used for transactions and
// effects. It is the same generator the payment path uses, so identifiers
// remain unique across every operation in the cell.
type IDGenerator interface {
	Next(ctx context.Context) (string, error)
}

func New(transactions *store.Runner, journal *ledger.Service, capabilities *authz.Service,
	ids IDGenerator, config Config) (*Service, error) {

	if transactions == nil || journal == nil || capabilities == nil || ids == nil {
		return nil, errors.New("transfer: transactions, journal, capabilities and ids are required")
	}
	if config.Region == "" || config.PolicyVersion == "" {
		return nil, errors.New("transfer: region and policy version are required")
	}
	return &Service{
		transactions: transactions, journal: journal, capabilities: capabilities,
		ids: ids, config: config,
	}, nil
}

// SettlementAccountFor names a book's inter-book settlement account.
//
// Derived rather than looked up so operational tooling can find it without a
// query, and stable across restarts for the same reason book identifiers are.
func SettlementAccountFor(bookID, assetID string) string {
	return "settlement_" + bookID + "_" + assetID
}

// Execute performs the transfer, atomically.
func (s *Service) Execute(ctx context.Context, request Request) (Receipt, error) {
	if err := request.validate(); err != nil {
		return Receipt{}, err
	}
	hash, err := idempotency.RequestHash(request)
	if err != nil {
		return Receipt{}, err
	}

	// Identifiers are allocated before the transaction, because the durable
	// generator runs its own. A serialization retry burns the candidates
	// rather than reusing them — exactly as provisioning and payments do.
	payerTransactionID, err := s.nextID(ctx, "transfer_")
	if err != nil {
		return Receipt{}, err
	}
	payeeTransactionID, err := s.nextID(ctx, "transfer_")
	if err != nil {
		return Receipt{}, err
	}

	var receipt Receipt
	err = s.transactions.RunSerializable(ctx, func(tx pgx.Tx) error {
		existing, found, err := loadTransfer(ctx, tx, request.IdempotencyScope, request.IdempotencyKey)
		if err != nil {
			return err
		}
		if found {
			if existing.requestHash != hash {
				return ErrRequestConflict
			}
			receipt = existing.receipt()
			return nil
		}

		payer, err := loadAccount(ctx, tx, request.PayerAccountID)
		if err != nil {
			return err
		}
		payee, err := loadAccount(ctx, tx, request.PayeeAccountID)
		if err != nil {
			return err
		}
		if err := checkParties(request, payer, payee); err != nil {
			return err
		}

		// Two authorization checks, because a capability is scoped to a book
		// and the two parties may be in different ones. Neither implies the
		// other.
		if err := s.authorize(ctx, request.PrincipalID, payer.bookID,
			payer.accountID, PermissionDebit); err != nil {
			return err
		}
		if err := s.authorize(ctx, request.PrincipalID, payee.bookID,
			payee.accountID, PermissionCredit); err != nil {
			return err
		}

		legs, err := s.planLegs(ctx, tx, request, payer, payee,
			payerTransactionID, payeeTransactionID)
		if err != nil {
			return err
		}

		// The legs are written in a globally fixed order — by book identifier —
		// so two opposing transfers, A→B and B→A, acquire the two books' chain
		// rows in the same sequence and cannot deadlock against each other.
		sort.Slice(legs, func(i, j int) bool { return legs[i].bookID < legs[j].bookID })

		posted := make([]postedLeg, 0, len(legs))
		for _, leg := range legs {
			postRequest := ledger.PostRequest{
				TransactionID:      leg.transactionID,
				BookID:             leg.bookID,
				OperationID:        request.TransferID,
				EffectID:           leg.effectID,
				Kind:               leg.kind,
				PostingRuleVersion: s.config.PolicyVersion,
				SchemaVersion:      1,
				RequestHash:        hash,
				Metadata:           leg.metadata,
				Lines:              leg.lines,
			}
			result, err := s.journal.PostInTx(ctx, tx, postRequest)
			if err != nil {
				return classifyPostingError(err)
			}
			posted = append(posted, postedLeg{plan: leg, transactionID: result.TransactionID})
		}

		if err := insertTransfer(ctx, tx, request, payer, payee, s.config.Region, hash); err != nil {
			return err
		}
		for _, leg := range posted {
			if _, err := tx.Exec(ctx, `
INSERT INTO transfer_effects
    (transfer_effect_id, transfer_id, leg, book_id, ledger_transaction_id, amount_atoms)
VALUES ($1,$2,$3,$4,$5,$6::DECIMAL)`,
				leg.plan.effectID, request.TransferID, leg.plan.leg, leg.plan.bookID,
				leg.transactionID, request.AmountAtoms.String()); err != nil {
				return err
			}
		}

		// Spending rights move with the value, in the same transaction. Without
		// this the recipient could not spend what they received, and the escrow
		// conservation invariant would drift by the transferred amount.
		if err := s.moveEscrow(ctx, tx, request, "SPEND", request.PayerAccountID); err != nil {
			return err
		}
		if err := s.moveEscrow(ctx, tx, request, "RETURN", request.PayeeAccountID); err != nil {
			return err
		}

		if err := s.publish(ctx, tx, request, payer, payee, posted); err != nil {
			return err
		}

		receipt = Receipt{
			TransferID:  request.TransferID,
			PayerBookID: payer.bookID, PayeeBookID: payee.bookID,
			CrossBook: payer.bookID != payee.bookID,
		}
		for _, leg := range posted {
			switch leg.plan.leg {
			case legSingle:
				receipt.PayerTransactionID = leg.transactionID
				receipt.PayeeTransactionID = leg.transactionID
			case legPayer:
				receipt.PayerTransactionID = leg.transactionID
			case legPayee:
				receipt.PayeeTransactionID = leg.transactionID
			}
		}
		return nil
	})
	if err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

func (s *Service) nextID(ctx context.Context, prefix string) (string, error) {
	value, err := s.ids.Next(ctx)
	if err != nil {
		return "", err
	}
	return prefix + value, nil
}

func (s *Service) authorize(ctx context.Context, principal, bookID, accountID, permission string) error {
	err := s.capabilities.Authorize(ctx, authz.Request{
		Principal: principal, BookID: bookID,
		Accounts: []authz.AccountPermission{{AccountID: accountID, Permission: permission}},
	})
	if errors.Is(err, authz.ErrDenied) {
		return fmt.Errorf("%w: %s on %s", ErrDenied, permission, accountID)
	}
	return err
}

func (s *Service) moveEscrow(ctx context.Context, tx pgx.Tx, request Request, kind, accountID string) error {
	effectID := request.TransferID + ":" + strings.ToLower(kind)
	var applied bool
	err := tx.QueryRow(ctx, `
SELECT public.apply_transfer_escrow_effect($1,$2,$3,$4,$5,$6,$7::DECIMAL)`,
		effectID, kind, request.TransferID, accountID, request.AssetID,
		s.config.Region, request.AmountAtoms.String()).Scan(&applied)
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "escrow insufficient rights") {
		return fmt.Errorf("%w: %s", ErrInsufficientFunds, accountID)
	}
	return err
}

func (r Request) validate() error {
	if !boundedID(r.TransferID) || !boundedID(r.IdempotencyScope) || !boundedID(r.IdempotencyKey) ||
		!boundedID(r.PrincipalID) || !boundedID(r.AssetID) ||
		!boundedID(r.PayerAccountID) || !boundedID(r.PayeeAccountID) {
		return fmt.Errorf("%w: identifiers are required", ErrInvalidRequest)
	}
	if r.AmountAtoms.Sign() <= 0 {
		return fmt.Errorf("%w: amount must be positive", ErrInvalidRequest)
	}
	if r.PayerAccountID == r.PayeeAccountID {
		return ErrSameAccount
	}
	if len(r.Memo) > 512 {
		return fmt.Errorf("%w: memo is too long", ErrInvalidRequest)
	}
	return nil
}

func boundedID(value string) bool {
	return value != "" && len(value) <= 512 && strings.TrimSpace(value) == value
}
