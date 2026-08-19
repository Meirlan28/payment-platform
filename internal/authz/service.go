// Package authz enforces fail-closed, account-level payment capabilities for
// an authenticated workload principal. Grants and revocations are immutable
// policy facts; this service has read-only database privileges.
package authz

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

const (
	AuthorizePayerAvailable   = "AUTHORIZE_PAYER_AVAILABLE"
	AuthorizePayerHeld        = "AUTHORIZE_PAYER_HELD"
	AuthorizeMerchant         = "AUTHORIZE_MERCHANT"
	CaptureFee                = "CAPTURE_FEE"
	CaptureTax                = "CAPTURE_TAX"
	CaptureCashbackExpense    = "CAPTURE_CASHBACK_EXPENSE"
	RefundMerchantDebit       = "REFUND_MERCHANT_DEBIT"
	ChargebackMerchantReserve = "CHARGEBACK_MERCHANT_RESERVE"
	// Transfers between customers. Held separately from the payment
	// permissions, and separately from each other, so that no single
	// credential can both take money from one account and put it into
	// another of its choosing.
	TransferDebitAvailable  = "TRANSFER_DEBIT_AVAILABLE"
	TransferCreditAvailable = "TRANSFER_CREDIT_AVAILABLE"
)

var ErrDenied = errors.New("authz: payment account capability denied")

type Queryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

type AccountPermission struct {
	AccountID  string
	Permission string
}

type Request struct {
	Principal string
	BookID    string
	Accounts  []AccountPermission
}

type Service struct {
	db Queryer
}

func New(db Queryer) (*Service, error) {
	if db == nil {
		return nil, errors.New("authz: database is required")
	}
	return &Service{db: db}, nil
}

// Authorize succeeds only when every distinct requested account/permission
// pair has an unrevoked immutable capability for this exact principal and
// book. It deliberately has no wildcard or tenant fallback.
func (s *Service) Authorize(ctx context.Context, request Request) error {
	if s == nil || s.db == nil || request.Principal == "" || request.BookID == "" || len(request.Accounts) == 0 {
		return ErrDenied
	}
	type key struct{ account, permission string }
	distinct := make([]key, 0, len(request.Accounts))
	seen := make(map[key]struct{}, len(request.Accounts))
	for _, item := range request.Accounts {
		item.AccountID = strings.TrimSpace(item.AccountID)
		item.Permission = strings.TrimSpace(item.Permission)
		if item.AccountID == "" || item.Permission == "" {
			return ErrDenied
		}
		current := key{account: item.AccountID, permission: item.Permission}
		if _, exists := seen[current]; exists {
			continue
		}
		seen[current] = struct{}{}
		distinct = append(distinct, current)
	}

	arguments := make([]any, 0, 2+len(distinct)*2)
	arguments = append(arguments, request.Principal, request.BookID)
	values := make([]string, 0, len(distinct))
	for index, item := range distinct {
		base := 3 + index*2
		values = append(values, fmt.Sprintf("($%d::STRING, $%d::STRING)", base, base+1))
		arguments = append(arguments, item.account, item.permission)
	}
	query := `
WITH requested(account_id, permission) AS (VALUES ` + strings.Join(values, ",") + `)
SELECT count(*)
  FROM requested AS request
	 WHERE EXISTS (
	       SELECT 1
	         FROM payment_account_capabilities AS capability
	        WHERE capability.principal_id = $1
          AND capability.book_id = $2
          AND capability.account_id = request.account_id
          AND capability.permission = request.permission
          AND NOT EXISTS (
              SELECT 1 FROM payment_account_capability_revocations AS revocation
               WHERE revocation.capability_id = capability.capability_id
          )
 )`
	var allowed int
	if err := s.db.QueryRow(ctx, query, arguments...).Scan(&allowed); err != nil {
		return fmt.Errorf("authz: evaluate capabilities: %w", err)
	}
	if allowed != len(distinct) {
		return ErrDenied
	}
	return nil
}
