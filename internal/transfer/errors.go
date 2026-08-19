package transfer

import (
	"errors"
	"strings"

	"github.com/example/payment-platform/internal/ledger"
)

// classifyPostingError turns the ledger's refusal into an answer the caller
// can act on.
//
// The spend-limit trigger is the last line of defence against overdrawing an
// account, and it fires as a posting error. Reporting that as an internal
// fault would tell the customer nothing and would look like a system failure
// rather than the deliberate refusal it is.
func classifyPostingError(err error) error {
	if err == nil {
		return nil
	}
	message := err.Error()
	switch {
	case errors.Is(err, ledger.ErrInsufficientFunds),
		strings.Contains(message, "spend limit"),
		strings.Contains(message, "insufficient"):
		return ErrInsufficientFunds
	case strings.Contains(message, "different book"):
		// Only reachable if a settlement account were registered against the
		// wrong book, which is a provisioning defect rather than a caller one.
		return ErrSettlementMissing
	}
	return err
}
