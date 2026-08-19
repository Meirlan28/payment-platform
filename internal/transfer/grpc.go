package transfer

import (
	"context"
	"errors"
	"log/slog"

	transferv1 "github.com/example/payment-platform/gen/go/transfer/v1"
	"github.com/example/payment-platform/internal/ledger"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// PrincipalResolver returns the verified workload identity of the caller.
type PrincipalResolver func(context.Context) (string, error)

// Server is the gRPC surface.
//
// Two gates stand in front of every transfer, and they answer different
// questions. The permitted-caller list asks whether this workload may use the
// transfer API at all; the ledger's capability check asks whether the
// principal named in the request may move these particular accounts. Neither
// implies the other, and dropping either would leave the surface usable by
// something that should not have it.
type Server struct {
	transferv1.UnimplementedTransferServiceServer
	Transfers        *Service
	ResolvePrincipal PrincipalResolver
	Logger           *slog.Logger
	// PermittedCallers lists the workload identities allowed to move customer
	// money. An empty set denies everything rather than defaulting to open.
	PermittedCallers map[string]struct{}
}

func (s *Server) Execute(ctx context.Context, request *transferv1.ExecuteRequest) (*transferv1.ExecuteResponse, error) {
	principal, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	amount, err := ledger.ParseAmount(request.GetAmountAtoms())
	if err != nil || amount.Sign() <= 0 {
		return nil, status.Error(codes.InvalidArgument,
			"amount_atoms must be a positive DECIMAL(38,0) integer")
	}
	receipt, err := s.Transfers.Execute(ctx, Request{
		TransferID:       request.GetTransferId(),
		IdempotencyScope: request.GetIdempotencyScope(),
		IdempotencyKey:   request.GetIdempotencyKey(),
		// The principal whose capabilities are checked is the caller's own
		// verified identity, never a value from the request body. A field the
		// caller controls would let a compromised client name somebody else's
		// authority.
		PrincipalID:    principal,
		AssetID:        request.GetAssetId(),
		PayerAccountID: request.GetPayerAccountId(),
		PayeeAccountID: request.GetPayeeAccountId(),
		AmountAtoms:    amount,
		Memo:           request.GetMemo(),
	})
	if err != nil {
		return nil, s.reject(err)
	}
	return &transferv1.ExecuteResponse{
		Transfer:         message(receipt, request),
		IdempotentReplay: receipt.Duplicate,
	}, nil
}

func (s *Server) GetTransfer(ctx context.Context, request *transferv1.GetTransferRequest) (*transferv1.GetTransferResponse, error) {
	if _, err := s.caller(ctx); err != nil {
		return nil, err
	}
	found, err := s.Transfers.Lookup(ctx, request.GetTransferId(),
		request.GetIdempotencyScope(), request.GetIdempotencyKey())
	if err != nil {
		return nil, s.reject(err)
	}
	return &transferv1.GetTransferResponse{Transfer: &transferv1.Transfer{
		TransferId: found.TransferID, AssetId: found.AssetID,
		PayerAccountId: found.PayerAccountID, PayeeAccountId: found.PayeeAccountID,
		AmountAtoms: found.AmountAtoms, State: found.State,
		PayerTransactionId: found.PayerTransactionID,
		PayeeTransactionId: found.PayeeTransactionID,
		PayerBookId:        found.PayerBookID, PayeeBookId: found.PayeeBookID,
		CrossBook: found.PayerBookID != found.PayeeBookID,
	}}, nil
}

func (s *Server) caller(ctx context.Context) (string, error) {
	if s == nil || s.Transfers == nil || s.ResolvePrincipal == nil {
		return "", status.Error(codes.Internal, "transfer API is not configured")
	}
	principal, err := s.ResolvePrincipal(ctx)
	if err != nil || principal == "" {
		return "", status.Error(codes.Unauthenticated, "verified client identity is required")
	}
	if _, permitted := s.PermittedCallers[principal]; !permitted {
		return "", status.Error(codes.PermissionDenied,
			"caller is not permitted to move customer funds")
	}
	return principal, nil
}

// reject maps a failure onto the status the caller must act on.
//
// The distinction that matters most is between a refusal and an unknown
// outcome. Everything named here is a decision the service made deliberately;
// anything unnamed becomes Internal, which callers must treat as ambiguous and
// resolve with GetTransfer rather than assume failed.
func (s *Server) reject(err error) error {
	switch {
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrSameAccount):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, ErrRequestConflict):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.Is(err, ErrAccountNotFound), errors.Is(err, ErrTransferNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, ErrDenied):
		return status.Error(codes.PermissionDenied, err.Error())
	case errors.Is(err, ErrInsufficientFunds), errors.Is(err, ErrAssetMismatch),
		errors.Is(err, ErrAccountNotUsable):
		// Understood and refused, with nothing applied. Retrying changes
		// nothing, which is exactly what FailedPrecondition tells the caller.
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, ErrSettlementMissing):
		// A book without its settlement account is a provisioning defect, not
		// a caller error, and it will not fix itself on retry.
		if s.Logger != nil {
			s.Logger.Error("transfer refused: settlement account missing", "error", err)
		}
		return status.Error(codes.FailedPrecondition, err.Error())
	}
	if s.Logger != nil {
		s.Logger.Error("transfer failed", "error", err)
	}
	return status.Error(codes.Internal, "the transfer could not be completed")
}

func message(receipt Receipt, request *transferv1.ExecuteRequest) *transferv1.Transfer {
	return &transferv1.Transfer{
		TransferId: receipt.TransferID, AssetId: request.GetAssetId(),
		PayerAccountId: request.GetPayerAccountId(),
		PayeeAccountId: request.GetPayeeAccountId(),
		AmountAtoms:    request.GetAmountAtoms(), State: "SETTLED",
		PayerTransactionId: receipt.PayerTransactionID,
		PayeeTransactionId: receipt.PayeeTransactionID,
		PayerBookId:        receipt.PayerBookID, PayeeBookId: receipt.PayeeBookID,
		CrossBook: receipt.CrossBook,
	}
}
