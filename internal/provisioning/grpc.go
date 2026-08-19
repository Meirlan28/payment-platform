package provisioning

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	provisioningv1 "github.com/example/payment-platform/gen/go/provisioning/v1"
	"github.com/example/payment-platform/internal/ledger"
	"github.com/example/payment-platform/internal/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// PrincipalResolver returns the verified identity of the calling workload.
// Production passes api.SPIFFEPrincipal, which reads the client certificate
// and ignores anything the caller could set itself.
type PrincipalResolver func(context.Context) (string, error)

// AccountProvisioningServer is the authenticated boundary for opening
// accounts. It resolves the payment principal through the allowlist, never
// from the request.
type AccountProvisioningServer struct {
	provisioningv1.UnimplementedAccountProvisioningServiceServer
	Accounts         *Service
	Allowlist        *Allowlist
	ResolvePrincipal PrincipalResolver
	// Logger records the cause of failures that are deliberately reported to
	// the caller as an opaque Internal error. Without it a misconfigured
	// service rejects every request and says nothing about why.
	Logger *slog.Logger
}

func (s *AccountProvisioningServer) ProvisionCustomerAccount(
	ctx context.Context,
	request *provisioningv1.ProvisionCustomerAccountRequest,
) (*provisioningv1.ProvisionCustomerAccountResponse, error) {
	principal, err := s.principal(ctx)
	if err != nil {
		return nil, err
	}
	paymentPrincipal, err := s.Allowlist.Resolve(principal, request.GetPaymentPrincipalSelector())
	if err != nil {
		return nil, s.reject(ctx, err)
	}
	// Resolved through the same allowlist and the same rules, but only when the
	// caller actually asked for it. An omitted selector must not fall back to
	// the payment principal: that would hand transfer authority to a workload
	// nobody named, which is exactly what the selector indirection prevents.
	var transferPrincipal string
	if selector := request.GetTransferPrincipalSelector(); selector != "" {
		transferPrincipal, err = s.Allowlist.Resolve(principal, selector)
		if err != nil {
			return nil, s.reject(ctx, err)
		}
	}
	result, err := s.Accounts.ProvisionCustomerAccount(ctx, CustomerAccountRequest{
		ExternalReference:   request.GetExternalReference(),
		AssetID:             request.GetAssetId(),
		PaymentPrincipalID:  paymentPrincipal,
		TransferPrincipalID: transferPrincipal,
	})
	if err != nil {
		return nil, s.reject(ctx, err)
	}
	return &provisioningv1.ProvisionCustomerAccountResponse{
		Region: result.Region, BookId: result.BookID,
		AvailableAccountId: result.AvailableAccountID,
		HeldAccountId:      result.HeldAccountID,
		IdempotentReplay:   result.Duplicate,
	}, nil
}

func (s *AccountProvisioningServer) ProvisionMerchantAccount(
	ctx context.Context,
	request *provisioningv1.ProvisionMerchantAccountRequest,
) (*provisioningv1.ProvisionMerchantAccountResponse, error) {
	principal, err := s.principal(ctx)
	if err != nil {
		return nil, err
	}
	paymentPrincipal, err := s.Allowlist.Resolve(principal, request.GetPaymentPrincipalSelector())
	if err != nil {
		return nil, s.reject(ctx, err)
	}
	if err := s.Accounts.ProvisionMerchantAccount(ctx, MerchantAccountRequest{
		AccountID: request.GetAccountId(), AssetID: request.GetAssetId(),
		BookID: request.GetBookId(), PaymentPrincipalID: paymentPrincipal,
	}); err != nil {
		return nil, s.reject(ctx, err)
	}
	return &provisioningv1.ProvisionMerchantAccountResponse{AccountId: request.GetAccountId()}, nil
}

func (s *AccountProvisioningServer) principal(ctx context.Context) (string, error) {
	if s == nil || s.Accounts == nil || s.Allowlist == nil || s.ResolvePrincipal == nil {
		return "", status.Error(codes.Internal, "provisioning API is not configured")
	}
	principal, err := s.ResolvePrincipal(ctx)
	if err != nil || principal == "" {
		return "", status.Error(codes.Unauthenticated, "verified client identity is required")
	}
	return principal, nil
}

// FundingServer is the authenticated boundary for crediting an account. Its
// caller is a rail or settlement adapter, a different credential class from
// the one permitted to open accounts.
type FundingServer struct {
	provisioningv1.UnimplementedFundingServiceServer
	Accounts         *Service
	ResolvePrincipal PrincipalResolver
	Logger           *slog.Logger
	// PermittedCallers lists the workload identities allowed to create value.
	// An empty set denies everything rather than defaulting to open.
	PermittedCallers map[string]struct{}
}

func (s *FundingServer) Deposit(
	ctx context.Context,
	request *provisioningv1.DepositRequest,
) (*provisioningv1.DepositResponse, error) {
	if s == nil || s.Accounts == nil || s.ResolvePrincipal == nil {
		return nil, status.Error(codes.Internal, "funding API is not configured")
	}
	principal, err := s.ResolvePrincipal(ctx)
	if err != nil || principal == "" {
		return nil, status.Error(codes.Unauthenticated, "verified client identity is required")
	}
	if _, permitted := s.PermittedCallers[principal]; !permitted {
		return nil, status.Error(codes.PermissionDenied, "caller is not permitted to credit accounts")
	}
	amount, err := ledger.ParseAmount(request.GetAmountAtoms())
	if err != nil || amount.Sign() <= 0 {
		return nil, status.Error(codes.InvalidArgument,
			"amount_atoms must be a positive DECIMAL(38,0) integer")
	}
	result, err := s.Accounts.Deposit(ctx, DepositRequest{
		ExternalReference:      request.GetExternalReference(),
		AccountID:              request.GetAccountId(),
		AssetID:                request.GetAssetId(),
		AmountAtoms:            amount,
		FundingSourceReference: request.GetFundingSourceReference(),
	})
	if err != nil {
		return nil, s.reject(ctx, err)
	}
	return &provisioningv1.DepositResponse{
		LedgerTransactionId: result.LedgerTransactionID,
		IdempotentReplay:    result.Duplicate,
	}, nil
}

// LedgerQueryServer serves authoritative account snapshots. It is read-only:
// its database role holds SELECT and nothing else.
type LedgerQueryServer struct {
	provisioningv1.UnimplementedLedgerQueryServiceServer
	DB               store.Beginner
	ResolvePrincipal PrincipalResolver
	Logger           *slog.Logger
	// MaxSnapshotAge bounds how far back a caller may read, so a request
	// cannot ask for a timestamp the cluster has already garbage collected.
	MaxSnapshotAge time.Duration
	// MinSnapshotAge keeps reads far enough in the past to be a meaningful
	// watermark rather than a racy "now".
	MinSnapshotAge time.Duration
}

func (s *LedgerQueryServer) GetAccountSnapshot(
	ctx context.Context,
	request *provisioningv1.GetAccountSnapshotRequest,
) (*provisioningv1.GetAccountSnapshotResponse, error) {
	if s == nil || s.DB == nil || s.ResolvePrincipal == nil {
		return nil, status.Error(codes.Internal, "ledger query API is not configured")
	}
	principal, err := s.ResolvePrincipal(ctx)
	if err != nil || principal == "" {
		return nil, status.Error(codes.Unauthenticated, "verified client identity is required")
	}
	if !request.GetAsOf().IsValid() {
		return nil, status.Error(codes.InvalidArgument, "as_of is required")
	}
	asOf := request.GetAsOf().AsTime()
	age := time.Since(asOf)
	if minimum := s.MinSnapshotAge; minimum > 0 && age < minimum {
		return nil, status.Errorf(codes.InvalidArgument,
			"as_of must be at least %s in the past", minimum)
	}
	if maximum := s.MaxSnapshotAge; maximum > 0 && age > maximum {
		return nil, status.Errorf(codes.OutOfRange,
			"as_of is older than the %s retained history", maximum)
	}

	snapshot, err := AccountSnapshot(ctx, s.DB, request.GetAccountId(),
		request.GetAssetId(), request.GetRegion(), asOf)
	if err != nil {
		return nil, s.reject(ctx, err)
	}
	return &provisioningv1.GetAccountSnapshotResponse{
		AccountId: snapshot.AccountID, AssetId: snapshot.AssetID, Region: snapshot.Region,
		BalanceAtoms:         snapshot.BalanceAtoms.String(),
		EscrowAvailableAtoms: snapshot.EscrowAvailableAtoms.String(),
		LastSequenceNo:       snapshot.LastSequenceNo,
		AsOf:                 timestamppb.New(snapshot.AsOf),
	}, nil
}

// reject maps the error for the caller and, when the mapped status hides the
// cause, records it locally. The caller still learns nothing it should not.
func (s *AccountProvisioningServer) reject(ctx context.Context, err error) error {
	return logRejected(ctx, s.Logger, "account-provisioning", err)
}

func (s *FundingServer) reject(ctx context.Context, err error) error {
	return logRejected(ctx, s.Logger, "funding", err)
}

func (s *LedgerQueryServer) reject(ctx context.Context, err error) error {
	return logRejected(ctx, s.Logger, "ledger-query", err)
}

func logRejected(_ context.Context, logger *slog.Logger, operation string, err error) error {
	mapped := mapError(err)
	if logger != nil && status.Code(mapped) == codes.Internal {
		logger.Error("request failed", "operation", operation, "error", err)
	}
	return mapped
}

// mapError keeps the platform's status contract: an ambiguous outcome is
// reported as such so the caller retries with the same external reference
// instead of treating it as a failure.
func mapError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrAmbiguousCommit):
		return status.Error(codes.Unavailable,
			"commit outcome is unknown; retry the same external reference")
	case errors.Is(err, ErrPrincipalDenied):
		return status.Error(codes.PermissionDenied, err.Error())
	case errors.Is(err, ErrRequestConflict):
		return status.Error(codes.AlreadyExists,
			"external reference was already used for a different request")
	case errors.Is(err, ErrNotProvisioned), errors.Is(err, ledger.ErrAccountNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, ErrEscrowMissing):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ledger.ErrInvalidPosting),
		errors.Is(err, ledger.ErrAssetMismatch), errors.Is(err, ledger.ErrAmountOverflow),
		errors.Is(err, ledger.ErrCrossBook):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, ledger.ErrInsufficientFunds):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.DeadlineExceeded,
			"deadline exceeded; retry with the same external reference")
	case errors.Is(err, context.Canceled):
		return status.Error(codes.Canceled,
			"request canceled; retry with the same external reference")
	default:
		return status.Error(codes.Internal, fmt.Sprintf("provisioning command failed (%T)", err))
	}
}
