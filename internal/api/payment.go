// Package api is the authenticated gRPC boundary for financial commands.
package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	paymentv1 "github.com/example/payment-platform/gen/go/payment/v1"
	"github.com/example/payment-platform/internal/authz"
	"github.com/example/payment-platform/internal/escrow"
	"github.com/example/payment-platform/internal/idempotency"
	"github.com/example/payment-platform/internal/ledger"
	"github.com/example/payment-platform/internal/payment"
	"github.com/example/payment-platform/internal/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const maxIdempotencyKeyBytes = 128

type PaymentCommands interface {
	Authorize(context.Context, payment.HoldRequest) (payment.Receipt, error)
	Capture(context.Context, payment.CaptureRequest) (payment.Receipt, error)
	Release(context.Context, payment.ReleaseRequest) (payment.Receipt, error)
	Reversal(context.Context, payment.ReleaseRequest) (payment.Receipt, error)
	Refund(context.Context, payment.RefundRequest) (payment.Receipt, error)
	Chargeback(context.Context, payment.ChargebackRequest) (payment.Receipt, error)
	GetForScope(context.Context, string, string) (payment.Receipt, error)
}

type PrincipalResolver func(context.Context) (string, error)

type PaymentAuthorizer interface {
	Authorize(context.Context, authz.Request) error
}

type PaymentServer struct {
	paymentv1.UnimplementedPaymentServiceServer
	Payments          PaymentCommands
	RegionID          string
	ResolvePrincipal  PrincipalResolver
	AuthorizeAccounts PaymentAuthorizer
}

func (s *PaymentServer) Authorize(ctx context.Context, request *paymentv1.AuthorizeRequest) (*paymentv1.AuthorizeResponse, error) {
	principal, err := s.principal(ctx)
	if err != nil {
		return nil, err
	}
	if err := validateKey(request.GetIdempotencyKey()); err != nil {
		return nil, err
	}
	amount, err := requiredMoney(request.GetAmount())
	if err != nil {
		return nil, err
	}
	cashbackRule, err := optionalMoney(request.GetCashbackRuleMaximum(), amount.asset)
	if err != nil {
		return nil, err
	}
	if request.GetAuthorityRegion() == "" || request.GetAuthorityRegion() != s.RegionID {
		return nil, status.Error(codes.InvalidArgument, "authority_region must equal the serving region")
	}
	if err := s.authorize(ctx, principal, request.GetBookId(), []authz.AccountPermission{
		{AccountID: request.GetPayerAccountId(), Permission: authz.AuthorizePayerAvailable},
		{AccountID: request.GetPayerHeldAccountId(), Permission: authz.AuthorizePayerHeld},
		{AccountID: request.GetMerchantAccountId(), Permission: authz.AuthorizeMerchant},
	}); err != nil {
		return nil, err
	}
	receipt, err := s.Payments.Authorize(ctx, payment.HoldRequest{
		Scope: "principal/" + principal, IdempotencyKey: request.GetIdempotencyKey(),
		BookID: request.GetBookId(), AssetID: amount.asset,
		CustomerAvailableAccountID: request.GetPayerAccountId(),
		CustomerHeldAccountID:      request.GetPayerHeldAccountId(),
		MerchantAccountID:          request.GetMerchantAccountId(), Amount: amount.amount,
		CashbackRuleMaximum: cashbackRule, PostingRuleVersion: request.GetPostingRuleVersion(),
		AuthorityRegion: request.GetAuthorityRegion(),
	})
	if err != nil {
		return nil, mapError(err)
	}
	return &paymentv1.AuthorizeResponse{Payment: paymentMessage(receipt)}, nil
}

func (s *PaymentServer) Capture(ctx context.Context, request *paymentv1.CaptureRequest) (*paymentv1.CaptureResponse, error) {
	principal, err := s.principal(ctx)
	if err != nil {
		return nil, err
	}
	if err := validateKey(request.GetIdempotencyKey()); err != nil {
		return nil, err
	}
	amount, err := requiredMoney(request.GetAmount())
	if err != nil {
		return nil, err
	}
	fee, err := optionalMoney(request.GetFee(), amount.asset)
	if err != nil {
		return nil, err
	}
	tax, err := optionalMoney(request.GetTax(), amount.asset)
	if err != nil {
		return nil, err
	}
	cashback, err := optionalMoney(request.GetCashback(), amount.asset)
	if err != nil {
		return nil, err
	}
	permissions := make([]authz.AccountPermission, 0, 3)
	if fee.Sign() > 0 {
		permissions = append(permissions, authz.AccountPermission{AccountID: request.GetFeeAccountId(), Permission: authz.CaptureFee})
	}
	if tax.Sign() > 0 {
		permissions = append(permissions, authz.AccountPermission{AccountID: request.GetTaxAccountId(), Permission: authz.CaptureTax})
	}
	if cashback.Sign() > 0 {
		permissions = append(permissions, authz.AccountPermission{AccountID: request.GetCashbackExpenseAccountId(), Permission: authz.CaptureCashbackExpense})
	}
	if len(permissions) > 0 {
		if err := s.authorize(ctx, principal, request.GetBookId(), permissions); err != nil {
			return nil, err
		}
	}
	receipt, err := s.Payments.Capture(ctx, payment.CaptureRequest{
		Scope: "principal/" + principal, IdempotencyKey: request.GetIdempotencyKey(),
		PaymentID: request.GetPaymentId(), BookID: request.GetBookId(), AssetID: amount.asset,
		Amount: amount.amount, Fee: fee, Tax: tax, Cashback: cashback,
		FeeAccountID: request.GetFeeAccountId(), TaxAccountID: request.GetTaxAccountId(),
		CashbackExpenseAccountID: request.GetCashbackExpenseAccountId(),
		PostingRuleVersion:       request.GetPostingRuleVersion(),
	})
	if err != nil {
		return nil, mapError(err)
	}
	return &paymentv1.CaptureResponse{Payment: paymentMessage(receipt)}, nil
}

func (s *PaymentServer) Release(ctx context.Context, request *paymentv1.ReleaseRequest) (*paymentv1.ReleaseResponse, error) {
	principal, err := s.principal(ctx)
	if err != nil {
		return nil, err
	}
	if err := validateKey(request.GetIdempotencyKey()); err != nil {
		return nil, err
	}
	amount, err := requiredMoney(request.GetAmount())
	if err != nil {
		return nil, err
	}
	receipt, err := s.Payments.Release(ctx, payment.ReleaseRequest{
		Scope: "principal/" + principal, IdempotencyKey: request.GetIdempotencyKey(),
		PaymentID: request.GetPaymentId(), BookID: request.GetBookId(), AssetID: amount.asset,
		Amount: amount.amount, PostingRuleVersion: request.GetPostingRuleVersion(),
	})
	if err != nil {
		return nil, mapError(err)
	}
	return &paymentv1.ReleaseResponse{Payment: paymentMessage(receipt)}, nil
}

func (s *PaymentServer) Reversal(ctx context.Context, request *paymentv1.ReversalRequest) (*paymentv1.ReversalResponse, error) {
	principal, err := s.principal(ctx)
	if err != nil {
		return nil, err
	}
	if err := validateKey(request.GetIdempotencyKey()); err != nil {
		return nil, err
	}
	amount, err := requiredMoney(request.GetAmount())
	if err != nil {
		return nil, err
	}
	receipt, err := s.Payments.Reversal(ctx, payment.ReleaseRequest{
		Scope: "principal/" + principal, IdempotencyKey: request.GetIdempotencyKey(),
		PaymentID: request.GetPaymentId(), BookID: request.GetBookId(), AssetID: amount.asset,
		Amount: amount.amount, PostingRuleVersion: request.GetPostingRuleVersion(),
	})
	if err != nil {
		return nil, mapError(err)
	}
	return &paymentv1.ReversalResponse{Payment: paymentMessage(receipt)}, nil
}

func (s *PaymentServer) Refund(ctx context.Context, request *paymentv1.RefundRequest) (*paymentv1.RefundResponse, error) {
	principal, err := s.principal(ctx)
	if err != nil {
		return nil, err
	}
	if err := validateKey(request.GetIdempotencyKey()); err != nil {
		return nil, err
	}
	amount, err := requiredMoney(request.GetAmount())
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, principal, request.GetBookId(), []authz.AccountPermission{{
		AccountID: request.GetMerchantDebitAccountId(), Permission: authz.RefundMerchantDebit,
	}}); err != nil {
		return nil, err
	}
	receipt, err := s.Payments.Refund(ctx, payment.RefundRequest{
		Scope: "principal/" + principal, IdempotencyKey: request.GetIdempotencyKey(),
		PaymentID: request.GetPaymentId(), BookID: request.GetBookId(), AssetID: amount.asset,
		OriginalCaptureTransactionID: request.GetOriginalCaptureTransactionId(),
		MerchantDebitAccountID:       request.GetMerchantDebitAccountId(), Amount: amount.amount,
		PostingRuleVersion: request.GetPostingRuleVersion(),
	})
	if err != nil {
		return nil, mapError(err)
	}
	return &paymentv1.RefundResponse{Payment: paymentMessage(receipt)}, nil
}

func (s *PaymentServer) Chargeback(ctx context.Context, request *paymentv1.ChargebackRequest) (*paymentv1.ChargebackResponse, error) {
	principal, err := s.principal(ctx)
	if err != nil {
		return nil, err
	}
	if err := validateKey(request.GetIdempotencyKey()); err != nil {
		return nil, err
	}
	amount, err := requiredMoney(request.GetAmount())
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, principal, request.GetBookId(), []authz.AccountPermission{{
		AccountID: request.GetMerchantReserveAccountId(), Permission: authz.ChargebackMerchantReserve,
	}}); err != nil {
		return nil, err
	}
	receipt, err := s.Payments.Chargeback(ctx, payment.ChargebackRequest{
		Scope: "principal/" + principal, IdempotencyKey: request.GetIdempotencyKey(),
		PaymentID: request.GetPaymentId(), BookID: request.GetBookId(), AssetID: amount.asset,
		OriginalCaptureTransactionID: request.GetOriginalCaptureTransactionId(),
		MerchantReserveAccountID:     request.GetMerchantReserveAccountId(),
		Amount:                       amount.amount,
		PostingRuleVersion:           request.GetPostingRuleVersion(),
	})
	if err != nil {
		return nil, mapError(err)
	}
	return &paymentv1.ChargebackResponse{Payment: paymentMessage(receipt)}, nil
}

func (s *PaymentServer) GetPayment(ctx context.Context, request *paymentv1.GetPaymentRequest) (*paymentv1.GetPaymentResponse, error) {
	principal, err := s.principal(ctx)
	if err != nil {
		return nil, err
	}
	if request.GetPaymentId() == "" {
		return nil, status.Error(codes.InvalidArgument, "payment_id is required")
	}
	receipt, err := s.Payments.GetForScope(ctx, "principal/"+principal, request.GetPaymentId())
	if err != nil {
		return nil, mapError(err)
	}
	return &paymentv1.GetPaymentResponse{Payment: paymentMessage(receipt)}, nil
}

func (s *PaymentServer) principal(ctx context.Context) (string, error) {
	if s == nil || s.Payments == nil || s.ResolvePrincipal == nil || s.AuthorizeAccounts == nil || s.RegionID == "" {
		return "", status.Error(codes.Internal, "payment API is not configured")
	}
	principal, err := s.ResolvePrincipal(ctx)
	if err != nil || principal == "" {
		return "", status.Error(codes.Unauthenticated, "verified client identity is required")
	}
	return principal, nil
}

func (s *PaymentServer) authorize(ctx context.Context, principal, bookID string, accounts []authz.AccountPermission) error {
	if bookID == "" {
		return status.Error(codes.InvalidArgument, "book_id is required")
	}
	if err := s.AuthorizeAccounts.Authorize(ctx, authz.Request{
		Principal: principal, BookID: bookID, Accounts: accounts,
	}); err != nil {
		if errors.Is(err, authz.ErrDenied) {
			return status.Error(codes.PermissionDenied, "principal is not entitled to the requested payment accounts")
		}
		return status.Error(codes.Unavailable, "authorization policy could not be evaluated")
	}
	return nil
}

// SPIFFEPrincipal requires a verified mTLS peer and uses exactly one URI SAN
// as the idempotency/security principal. Client-controlled metadata is ignored.
func SPIFFEPrincipal(ctx context.Context) (string, error) {
	peerInfo, ok := peer.FromContext(ctx)
	if !ok {
		return "", errors.New("missing peer")
	}
	tlsInfo, ok := peerInfo.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.VerifiedChains) == 0 {
		return "", errors.New("peer certificate was not verified")
	}
	certificate := tlsInfo.State.VerifiedChains[0][0]
	if len(certificate.URIs) != 1 || certificate.URIs[0].Scheme != "spiffe" {
		return "", errors.New("client certificate must contain exactly one SPIFFE URI SAN")
	}
	return certificate.URIs[0].String(), nil
}

type parsedMoney struct {
	asset  string
	amount ledger.Amount
}

func requiredMoney(value *paymentv1.Money) (parsedMoney, error) {
	if value == nil || value.GetAssetId() == "" || value.GetAtoms() == "" {
		return parsedMoney{}, status.Error(codes.InvalidArgument, "money asset_id and atoms are required")
	}
	amount, err := ledger.ParseAmount(value.GetAtoms())
	if err != nil || amount.Sign() <= 0 {
		return parsedMoney{}, status.Error(codes.InvalidArgument, "money atoms must be a positive DECIMAL(38,0) integer")
	}
	return parsedMoney{asset: value.GetAssetId(), amount: amount}, nil
}

func optionalMoney(value *paymentv1.Money, requiredAsset string) (ledger.Amount, error) {
	if value == nil {
		return ledger.NewAmountInt64(0), nil
	}
	if value.GetAssetId() != requiredAsset || value.GetAtoms() == "" {
		return ledger.Amount{}, status.Error(codes.InvalidArgument, "component money must use the payment asset")
	}
	amount, err := ledger.ParseAmount(value.GetAtoms())
	if err != nil || amount.Sign() < 0 {
		return ledger.Amount{}, status.Error(codes.InvalidArgument, "component atoms must be a non-negative DECIMAL(38,0) integer")
	}
	return amount, nil
}

func validateKey(key string) error {
	if key == "" || len(key) > maxIdempotencyKeyBytes || strings.TrimSpace(key) != key {
		return status.Error(codes.InvalidArgument, "idempotency_key must be 1..128 non-whitespace-trimmed bytes")
	}
	return nil
}

func paymentMessage(receipt payment.Receipt) *paymentv1.Payment {
	var digest string
	if receipt.Ledger.EntryHash != ([sha256.Size]byte{}) {
		digest = hex.EncodeToString(receipt.Ledger.EntryHash[:])
	}
	return &paymentv1.Payment{
		PaymentId: receipt.PaymentID, State: string(receipt.State),
		TransactionId: receipt.Ledger.TransactionID, DurableReceiptHash: digest,
		AmountAtoms: receipt.Amount.String(), Version: receipt.Version,
		IdempotentReplay: receipt.Duplicate,
	}
}

func mapError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrAmbiguousCommit):
		return status.Error(codes.Unavailable, "commit outcome is unknown; retry the same idempotency key")
	case errors.Is(err, authz.ErrDenied):
		return status.Error(codes.PermissionDenied, "payment account capability denied")
	case errors.Is(err, idempotency.ErrKeyConflict), errors.Is(err, ledger.ErrEffectConflict):
		return status.Error(codes.AlreadyExists, "idempotency/effect key conflicts with a different request")
	case errors.Is(err, idempotency.ErrInProgress):
		return status.Error(codes.Aborted, "the same request is still processing; retry with the same key")
	case errors.Is(err, ledger.ErrInsufficientFunds), errors.Is(err, escrow.ErrInsufficientRights),
		errors.Is(err, payment.ErrOverCapture),
		errors.Is(err, payment.ErrOverRefund), errors.Is(err, payment.ErrCashbackRule):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, payment.ErrPaymentNotFound), errors.Is(err, ledger.ErrAccountNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, payment.ErrInvalidRequest), errors.Is(err, payment.ErrInvalidTransition),
		errors.Is(err, ledger.ErrInvalidPosting), errors.Is(err, ledger.ErrCrossBook),
		errors.Is(err, ledger.ErrAssetMismatch), errors.Is(err, ledger.ErrAmountOverflow):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.DeadlineExceeded, "deadline exceeded; query or retry with the same idempotency key")
	case errors.Is(err, context.Canceled):
		return status.Error(codes.Canceled, "request canceled; query or retry with the same idempotency key")
	default:
		return status.Error(codes.Internal, fmt.Sprintf("financial command failed (%T)", err))
	}
}
