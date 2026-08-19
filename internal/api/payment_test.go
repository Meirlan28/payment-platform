package api

import (
	"context"
	"testing"

	paymentv1 "github.com/example/payment-platform/gen/go/payment/v1"
	"github.com/example/payment-platform/internal/authz"
	"github.com/example/payment-platform/internal/ledger"
	"github.com/example/payment-platform/internal/payment"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fakeAuthorizer struct {
	request authz.Request
	err     error
}

func (f *fakeAuthorizer) Authorize(_ context.Context, request authz.Request) error {
	f.request = request
	return f.err
}

type fakePayments struct {
	authorized payment.HoldRequest
	receipt    payment.Receipt
	err        error
}

func (f *fakePayments) Authorize(_ context.Context, request payment.HoldRequest) (payment.Receipt, error) {
	f.authorized = request
	return f.receipt, f.err
}
func (f *fakePayments) Capture(context.Context, payment.CaptureRequest) (payment.Receipt, error) {
	return f.receipt, f.err
}
func (f *fakePayments) Release(context.Context, payment.ReleaseRequest) (payment.Receipt, error) {
	return f.receipt, f.err
}
func (f *fakePayments) Reversal(context.Context, payment.ReleaseRequest) (payment.Receipt, error) {
	return f.receipt, f.err
}
func (f *fakePayments) Refund(context.Context, payment.RefundRequest) (payment.Receipt, error) {
	return f.receipt, f.err
}
func (f *fakePayments) Chargeback(context.Context, payment.ChargebackRequest) (payment.Receipt, error) {
	return f.receipt, f.err
}
func (f *fakePayments) GetForScope(context.Context, string, string) (payment.Receipt, error) {
	return f.receipt, f.err
}
func (f *fakePayments) GetDetailsForScope(context.Context, string, string) (payment.Details, error) {
	return payment.Details{Receipt: f.receipt}, f.err
}

type fakeErrorObserver struct {
	operation string
	err       error
}

func (f *fakeErrorObserver) ObservePaymentError(operation string, err error) {
	f.operation, f.err = operation, err
}

func TestAuthorizeScopesIdempotencyToVerifiedPrincipalAndRegion(t *testing.T) {
	journalHash := [32]byte{1, 2, 3}
	fake := &fakePayments{receipt: payment.Receipt{
		PaymentID: "payment-1", State: payment.Held, Amount: ledger.MustAmount("100"),
		Ledger: ledger.Receipt{TransactionID: "transaction-1", EntryHash: journalHash},
	}}
	server := &PaymentServer{
		Payments: fake, RegionID: "asia-kz-1",
		ResolvePrincipal:  func(context.Context) (string, error) { return "spiffe://payments.test/merchant/7", nil },
		AuthorizeAccounts: &fakeAuthorizer{},
	}
	response, err := server.Authorize(context.Background(), &paymentv1.AuthorizeRequest{
		IdempotencyKey: "merchant-order-9", PayerAccountId: "customer-available",
		PayerHeldAccountId: "customer-held", MerchantAccountId: "merchant-payable",
		BookId: "book-kz", AuthorityRegion: "asia-kz-1", PostingRuleVersion: "wallet-hold-v1",
		Amount:              &paymentv1.Money{AssetId: "KZT", Atoms: "100"},
		CashbackRuleMaximum: &paymentv1.Money{AssetId: "KZT", Atoms: "0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if fake.authorized.Scope != "principal/spiffe://payments.test/merchant/7" ||
		fake.authorized.AuthorityRegion != "asia-kz-1" {
		t.Fatalf("incorrect trusted scope/region: %#v", fake.authorized)
	}
	if response.GetPayment().GetDurableReceiptHash() == "" {
		t.Fatal("successful financial response must carry a durable receipt hash")
	}
}

func TestAuthorizeRejectsCrossRegionAuthority(t *testing.T) {
	server := &PaymentServer{
		Payments: &fakePayments{}, RegionID: "region-a",
		ResolvePrincipal:  func(context.Context) (string, error) { return "spiffe://test/client", nil },
		AuthorizeAccounts: &fakeAuthorizer{},
	}
	_, err := server.Authorize(context.Background(), &paymentv1.AuthorizeRequest{
		IdempotencyKey: "key", AuthorityRegion: "region-b",
		Amount: &paymentv1.Money{AssetId: "USD", Atoms: "1"},
	})
	if err == nil {
		t.Fatal("cross-region authority use must be rejected")
	}
}

func TestAuthorizeFailsClosedForUnauthorizedAccount(t *testing.T) {
	fake := &fakePayments{}
	policy := &fakeAuthorizer{err: authz.ErrDenied}
	server := &PaymentServer{
		Payments: fake, RegionID: "region-a", AuthorizeAccounts: policy,
		ResolvePrincipal: func(context.Context) (string, error) { return "spiffe://test/client", nil },
	}
	_, err := server.Authorize(context.Background(), &paymentv1.AuthorizeRequest{
		IdempotencyKey: "key", BookId: "book", AuthorityRegion: "region-a",
		PayerAccountId: "victim", PayerHeldAccountId: "victim-held", MerchantAccountId: "merchant",
		Amount: &paymentv1.Money{AssetId: "USD", Atoms: "1"},
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected permission denied, got %v", err)
	}
	if fake.authorized.BookID != "" {
		t.Fatal("financial command ran after authorization denial")
	}
}

func TestFinancialCommandFailureIsObservedBeforeGRPCMapping(t *testing.T) {
	fake := &fakePayments{err: payment.ErrOverRefund}
	observer := &fakeErrorObserver{}
	server := &PaymentServer{
		Payments: fake, RegionID: "region-a", AuthorizeAccounts: &fakeAuthorizer{}, ErrorObserver: observer,
		ResolvePrincipal: func(context.Context) (string, error) { return "spiffe://test/client", nil },
	}
	_, err := server.Refund(context.Background(), &paymentv1.RefundRequest{
		IdempotencyKey: "refund-key", BookId: "book", PaymentId: "payment",
		OriginalCaptureTransactionId: "capture", MerchantDebitAccountId: "merchant",
		Amount: &paymentv1.Money{AssetId: "USD", Atoms: "1"},
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("unexpected gRPC error: %v", err)
	}
	if observer.operation != "refund" || observer.err != payment.ErrOverRefund {
		t.Fatalf("observer did not receive the typed domain failure: %#v", observer)
	}
}
