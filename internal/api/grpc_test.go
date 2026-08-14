package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	paymentv1 "github.com/example/payment-platform/gen/go/payment/v1"
	"github.com/example/payment-platform/internal/ledger"
	"github.com/example/payment-platform/internal/payment"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/test/bufconn"
)

func TestGRPCRequiresVerifiedSPIFFEClientAndReturnsDurableReceipt(t *testing.T) {
	serverCertificate, clientCertificate, roots := testPKI(t)
	listener := bufconn.Listen(1 << 20)
	fake := &fakePayments{receipt: payment.Receipt{
		PaymentID: "payment-mtls", State: payment.Held, Amount: ledger.NewAmountInt64(9),
		Ledger: ledger.Receipt{TransactionID: "transaction-mtls", EntryHash: [32]byte{9}},
	}}
	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCertificate},
		ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert, NextProtos: []string{"h2"},
	})))
	paymentv1.RegisterPaymentServiceServer(grpcServer, &PaymentServer{
		Payments: fake, RegionID: "region-a", ResolvePrincipal: SPIFFEPrincipal,
		AuthorizeAccounts: &fakeAuthorizer{},
	})
	serveError := make(chan error, 1)
	go func() { serveError <- grpcServer.Serve(listener) }()
	defer func() {
		grpcServer.Stop()
		_ = listener.Close()
		<-serveError
	}()

	clientConnection, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			MinVersion: tls.VersionTLS13, RootCAs: roots,
			Certificates: []tls.Certificate{clientCertificate}, ServerName: "bufnet",
		})),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer clientConnection.Close()
	response, err := paymentv1.NewPaymentServiceClient(clientConnection).Authorize(context.Background(), &paymentv1.AuthorizeRequest{
		IdempotencyKey: "mtls-key", BookId: "book", PayerAccountId: "available",
		PayerHeldAccountId: "held", MerchantAccountId: "merchant",
		AuthorityRegion: "region-a", PostingRuleVersion: "hold-v1",
		Amount: &paymentv1.Money{AssetId: "USD", Atoms: "9"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if fake.authorized.Scope != "principal/spiffe://payments.test/tenant/acme" {
		t.Fatalf("untrusted or missing SPIFFE scope: %q", fake.authorized.Scope)
	}
	if response.GetPayment().GetTransactionId() != "transaction-mtls" ||
		response.GetPayment().GetDurableReceiptHash() == "" {
		t.Fatalf("missing durable receipt: %#v", response.GetPayment())
	}
}

func testPKI(t *testing.T) (tls.Certificate, tls.Certificate, *x509.CertPool) {
	t.Helper()
	now := time.Now()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	makeLeaf := func(serial int64, server bool) tls.Certificate {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "workload"},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature,
		}
		if server {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			template.DNSNames = []string{"bufnet"}
		} else {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			template.URIs = []*url.URL{{Scheme: "spiffe", Host: "payments.test", Path: "/tenant/acme"}}
		}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, public, caPrivate)
		if err != nil {
			t.Fatal(err)
		}
		certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		privatePKCS8, err := x509.MarshalPKCS8PrivateKey(private)
		if err != nil {
			t.Fatal(err)
		}
		privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privatePKCS8})
		certificate, err := tls.X509KeyPair(certificatePEM, privatePEM)
		if err != nil {
			t.Fatal(err)
		}
		return certificate
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return makeLeaf(2, true), makeLeaf(3, false), roots
}
