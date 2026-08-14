package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	paymentv1 "github.com/example/payment-platform/gen/go/payment/v1"
	grpcapi "github.com/example/payment-platform/internal/api"
	"github.com/example/payment-platform/internal/authz"
	"github.com/example/payment-platform/internal/idempotency"
	"github.com/example/payment-platform/internal/idgen"
	"github.com/example/payment-platform/internal/ledger"
	"github.com/example/payment-platform/internal/payment"
	"github.com/example/payment-platform/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
)

type config struct {
	databaseURL            string
	grpcAddress            string
	metricsAddress         string
	regionID               string
	issuer                 string
	environment            string
	tlsCertificate         string
	tlsKey                 string
	tlsClientCA            string
	maxDatabaseConnections int32
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(logger); err != nil {
		logger.Error("payment API stopped", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	configuration, err := loadConfig()
	if err != nil {
		return err
	}
	rootContext, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	poolConfig, err := pgxpool.ParseConfig(configuration.databaseURL)
	if err != nil {
		return fmt.Errorf("parse DATABASE_URL: %w", err)
	}
	if strings.EqualFold(configuration.environment, "production") &&
		(poolConfig.ConnConfig.TLSConfig == nil || poolConfig.ConnConfig.TLSConfig.InsecureSkipVerify) {
		return errors.New("production CockroachDB TLS must verify the server certificate and hostname")
	}
	poolConfig.MaxConns = configuration.maxDatabaseConnections
	poolConfig.MinConns = max(2, configuration.maxDatabaseConnections/10)
	poolConfig.MaxConnLifetime = 30 * time.Minute
	poolConfig.MaxConnLifetimeJitter = 5 * time.Minute
	poolConfig.MaxConnIdleTime = 5 * time.Minute
	poolConfig.HealthCheckPeriod = 15 * time.Second
	poolConfig.ConnConfig.RuntimeParams["application_name"] = "payment-api/" + configuration.regionID
	pool, err := pgxpool.NewWithConfig(rootContext, poolConfig)
	if err != nil {
		return fmt.Errorf("open CockroachDB pool: %w", err)
	}
	defer pool.Close()
	probeContext, cancelProbe := context.WithTimeout(rootContext, 5*time.Second)
	err = pool.Ping(probeContext)
	cancelProbe()
	if err != nil {
		return fmt.Errorf("CockroachDB readiness: %w", err)
	}

	generator, err := idgen.New(pool, configuration.issuer, 4096)
	if err != nil {
		return err
	}
	transactions := store.NewRunner(pool)
	journal := ledger.NewService(transactions, generator)
	idem := idempotency.NewService(generator)
	payments := payment.NewService(transactions, journal, idem, generator)
	authorizer, err := authz.New(pool)
	if err != nil {
		return err
	}

	tlsConfig, err := serverTLS(configuration)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", configuration.grpcAddress)
	if err != nil {
		return fmt.Errorf("listen gRPC: %w", err)
	}
	defer listener.Close()

	grpcServer := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsConfig)),
		grpc.MaxRecvMsgSize(1<<20),
		grpc.MaxSendMsgSize(1<<20),
		grpc.MaxConcurrentStreams(1024),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 20 * time.Second, PermitWithoutStream: false}),
		grpc.KeepaliveParams(keepalive.ServerParameters{MaxConnectionIdle: 5 * time.Minute, MaxConnectionAge: 30 * time.Minute, MaxConnectionAgeGrace: 2 * time.Minute, Time: 2 * time.Hour, Timeout: 20 * time.Second}),
		grpc.ChainUnaryInterceptor(defaultDeadline(2*time.Second), recoverPanics(logger)),
	)
	paymentv1.RegisterPaymentServiceServer(grpcServer, &grpcapi.PaymentServer{
		Payments: payments, RegionID: configuration.regionID,
		ResolvePrincipal:  grpcapi.SPIFFEPrincipal,
		AuthorizeAccounts: authorizer,
	})
	healthServer := health.NewServer()
	healthv1.RegisterHealthServer(grpcServer, healthServer)
	healthServer.SetServingStatus("", healthv1.HealthCheckResponse_SERVING)

	registry := prometheus.NewRegistry()
	metricsServer := newMetricsServer(configuration.metricsAddress, pool, registry)
	errorsChannel := make(chan error, 2)
	go func() {
		logger.Info("gRPC server ready", "address", configuration.grpcAddress, "region", configuration.regionID)
		if serveErr := grpcServer.Serve(listener); serveErr != nil {
			errorsChannel <- fmt.Errorf("gRPC serve: %w", serveErr)
		}
	}()
	go func() {
		logger.Info("local metrics server ready", "address", configuration.metricsAddress)
		if serveErr := metricsServer.ListenAndServe(); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errorsChannel <- fmt.Errorf("metrics serve: %w", serveErr)
		}
	}()

	select {
	case <-rootContext.Done():
		logger.Info("shutdown requested")
	case serveErr := <-errorsChannel:
		stop()
		return serveErr
	}
	healthServer.SetServingStatus("", healthv1.HealthCheckResponse_NOT_SERVING)

	shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelShutdown()
	grpcStopped := make(chan struct{})
	go func() {
		grpcServer.GracefulStop()
		close(grpcStopped)
	}()
	select {
	case <-grpcStopped:
	case <-shutdownContext.Done():
		grpcServer.Stop()
	}
	if err := metricsServer.Shutdown(shutdownContext); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

func loadConfig() (config, error) {
	result := config{
		databaseURL: os.Getenv("DATABASE_URL"), grpcAddress: valueOr("GRPC_ADDRESS", ":8443"),
		metricsAddress: valueOr("METRICS_ADDRESS", "127.0.0.1:9090"),
		regionID:       os.Getenv("REGION_ID"), issuer: os.Getenv("ID_ISSUER"),
		environment:    os.Getenv("ENVIRONMENT"),
		tlsCertificate: os.Getenv("TLS_CERT_FILE"), tlsKey: os.Getenv("TLS_KEY_FILE"),
		tlsClientCA: os.Getenv("TLS_CLIENT_CA_FILE"), maxDatabaseConnections: 64,
	}
	if raw := os.Getenv("DB_MAX_CONNECTIONS"); raw != "" {
		value, err := strconv.ParseInt(raw, 10, 32)
		if err != nil || value < 4 || value > 4096 {
			return config{}, errors.New("DB_MAX_CONNECTIONS must be between 4 and 4096")
		}
		result.maxDatabaseConnections = int32(value)
	}
	if result.databaseURL == "" || result.regionID == "" || result.issuer == "" ||
		result.tlsCertificate == "" || result.tlsKey == "" || result.tlsClientCA == "" {
		return config{}, errors.New("DATABASE_URL, REGION_ID, ID_ISSUER and all TLS file variables are required")
	}
	if !strings.EqualFold(result.environment, "production") && !strings.EqualFold(result.environment, "integration") {
		return config{}, errors.New("ENVIRONMENT must be production or integration")
	}
	if strings.EqualFold(result.environment, "production") && strings.Contains(result.databaseURL, "sslmode=disable") {
		return config{}, errors.New("production CockroachDB connection must verify TLS")
	}
	host, _, err := net.SplitHostPort(result.metricsAddress)
	if err != nil {
		return config{}, fmt.Errorf("METRICS_ADDRESS: %w", err)
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return config{}, errors.New("metrics endpoint must bind loopback; scrape through the colocated collector")
	}
	return result, nil
}

func serverTLS(configuration config) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(configuration.tlsCertificate, configuration.tlsKey)
	if err != nil {
		return nil, fmt.Errorf("load server certificate: %w", err)
	}
	caPEM, err := os.ReadFile(configuration.tlsClientCA)
	if err != nil {
		return nil, fmt.Errorf("read client CA: %w", err)
	}
	clientCA := x509.NewCertPool()
	if !clientCA.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("client CA file contains no certificates")
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate},
		ClientCAs: clientCA, ClientAuth: tls.RequireAndVerifyClientCert,
		NextProtos: []string{"h2"},
	}, nil
}

func newMetricsServer(address string, pool *pgxpool.Pool, registry *prometheus.Registry) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/live", func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/ready", func(response http.ResponseWriter, request *http.Request) {
		ctx, cancel := context.WithTimeout(request.Context(), 250*time.Millisecond)
		defer cancel()
		if err := pool.Ping(ctx); err != nil {
			http.Error(response, "not ready", http.StatusServiceUnavailable)
			return
		}
		response.WriteHeader(http.StatusNoContent)
	})
	return &http.Server{
		Addr: address, Handler: mux, ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10,
	}
}

func defaultDeadline(maximum time.Duration) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, request any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if _, exists := ctx.Deadline(); !exists {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, maximum)
			defer cancel()
		}
		return handler(ctx, request)
	}
}

func recoverPanics(logger *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, request any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (response any, err error) {
		defer func() {
			if recovered := recover(); recovered != nil {
				logger.Error("gRPC handler panic", "method", info.FullMethod)
				response, err = nil, status.Error(codes.Internal, "internal server error")
			}
		}()
		return handler(ctx, request)
	}
}

func valueOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
