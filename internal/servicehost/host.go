// Package servicehost is the shared process wiring for the small mTLS gRPC
// control-plane services: account provisioning, funding and ledger queries.
//
// It exists so those binaries state only what makes them different — their
// database role, their registered service and their configuration — while the
// parts that must not vary between them (TLS 1.3 with required client
// certificates, request deadlines, panic isolation, loopback-only metrics,
// readiness tied to the database, and bounded graceful shutdown) are written
// once. It deliberately does not touch cmd/payment-api, whose own wiring is
// the reference this package follows.
package servicehost

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

// Config is the deployment-supplied environment of one control-plane service.
type Config struct {
	DatabaseURL            string
	GRPCAddress            string
	MetricsAddress         string
	RegionID               string
	Issuer                 string
	Environment            string
	TLSCertificate         string
	TLSKey                 string
	TLSClientCA            string
	MaxDatabaseConnections int32
}

// LoadConfig reads the same variable names cmd/payment-api uses, so a
// deployment configures every service in the platform the same way.
// requireIssuer is false for services that allocate no durable identifiers.
func LoadConfig(defaultGRPCAddress string, requireIssuer bool) (Config, error) {
	config := Config{
		DatabaseURL:    os.Getenv("DATABASE_URL"),
		GRPCAddress:    valueOr("GRPC_ADDRESS", defaultGRPCAddress),
		MetricsAddress: valueOr("METRICS_ADDRESS", "127.0.0.1:9090"),
		RegionID:       os.Getenv("REGION_ID"),
		Issuer:         os.Getenv("ID_ISSUER"),
		Environment:    os.Getenv("ENVIRONMENT"),
		TLSCertificate: os.Getenv("TLS_CERT_FILE"),
		TLSKey:         os.Getenv("TLS_KEY_FILE"),
		TLSClientCA:    os.Getenv("TLS_CLIENT_CA_FILE"),

		MaxDatabaseConnections: 16,
	}
	if raw := os.Getenv("DB_MAX_CONNECTIONS"); raw != "" {
		value, err := strconv.ParseInt(raw, 10, 32)
		if err != nil || value < 2 || value > 4096 {
			return Config{}, errors.New("DB_MAX_CONNECTIONS must be between 2 and 4096")
		}
		config.MaxDatabaseConnections = int32(value)
	}
	if config.DatabaseURL == "" || config.RegionID == "" ||
		config.TLSCertificate == "" || config.TLSKey == "" || config.TLSClientCA == "" {
		return Config{}, errors.New("DATABASE_URL, REGION_ID and all TLS file variables are required")
	}
	if requireIssuer && config.Issuer == "" {
		return Config{}, errors.New("ID_ISSUER is required")
	}
	if !strings.EqualFold(config.Environment, "production") &&
		!strings.EqualFold(config.Environment, "integration") {
		return Config{}, errors.New("ENVIRONMENT must be production or integration")
	}
	if strings.EqualFold(config.Environment, "production") &&
		strings.Contains(config.DatabaseURL, "sslmode=disable") {
		return Config{}, errors.New("production CockroachDB connection must verify TLS")
	}
	host, _, err := net.SplitHostPort(config.MetricsAddress)
	if err != nil {
		return Config{}, fmt.Errorf("METRICS_ADDRESS: %w", err)
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return Config{}, errors.New("metrics endpoint must bind loopback; scrape through the colocated collector")
	}
	return config, nil
}

// OpenPool applies the same production TLS requirement and pool shape as the
// payment API. applicationName identifies the workload in database telemetry.
func OpenPool(ctx context.Context, config Config, applicationName string) (*pgxpool.Pool, error) {
	poolConfig, err := pgxpool.ParseConfig(config.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse DATABASE_URL: %w", err)
	}
	if strings.EqualFold(config.Environment, "production") &&
		(poolConfig.ConnConfig.TLSConfig == nil || poolConfig.ConnConfig.TLSConfig.InsecureSkipVerify) {
		return nil, errors.New("production CockroachDB TLS must verify the server certificate and hostname")
	}
	poolConfig.MaxConns = config.MaxDatabaseConnections
	poolConfig.MinConns = max(1, config.MaxDatabaseConnections/10)
	poolConfig.MaxConnLifetime = 30 * time.Minute
	poolConfig.MaxConnLifetimeJitter = 5 * time.Minute
	poolConfig.MaxConnIdleTime = 5 * time.Minute
	poolConfig.HealthCheckPeriod = 15 * time.Second
	poolConfig.ConnConfig.RuntimeParams["application_name"] = applicationName + "/" + config.RegionID

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("open CockroachDB pool: %w", err)
	}
	probeContext, cancelProbe := context.WithTimeout(ctx, 5*time.Second)
	defer cancelProbe()
	if err := pool.Ping(probeContext); err != nil {
		pool.Close()
		return nil, fmt.Errorf("CockroachDB readiness: %w", err)
	}
	return pool, nil
}

// Options describes one service to Serve.
type Options struct {
	Config Config
	Pool   *pgxpool.Pool
	Logger *slog.Logger
	// ServiceName appears in logs and in the database application name.
	ServiceName string
	// Register attaches the service implementation to the gRPC server.
	Register func(*grpc.Server)
	// RequestDeadline bounds any call that arrives without one.
	RequestDeadline time.Duration
	// Registry is exposed on the loopback metrics endpoint.
	Registry *prometheus.Registry
}

// Serve runs the gRPC and metrics servers until the process is signalled, then
// stops accepting work and drains in flight calls within a bounded window.
func Serve(ctx context.Context, options Options) error {
	if options.Pool == nil || options.Logger == nil || options.Register == nil || options.ServiceName == "" {
		return errors.New("servicehost: incomplete options")
	}
	deadline := options.RequestDeadline
	if deadline <= 0 {
		deadline = 5 * time.Second
	}
	registry := options.Registry
	if registry == nil {
		registry = prometheus.NewRegistry()
	}

	rootContext, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	tlsConfig, err := ServerTLS(options.Config)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", options.Config.GRPCAddress)
	if err != nil {
		return fmt.Errorf("listen gRPC: %w", err)
	}
	defer listener.Close()

	server := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsConfig)),
		grpc.MaxRecvMsgSize(1<<20),
		grpc.MaxSendMsgSize(1<<20),
		grpc.MaxConcurrentStreams(256),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime: 20 * time.Second, PermitWithoutStream: false,
		}),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle: 5 * time.Minute, MaxConnectionAge: 30 * time.Minute,
			MaxConnectionAgeGrace: 2 * time.Minute, Time: 2 * time.Hour, Timeout: 20 * time.Second,
		}),
		grpc.ChainUnaryInterceptor(
			defaultDeadline(deadline),
			recoverPanics(options.Logger),
		),
	)
	options.Register(server)
	healthServer := health.NewServer()
	healthv1.RegisterHealthServer(server, healthServer)
	healthServer.SetServingStatus("", healthv1.HealthCheckResponse_SERVING)

	metricsServer := newMetricsServer(options.Config.MetricsAddress, options.Pool, registry)
	failures := make(chan error, 2)
	go func() {
		options.Logger.Info("gRPC server ready",
			"service", options.ServiceName,
			"address", options.Config.GRPCAddress,
			"region", options.Config.RegionID)
		if err := server.Serve(listener); err != nil {
			failures <- fmt.Errorf("gRPC serve: %w", err)
		}
	}()
	go func() {
		options.Logger.Info("local metrics server ready", "address", options.Config.MetricsAddress)
		if err := metricsServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			failures <- fmt.Errorf("metrics serve: %w", err)
		}
	}()

	select {
	case <-rootContext.Done():
		options.Logger.Info("shutdown requested", "service", options.ServiceName)
	case err := <-failures:
		stop()
		return err
	}
	// Readiness flips before the drain so a load balancer stops sending new
	// work while in-flight calls are still allowed to finish.
	healthServer.SetServingStatus("", healthv1.HealthCheckResponse_NOT_SERVING)

	shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelShutdown()
	stopped := make(chan struct{})
	go func() {
		server.GracefulStop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-shutdownContext.Done():
		server.Stop()
	}
	if err := metricsServer.Shutdown(shutdownContext); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

// ServerTLS requires TLS 1.3 and a client certificate. There is deliberately
// no plaintext or one-way-TLS fallback: these services grant capabilities and
// create value, so an unauthenticated caller must not be representable.
func ServerTLS(config Config) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(config.TLSCertificate, config.TLSKey)
	if err != nil {
		return nil, fmt.Errorf("load server certificate: %w", err)
	}
	caPEM, err := os.ReadFile(config.TLSClientCA)
	if err != nil {
		return nil, fmt.Errorf("read client CA: %w", err)
	}
	clientCA := x509.NewCertPool()
	if !clientCA.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("client CA file contains no certificates")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		ClientCAs:    clientCA,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		NextProtos:   []string{"h2"},
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
	return func(ctx context.Context, request any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
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
