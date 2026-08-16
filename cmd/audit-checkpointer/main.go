package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/example/payment-platform/internal/auditexport"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type config struct {
	databaseURL                                                                     string
	metricsAddr                                                                     string
	interval                                                                        time.Duration
	cycleTimeout                                                                    time.Duration
	dbMaxConnections                                                                int32
	worker                                                                          auditexport.WorkerConfig
	vaultURL, vaultTokenFile, vaultNamespace, vaultMount, vaultKey, vaultManagedKey string
	vaultCA, vaultCert, vaultKeyFile                                                string
	sinks                                                                           [2]auditexport.S3Config
	sinkCA                                                                          [2]string
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	configuration, err := loadConfig()
	if err != nil {
		logger.Error("invalid audit-checkpointer configuration", "error", err)
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	dbConfig, err := pgxpool.ParseConfig(configuration.databaseURL)
	if err != nil {
		logger.Error("parse database configuration", "error", err)
		os.Exit(2)
	}
	dbConfig.MaxConns = configuration.dbMaxConnections
	dbConfig.MinConns = min(int32(4), configuration.dbMaxConnections)
	dbConfig.MaxConnLifetime = 30 * time.Minute
	dbConfig.MaxConnIdleTime = 5 * time.Minute
	db, err := pgxpool.NewWithConfig(ctx, dbConfig)
	if err != nil {
		logger.Error("open database pool", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	vaultHTTP, err := hardenedHTTPClient(configuration.vaultCA, configuration.vaultCert, configuration.vaultKeyFile)
	if err != nil {
		logger.Error("build Vault TLS client", "error", err)
		os.Exit(2)
	}
	vault, err := auditexport.NewVaultTransitSigner(
		configuration.vaultURL, configuration.vaultTokenFile,
		configuration.vaultNamespace, configuration.vaultMount,
		configuration.vaultKey, configuration.vaultManagedKey, vaultHTTP,
	)
	if err != nil {
		logger.Error("configure Vault Transit", "error", err)
		os.Exit(2)
	}

	registry := prometheus.NewRegistry()
	metrics := auditexport.NewMetrics(registry)
	signer := auditexport.ObservedSigner{Inner: vault, Metrics: metrics}
	sinks := make([]auditexport.Sink, 0, 2)
	for index := range configuration.sinks {
		sinkHTTP, clientErr := hardenedHTTPClient(configuration.sinkCA[index], "", "")
		if clientErr != nil {
			logger.Error("build WORM sink TLS client", "sink", configuration.sinks[index].ID, "error", clientErr)
			os.Exit(2)
		}
		configuration.sinks[index].HTTPClient = sinkHTTP
		sink, clientErr := auditexport.NewS3Sink(ctx, configuration.sinks[index])
		if clientErr != nil {
			logger.Error("configure WORM sink", "sink", configuration.sinks[index].ID, "error", clientErr)
			os.Exit(2)
		}
		sinks = append(sinks, sink)
	}
	repository := auditexport.Repository{DB: db}
	exporter, err := auditexport.NewExporter(repository, sinks, metrics)
	if err != nil {
		logger.Error("configure exact two-sink exporter", "error", err)
		os.Exit(2)
	}
	worker, err := auditexport.NewWorker(repository, signer, exporter, metrics, configuration.worker)
	if err != nil {
		logger.Error("configure audit worker", "error", err)
		os.Exit(2)
	}

	server := &http.Server{
		Addr: configuration.metricsAddr, ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10,
		Handler: healthMux(worker, registry),
	}
	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("audit-checkpointer health server started", "address", configuration.metricsAddr)
		if serveErr := server.ListenAndServe(); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			serverErrors <- serveErr
		}
	}()

	runCycle := func() {
		cycleCtx, cycleCancel := context.WithTimeout(ctx, configuration.cycleTimeout)
		defer cycleCancel()
		if cycleErr := worker.RunCycle(cycleCtx); cycleErr != nil {
			logger.Error("audit checkpoint/export cycle failed", "error", cycleErr)
			return
		}
		logger.Info("audit checkpoint/export cycle completed")
	}
	runCycle()
	ticker := time.NewTicker(configuration.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer shutdownCancel()
			_ = server.Shutdown(shutdownCtx)
			return
		case err := <-serverErrors:
			logger.Error("audit-checkpointer health server failed", "error", err)
			os.Exit(1)
		case <-ticker.C:
			runCycle()
		}
	}
}

func healthMux(worker *auditexport.Worker, gatherer prometheus.Gatherer) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(gatherer, promhttp.HandlerOpts{}))
	mux.HandleFunc("/live", func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(response, "live\n")
	})
	mux.HandleFunc("/ready", func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if !worker.Ready() {
			response.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(response, "not ready\n")
			return
		}
		_, _ = io.WriteString(response, "ready\n")
	})
	return mux
}

func loadConfig() (config, error) {
	if os.Getenv("ENVIRONMENT") != "production" {
		return config{}, errors.New("ENVIRONMENT=production is mandatory; no local signer/object-store fallback exists")
	}
	result := config{
		databaseURL:     os.Getenv("DATABASE_URL"),
		metricsAddr:     envDefault("METRICS_ADDRESS", "127.0.0.1:9090"),
		vaultURL:        os.Getenv("VAULT_ADDR"),
		vaultTokenFile:  os.Getenv("VAULT_TOKEN_FILE"),
		vaultNamespace:  os.Getenv("VAULT_NAMESPACE"),
		vaultMount:      envDefault("VAULT_TRANSIT_MOUNT", "transit"),
		vaultKey:        envDefault("VAULT_TRANSIT_KEY", "audit-checkpoint"),
		vaultManagedKey: envDefault("VAULT_HSM_MANAGED_KEY", "audit-checkpoint-hsm"),
		vaultCA:         os.Getenv("VAULT_CA_FILE"),
		vaultCert:       os.Getenv("VAULT_CLIENT_CERT_FILE"),
		vaultKeyFile:    os.Getenv("VAULT_CLIENT_KEY_FILE"),
	}
	if result.databaseURL == "" || result.vaultURL == "" || result.vaultTokenFile == "" ||
		result.vaultCA == "" || result.vaultCert == "" || result.vaultKeyFile == "" {
		return config{}, errors.New("database URL and Vault endpoint/token-file/mTLS files are required")
	}
	var err error
	if result.interval, err = durationEnv("AUDIT_INTERVAL", time.Second); err != nil {
		return config{}, err
	}
	if result.cycleTimeout, err = durationEnv("AUDIT_CYCLE_TIMEOUT", 55*time.Second); err != nil {
		return config{}, err
	}
	dbConnections, err := uintEnv("DB_MAX_CONNECTIONS", 64, 4, 1024)
	if err != nil {
		return config{}, err
	}
	result.dbMaxConnections = int32(dbConnections)
	maxRange, err := uintEnv("AUDIT_MAX_RANGE_ENTRIES", 100000, 1, 100000)
	if err != nil {
		return config{}, err
	}
	readyBacklog, err := uintEnv("AUDIT_READY_MAX_BACKLOG_ENTRIES", 100000, 0, 1000000000)
	if err != nil {
		return config{}, err
	}
	pending, err := uintEnv("AUDIT_MAX_PENDING_PER_BOOK", 32, 1, 1024)
	if err != nil {
		return config{}, err
	}
	concurrency, err := uintEnv("AUDIT_CONCURRENCY", 32, 1, 256)
	if err != nil {
		return config{}, err
	}
	shardCount, err := uintEnv("AUDIT_SHARD_COUNT", 16, 1, 4096)
	if err != nil {
		return config{}, err
	}
	shardIndex, err := uintEnv("AUDIT_SHARD_INDEX", 0, 0, shardCount-1)
	if err != nil {
		return config{}, err
	}
	result.worker = auditexport.WorkerConfig{
		SigningKeyID: result.vaultKey, MaxRangeEntries: int64(maxRange),
		MaxReadyBacklog: int64(readyBacklog), MaxPendingPerBook: int(pending),
		Concurrency: int(concurrency), ShardCount: shardCount, ShardIndex: shardIndex,
	}
	for index, prefix := range []string{"AUDIT_SINK_A_", "AUDIT_SINK_B_"} {
		pathStyle, parseErr := strconv.ParseBool(envDefault(prefix+"PATH_STYLE", "false"))
		if parseErr != nil {
			return config{}, fmt.Errorf("%sPATH_STYLE: %w", prefix, parseErr)
		}
		result.sinks[index] = auditexport.S3Config{
			ID: os.Getenv(prefix + "ID"), Endpoint: os.Getenv(prefix + "ENDPOINT"),
			Bucket: os.Getenv(prefix + "BUCKET"), Region: os.Getenv(prefix + "REGION"),
			RoleARN:              os.Getenv(prefix + "ROLE_ARN"),
			WebIdentityTokenFile: os.Getenv(prefix + "WEB_IDENTITY_TOKEN_FILE"),
			STSEndpoint:          os.Getenv(prefix + "STS_ENDPOINT"),
			ExpectedAccountID:    os.Getenv(prefix + "EXPECTED_ACCOUNT_ID"),
			UsePathStyle:         pathStyle,
		}
		result.sinkCA[index] = os.Getenv(prefix + "CA_FILE")
	}
	return result, nil
}

func hardenedHTTPClient(caFile, certFile, keyFile string) (*http.Client, error) {
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if caFile != "" {
		raw, readErr := os.ReadFile(caFile)
		if readErr != nil {
			return nil, readErr
		}
		if !roots.AppendCertsFromPEM(raw) {
			return nil, errors.New("TLS CA file contains no certificate")
		}
	}
	var certificates []tls.Certificate
	if certFile != "" || keyFile != "" {
		if certFile == "" || keyFile == "" {
			return nil, errors.New("both TLS client certificate and key are required")
		}
		certificate, loadErr := tls.LoadX509KeyPair(certFile, keyFile)
		if loadErr != nil {
			return nil, loadErr
		}
		certificates = []tls.Certificate{certificate}
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: certificates,
		},
		MaxIdleConns: 128, MaxIdleConnsPerHost: 32, IdleConnTimeout: 90 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: time.Second, ForceAttemptHTTP2: true,
	}
	return &http.Client{Transport: transport, Timeout: 20 * time.Second}, nil
}

func envDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func durationEnv(name string, fallback time.Duration) (time.Duration, error) {
	raw := envDefault(name, fallback.String())
	value, err := time.ParseDuration(raw)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration", name)
	}
	return value, nil
}

func uintEnv(name string, fallback, minimum, maximum uint64) (uint64, error) {
	raw := envDefault(name, strconv.FormatUint(fallback, 10))
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || value < minimum || value > maximum {
		return 0, fmt.Errorf("%s must be in [%d,%d]", name, minimum, maximum)
	}
	return value, nil
}
