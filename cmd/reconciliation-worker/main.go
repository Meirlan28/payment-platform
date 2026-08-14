package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/example/payment-platform/internal/idgen"
	"github.com/example/payment-platform/internal/observability"
	"github.com/example/payment-platform/internal/reconciliation"
	"github.com/example/payment-platform/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type config struct {
	databaseURL    string
	environment    string
	region         string
	issuer         string
	metricsAddress string
	interval       time.Duration
	runTimeout     time.Duration
	databaseConns  int32
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(logger); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("reconciliation worker stopped", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	poolConfig, err := pgxpool.ParseConfig(cfg.databaseURL)
	if err != nil {
		return fmt.Errorf("parse DATABASE_URL: %w", err)
	}
	if cfg.environment == "production" &&
		(poolConfig.ConnConfig.TLSConfig == nil || poolConfig.ConnConfig.TLSConfig.InsecureSkipVerify) {
		return errors.New("production CockroachDB TLS must verify certificate and hostname")
	}
	poolConfig.MaxConns = cfg.databaseConns
	poolConfig.MinConns = max(2, cfg.databaseConns/4)
	poolConfig.MaxConnLifetime = 30 * time.Minute
	poolConfig.MaxConnLifetimeJitter = 5 * time.Minute
	poolConfig.MaxConnIdleTime = 5 * time.Minute
	poolConfig.HealthCheckPeriod = 15 * time.Second
	poolConfig.ConnConfig.RuntimeParams["application_name"] = "reconciliation/" + cfg.region
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return fmt.Errorf("open CockroachDB pool: %w", err)
	}
	defer pool.Close()
	startup, cancelStartup := context.WithTimeout(ctx, 10*time.Second)
	err = pool.Ping(startup)
	cancelStartup()
	if err != nil {
		return fmt.Errorf("CockroachDB readiness: %w", err)
	}

	ids, err := idgen.New(pool, cfg.issuer, 128)
	if err != nil {
		return err
	}
	checker, err := reconciliation.NewChecker(store.NewRunner(pool))
	if err != nil {
		return err
	}
	registry := prometheus.NewRegistry()
	metrics := observability.NewReconciliationMetrics(registry)
	var ready atomic.Bool
	metricsServer := reconciliationMetricsServer(cfg.metricsAddress, pool, registry, &ready)
	serverErrors := make(chan error, 1)
	go func() {
		if serveErr := metricsServer.ListenAndServe(); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			serverErrors <- serveErr
		}
	}()

	logger.Info("reconciliation worker ready", "region", cfg.region, "interval", cfg.interval)
	for {
		runCtx, cancelRun := context.WithTimeout(ctx, cfg.runTimeout)
		identifier, idErr := ids.Next(runCtx)
		if idErr == nil {
			var report reconciliation.Report
			report, err = checker.Run(runCtx, "reconciliation_"+identifier)
			if err == nil {
				metrics.Observe(report)
				ready.Store(true)
				logger.Info("reconciliation completed", "run_id", report.RunID,
					"status", report.Status, "findings", len(report.Findings), "books", len(report.Watermarks))
			}
		} else {
			err = idErr
		}
		cancelRun()
		if err != nil {
			metrics.CycleErrors.Inc()
			ready.Store(false)
			logger.Error("reconciliation cycle failed", "error", err)
		}

		timer := time.NewTimer(cfg.interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return shutdownMetrics(metricsServer)
		case serveErr := <-serverErrors:
			timer.Stop()
			return fmt.Errorf("metrics server: %w", serveErr)
		case <-timer.C:
		}
	}
}

func loadConfig() (config, error) {
	result := config{
		databaseURL: os.Getenv("DATABASE_URL"), environment: strings.ToLower(os.Getenv("ENVIRONMENT")),
		region: os.Getenv("REGION_ID"), issuer: os.Getenv("ID_ISSUER"),
		metricsAddress: envOr("METRICS_ADDRESS", "127.0.0.1:9090"),
		interval:       30 * time.Second, runTimeout: 5 * time.Minute, databaseConns: 16,
	}
	var err error
	if result.interval, err = durationEnv("RECONCILIATION_INTERVAL", result.interval, time.Second, time.Hour); err != nil {
		return config{}, err
	}
	if result.runTimeout, err = durationEnv("RECONCILIATION_TIMEOUT", result.runTimeout, 10*time.Second, 30*time.Minute); err != nil {
		return config{}, err
	}
	if result.runTimeout <= result.interval {
		return config{}, errors.New("RECONCILIATION_TIMEOUT must exceed RECONCILIATION_INTERVAL")
	}
	if raw := os.Getenv("DB_MAX_CONNECTIONS"); raw != "" {
		value, parseErr := strconv.ParseInt(raw, 10, 32)
		if parseErr != nil || value < 4 || value > 256 {
			return config{}, errors.New("DB_MAX_CONNECTIONS must be between 4 and 256")
		}
		result.databaseConns = int32(value)
	}
	if result.databaseURL == "" || result.region == "" || result.issuer == "" {
		return config{}, errors.New("DATABASE_URL, REGION_ID and ID_ISSUER are required")
	}
	if result.environment != "production" && result.environment != "integration" {
		return config{}, errors.New("ENVIRONMENT must be production or integration")
	}
	if result.environment == "production" && strings.Contains(strings.ToLower(result.databaseURL), "sslmode=disable") {
		return config{}, errors.New("production CockroachDB connection must verify TLS")
	}
	host, _, err := net.SplitHostPort(result.metricsAddress)
	if err != nil {
		return config{}, fmt.Errorf("METRICS_ADDRESS: %w", err)
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return config{}, errors.New("metrics endpoint must bind loopback")
	}
	return result, nil
}

func durationEnv(name string, fallback, minimum, maximum time.Duration) (time.Duration, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback, nil
	}
	value, err := time.ParseDuration(raw)
	if err != nil || value < minimum || value > maximum {
		return 0, fmt.Errorf("%s must be between %s and %s", name, minimum, maximum)
	}
	return value, nil
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func reconciliationMetricsServer(
	address string,
	pool *pgxpool.Pool,
	registry *prometheus.Registry,
	ready *atomic.Bool,
) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/live", func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/ready", func(response http.ResponseWriter, request *http.Request) {
		if !ready.Load() {
			http.Error(response, "no completed reconciliation run", http.StatusServiceUnavailable)
			return
		}
		probe, cancel := context.WithTimeout(request.Context(), 250*time.Millisecond)
		defer cancel()
		if err := pool.Ping(probe); err != nil {
			http.Error(response, "database unavailable", http.StatusServiceUnavailable)
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

func shutdownMetrics(server *http.Server) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return server.Shutdown(ctx)
}
