package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/kilo666mj/rilldns/internal/querytelemetry"
)

func main() {
	dnstapListen := flag.String("dnstap-listen", "127.0.0.1:6000", "TCP address receiving bidirectional dnstap frames")
	metricsListen := flag.String("metrics-listen", "127.0.0.1:19154", "HTTP metrics listen address")
	blocklist := flag.String("blocklist", "/var/lib/rilldns/blocking/merged.hosts", "compiled hosts blocklist")
	analyticsMode := flag.String("analytics-mode", querytelemetry.ModeAggregate, "query analytics mode: aggregate, statistics, or detailed")
	analyticsRetention := flag.Duration("analytics-retention", 7*24*time.Hour, "retention for query analytics buckets")
	analyticsState := flag.String("analytics-state", "/var/lib/rilldns/query-analytics.json", "persistent query analytics state file")
	analyticsMaxDomains := flag.Int("analytics-max-domains", 512, "maximum tracked domain counters per five-minute bucket")
	analyticsMaxClients := flag.Int("analytics-max-clients", 128, "maximum tracked client counters per five-minute bucket")
	analyticsRecentQueries := flag.Int("analytics-recent-queries", 1000, "maximum recent queries retained in detailed mode")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	analytics, err := querytelemetry.NewAnalytics(querytelemetry.AnalyticsConfig{
		Mode: *analyticsMode, Retention: *analyticsRetention, MaxDomains: *analyticsMaxDomains,
		MaxClients: *analyticsMaxClients, RecentQueries: *analyticsRecentQueries,
	})
	if err != nil {
		logger.Error("configure query analytics", "error", err)
		os.Exit(1)
	}
	if analytics.Enabled() {
		if err := analytics.Load(*analyticsState); err != nil && !errors.Is(err, os.ErrNotExist) {
			logger.Error("load query analytics", "error", err)
			os.Exit(1)
		}
	}
	collector := querytelemetry.NewWithAnalytics(logger, analytics)
	// Bind first so CoreDNS can connect during boot while the initial blocklist
	// is being parsed. The accept loop starts only after the list is ready.
	listener, err := net.Listen("tcp", *dnstapListen)
	if err != nil {
		logger.Error("listen for dnstap", "error", err)
		os.Exit(1)
	}
	if err := collector.LoadBlocklist(*blocklist); err != nil {
		_ = listener.Close()
		logger.Error("load blocklist", "error", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go collector.Reload(ctx, *blocklist, 5*time.Second)
	if analytics.Enabled() {
		go persistAnalytics(ctx, logger, collector, *analyticsState, time.Minute)
	}

	go func() {
		if err := collector.Serve(ctx, listener); err != nil {
			logger.Error("dnstap collector stopped", "error", err)
			stop()
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(writer http.ResponseWriter, _ *http.Request) {
		total, blocked := collector.Metrics()
		writer.Header().Set("Content-Type", "text/plain; version=0.0.4")
		// The status line is already sent, so a scrape that disconnects
		// mid-body cannot be reported to the client; log the first failure.
		var writeErr error
		emit := func(format string, args ...any) {
			if writeErr != nil {
				return
			}
			_, writeErr = fmt.Fprintf(writer, format, args...)
		}
		emit("# HELP rilldns_dns_queries_total DNS client queries observed by the privacy-preserving dnstap collector.\n")
		emit("# TYPE rilldns_dns_queries_total counter\n")
		emit("rilldns_dns_queries_total %d\n", total)
		emit("# HELP rilldns_blocked_queries_total DNS queries matching the active compiled blocklist.\n")
		emit("# TYPE rilldns_blocked_queries_total counter\n")
		emit("rilldns_blocked_queries_total %d\n", blocked)
		if writeErr != nil {
			logger.Warn("write metrics response", "error", writeErr)
		}
	})
	mux.HandleFunc("GET /analytics", func(writer http.ResponseWriter, request *http.Request) {
		limit, err := boundedInt(request.URL.Query().Get("limit"), 10, 1, 100)
		if err != nil {
			writeError(writer, http.StatusBadRequest, err)
			return
		}
		recent, err := boundedInt(request.URL.Query().Get("recent"), 100, 0, 1000)
		if err != nil {
			writeError(writer, http.StatusBadRequest, err)
			return
		}
		snapshot, err := collector.Analytics(request.URL.Query().Get("range"), limit, recent)
		if err != nil {
			writeError(writer, http.StatusBadRequest, err)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(writer).Encode(snapshot); err != nil {
			logger.Warn("write analytics response", "error", err)
		}
	})
	server := &http.Server{Addr: *metricsListen, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("telemetry metrics stopped", "error", err)
			stop()
		}
	}()
	logger.Info("starting query telemetry", "dnstap_listen", *dnstapListen, "metrics_listen", *metricsListen, "analytics_mode", *analyticsMode, "analytics_retention", analyticsRetention.String())
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)
	if err := collector.SaveAnalytics(*analyticsState); err != nil {
		logger.Error("save query analytics during shutdown", "error", err)
	}
}

func boundedInt(raw string, fallback, minimum, maximum int) (int, error) {
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < minimum || value > maximum {
		return 0, fmt.Errorf("value must be an integer between %d and %d", minimum, maximum)
	}
	return value, nil
}

func writeError(writer http.ResponseWriter, status int, err error) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]any{"error": map[string]string{"message": err.Error()}})
}

func persistAnalytics(ctx context.Context, logger *slog.Logger, collector *querytelemetry.Collector, path string, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := collector.SaveAnalytics(path); err != nil {
				logger.Error("save query analytics", "error", err)
			}
		}
	}
}
