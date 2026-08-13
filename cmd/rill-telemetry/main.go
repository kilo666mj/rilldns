package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kilo666mj/rilldns/internal/querytelemetry"
)

func main() {
	dnstapListen := flag.String("dnstap-listen", "127.0.0.1:6000", "TCP address receiving bidirectional dnstap frames")
	metricsListen := flag.String("metrics-listen", "127.0.0.1:19154", "HTTP metrics listen address")
	blocklist := flag.String("blocklist", "/var/lib/rilldns/blocking/merged.hosts", "compiled hosts blocklist")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	collector := querytelemetry.New(logger)
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
		fmt.Fprintln(writer, "# HELP rilldns_dns_queries_total DNS client queries observed by the privacy-preserving dnstap collector.")
		fmt.Fprintln(writer, "# TYPE rilldns_dns_queries_total counter")
		fmt.Fprintf(writer, "rilldns_dns_queries_total %d\n", total)
		fmt.Fprintln(writer, "# HELP rilldns_blocked_queries_total DNS queries matching the active compiled blocklist.")
		fmt.Fprintln(writer, "# TYPE rilldns_blocked_queries_total counter")
		fmt.Fprintf(writer, "rilldns_blocked_queries_total %d\n", blocked)
	})
	server := &http.Server{Addr: *metricsListen, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("telemetry metrics stopped", "error", err)
			stop()
		}
	}()
	logger.Info("starting aggregate query telemetry", "dnstap_listen", *dnstapListen, "metrics_listen", *metricsListen)
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)
}
