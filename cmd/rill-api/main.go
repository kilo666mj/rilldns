package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kilo666mj/rilldns/internal/api"
	"github.com/kilo666mj/rilldns/internal/webui"
	"github.com/kilo666mj/rilldns/internal/zones"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8053", "HTTP listen address")
	zoneDir := flag.String("zone-dir", "/var/lib/rilldns/zones", "managed zone directory")
	auditPath := flag.String("audit-log", "/var/lib/rilldns/audit.jsonl", "append-only audit log")
	dnsAddress := flag.String("dns-address", "127.0.0.1:1053", "CoreDNS address used to verify publication")
	notifyAddress := flag.String("notify-address", "", "optional secondary NOTIFY address")
	readOnly := flag.Bool("read-only", false, "reject all zone mutations")
	statusDir := flag.String("status-dir", "/var/lib/rilldns/status", "refresh status directory")
	metricsListen := flag.String("metrics-listen", "", "optional read-only metrics listen address")
	prometheusURL := flag.String("prometheus-url", envOr("RILLDNS_PROMETHEUS_URL", "http://192.0.2.20:9090"), "Prometheus URL used for fixed UI history queries")
	coreDNSMetricsURL := flag.String("coredns-metrics-url", envOr("RILLDNS_COREDNS_METRICS_URL", "http://127.0.0.1:19153/metrics"), "local CoreDNS metrics URL to re-export")
	telemetryMetricsURL := flag.String("telemetry-metrics-url", envOr("RILLDNS_TELEMETRY_METRICS_URL", "http://127.0.0.1:19154/metrics"), "local aggregate query telemetry metrics URL to re-export")
	uiListen := flag.String("ui-listen", os.Getenv("RILLDNS_UI_LISTEN"), "optional OIDC-protected web UI listen address")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	verifier := zones.DNSVerifier{Address: *dnsAddress, NotifyAddress: *notifyAddress, Interval: 200 * time.Millisecond}
	store := zones.NewStore(*zoneDir, *auditPath, verifier)
	apiServer := api.NewWithStatus(store, logger, *readOnly, *statusDir)
	apiServer.SetMetricsSources(*prometheusURL, *coreDNSMetricsURL, *telemetryMetricsURL)
	server := &http.Server{
		Addr:              *listen,
		Handler:           apiServer.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      75 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	var metricsServer *http.Server
	var uiServer *http.Server
	if *metricsListen != "" {
		metricsServer = &http.Server{
			Addr:              *metricsListen,
			Handler:           apiServer.MetricsHandler(),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    8 << 10,
		}
		go func() {
			logger.Info("starting RillDNS metrics", "listen", *metricsListen)
			if err := metricsServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("RillDNS metrics stopped", "error", err)
			}
		}()
	}
	if *uiListen != "" {
		uiHandler, err := webui.New(apiServer.Handler(), webui.OIDCConfig{
			Issuer: os.Getenv("RILLDNS_OIDC_ISSUER"), ClientID: os.Getenv("RILLDNS_OIDC_CLIENT_ID"),
			ClientSecret: os.Getenv("RILLDNS_OIDC_CLIENT_SECRET"), RedirectURL: os.Getenv("RILLDNS_OIDC_REDIRECT_URL"),
			Scopes:          envCSV("RILLDNS_OIDC_SCOPES", []string{"openid", "profile", "email"}),
			AllowedSubjects: envCSV("RILLDNS_OIDC_ALLOWED_SUBJECTS", nil), AllowedEmails: envCSV("RILLDNS_OIDC_ALLOWED_EMAILS", nil),
			AllowedGroups: envCSV("RILLDNS_OIDC_ALLOWED_GROUPS", nil), SessionKey: os.Getenv("RILLDNS_SESSION_KEY"),
		})
		if err != nil {
			logger.Error("configure RillDNS UI", "error", err)
			os.Exit(1)
		}
		uiServer = &http.Server{Addr: *uiListen, Handler: uiHandler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 75 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
		go func() {
			logger.Info("starting RillDNS UI", "listen", *uiListen)
			if err := uiServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("RillDNS UI stopped", "error", err)
			}
		}()
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		if metricsServer != nil {
			_ = metricsServer.Shutdown(shutdownCtx)
		}
		if uiServer != nil {
			_ = uiServer.Shutdown(shutdownCtx)
		}
	}()

	logger.Info("starting RillDNS API", "listen", *listen, "zone_dir", *zoneDir, "dns_address", *dnsAddress, "read_only", *readOnly, "metrics_listen", *metricsListen)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("RillDNS API stopped", "error", err)
		os.Exit(1)
	}
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func envCSV(name string, fallback []string) []string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return append([]string(nil), fallback...)
	}
	var result []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}
