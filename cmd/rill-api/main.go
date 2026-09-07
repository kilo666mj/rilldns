package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/kilo666mj/rilldns/internal/api"
	"github.com/kilo666mj/rilldns/internal/cloudflare"
	"github.com/kilo666mj/rilldns/internal/controlclient"
	"github.com/kilo666mj/rilldns/internal/mcpserver"
	"github.com/kilo666mj/rilldns/internal/webui"
	"github.com/kilo666mj/rilldns/internal/zones"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8053", "HTTP listen address")
	zoneDir := flag.String("zone-dir", "/var/lib/rilldns/zones", "managed zone directory")
	auditPath := flag.String("audit-log", "/var/lib/rilldns/audit.jsonl", "append-only audit log")
	dnsAddress := flag.String("dns-address", "127.0.0.1:1053", "CoreDNS address used to verify publication")
	notifyAddress := flag.String("notify-address", "", "optional secondary NOTIFY address")
	notifyTSIGName := flag.String("notify-tsig-name", os.Getenv("RILLDNS_NOTIFY_TSIG_NAME"), "TSIG key name used to authenticate NOTIFY")
	notifyTSIGSecretFile := flag.String("notify-tsig-secret-file", os.Getenv("RILLDNS_NOTIFY_TSIG_SECRET_FILE"), "file containing the base64 TSIG secret used for NOTIFY")
	readOnly := flag.Bool("read-only", false, "reject all zone mutations")
	statusDir := flag.String("status-dir", "/var/lib/rilldns/status", "refresh status directory")
	metricsListen := flag.String("metrics-listen", "", "optional read-only metrics listen address")
	prometheusURL := flag.String("prometheus-url", envOr("RILLDNS_PROMETHEUS_URL", "http://192.0.2.20:9090"), "Prometheus URL used for fixed UI history queries")
	coreDNSMetricsURL := flag.String("coredns-metrics-url", envOr("RILLDNS_COREDNS_METRICS_URL", "http://127.0.0.1:19153/metrics"), "local CoreDNS metrics URL to re-export")
	telemetryMetricsURL := flag.String("telemetry-metrics-url", envOr("RILLDNS_TELEMETRY_METRICS_URL", "http://127.0.0.1:19154/metrics"), "local aggregate query telemetry metrics URL to re-export")
	uiListen := flag.String("ui-listen", os.Getenv("RILLDNS_UI_LISTEN"), "optional OIDC-protected web UI listen address")
	cloudflareZones := flag.String("cloudflare-zones", os.Getenv("RILLDNS_CLOUDFLARE_ZONES"), "optional comma-separated Cloudflare zone-name allowlist")
	cloudflareTokenFile := flag.String("cloudflare-token-file", os.Getenv("RILLDNS_CLOUDFLARE_TOKEN_FILE"), "file containing the Cloudflare API token")
	haNode := flag.String("ha-node", envOr("RILLDNS_HA_NODE", hostname()), "HA node identity")
	haRole := flag.String("ha-role", os.Getenv("RILLDNS_HA_ROLE"), "HA role: active or standby")
	haPeerName := flag.String("ha-peer-name", os.Getenv("RILLDNS_HA_PEER_NAME"), "HA peer identity")
	haPeerHealthURL := flag.String("ha-peer-health-url", os.Getenv("RILLDNS_HA_PEER_HEALTH_URL"), "read-only peer health URL")
	haPeerStatusURL := flag.String("ha-peer-status-url", os.Getenv("RILLDNS_HA_PEER_STATUS_URL"), "read-only peer HA status URL")
	haVIP := flag.String("ha-vip", os.Getenv("RILLDNS_HA_VIP"), "HA virtual IP to report ownership for")
	mcpToken := flag.String("mcp-token", os.Getenv("RILLDNS_MCP_TOKEN"), "bearer token enabling hosted MCP at /mcp")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	var notifySecret string
	if *notifyAddress != "" {
		if *notifyTSIGSecretFile == "" {
			logger.Error("configure NOTIFY", "error", "-notify-tsig-secret-file is required when NOTIFY is enabled")
			os.Exit(1)
		}
		secret, err := os.ReadFile(*notifyTSIGSecretFile)
		if err != nil {
			logger.Error("read NOTIFY TSIG secret", "error", err)
			os.Exit(1)
		}
		notifySecret = strings.TrimSpace(string(secret))
	}
	verifier := zones.DNSVerifier{Address: *dnsAddress, NotifyAddress: *notifyAddress, Interval: 200 * time.Millisecond, TSIGName: *notifyTSIGName, TSIGSecret: notifySecret}
	store := zones.NewStore(*zoneDir, *auditPath, verifier)
	apiServer := api.NewWithStatus(store, logger, *readOnly, *statusDir)
	apiServer.SetHA(*haNode, *haRole, *haPeerName, *haPeerHealthURL, *haPeerStatusURL, *haVIP)
	cloudflareConfigPath := filepath.Join(filepath.Dir(*statusDir), "cloudflare-zones.json")
	cloudflareConfig, err := cloudflare.LoadConfig(cloudflareConfigPath, canonicalNames(envCSVValue(*cloudflareZones)))
	if err != nil {
		logger.Error("load Cloudflare configuration", "error", err)
		os.Exit(1)
	}
	if len(cloudflareConfig.Zones) > 0 || strings.TrimSpace(*cloudflareTokenFile) != "" {
		if strings.TrimSpace(*cloudflareTokenFile) == "" {
			logger.Error("configure Cloudflare", "error", "-cloudflare-token-file is required when Cloudflare zones are configured")
			os.Exit(1)
		}
		token, err := os.ReadFile(*cloudflareTokenFile)
		if err != nil {
			logger.Error("read Cloudflare API token", "error", err)
			os.Exit(1)
		}
		client, err := cloudflare.New(string(token))
		if err != nil {
			logger.Error("configure Cloudflare", "error", err)
			os.Exit(1)
		}
		client.SetAuditPath(*auditPath)
		apiServer.SetCloudflare(client, cloudflareConfig.Zones)
		apiServer.SetCloudflareConfigPath(cloudflareConfigPath)
	}
	apiServer.SetMetricsSources(*prometheusURL, *coreDNSMetricsURL, *telemetryMetricsURL)
	apiHandler := apiServer.Handler()
	var mainHandler http.Handler = apiHandler
	var hostedMCP http.Handler
	if *mcpToken != "" {
		apiClient, err := controlclient.New(loopbackAPIURL(*listen))
		if err != nil {
			logger.Error("configure hosted MCP API client", "error", err)
			os.Exit(1)
		}
		mcpHandler, err := mcpserver.Hosted(apiClient, *dnsAddress, *mcpToken)
		if err != nil {
			logger.Error("configure hosted MCP", "error", err)
			os.Exit(1)
		}
		hostedMCP = mcpHandler
		mux := http.NewServeMux()
		mux.Handle("POST /mcp", mcpHandler)
		mux.Handle("/", apiHandler)
		mainHandler = mux
	}
	server := &http.Server{
		Addr:              *listen,
		Handler:           mainHandler,
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
		uiHandler = mountHostedMCP(uiHandler, hostedMCP)
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

func mountHostedMCP(fallback, hostedMCP http.Handler) http.Handler {
	if hostedMCP == nil {
		return fallback
	}
	mux := http.NewServeMux()
	mux.Handle("POST /mcp", hostedMCP)
	mux.Handle("/", fallback)
	return mux
}

func loopbackAPIURL(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "http://127.0.0.1:8053"
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port)
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func hostname() string {
	name, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return name
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

func envCSVValue(value string) []string {
	var result []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}

func canonicalNames(values []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}
