package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kilo666mj/rilldns/internal/secondary"
)

func main() {
	primary := flag.String("primary", "127.0.0.1:1053", "primary DNS server")
	probePrimary := flag.String("probe-primary", "", "optional cache-free primary used for SOA freshness checks")
	listen := flag.String("listen", "127.0.0.1:1054", "UDP/TCP NOTIFY listen address")
	zones := flag.String("zones", "", "comma-separated secondary zones (required)")
	output := flag.String("output", "/var/lib/rilldns/imported-zones", "published zone directory")
	status := flag.String("status", "/var/lib/rilldns/status/secondary.json", "status JSON path")
	refresh := flag.Duration("refresh", time.Hour, "SOA polling interval")
	retryMin := flag.Duration("retry-min", 30*time.Second, "first retry delay after a failed zone refresh")
	retryMax := flag.Duration("retry-max", 15*time.Minute, "maximum retry delay after repeated failures (capped at -refresh)")
	timeout := flag.Duration("timeout", 15*time.Second, "DNS operation timeout")
	notifyFrom := flag.String("notify-from", "127.0.0.1", "only accepted NOTIFY source IP")
	discoverZones := flag.Bool("discover-zones", false, "discover existing zone files and accept new zones notified by the trusted primary")
	maxZones := flag.Int("max-zones", 1000, "maximum configured and dynamically discovered zones")
	tsigName := flag.String("tsig-name", "rilldns-transfer.", "TSIG key name")
	tsigSecretFile := flag.String("tsig-secret-file", "/etc/rilldns/transfer.secret", "file containing base64 TSIG secret")
	flag.Parse()
	zoneList, err := parseZones(*zones)
	if err != nil {
		fatal(err)
	}
	secret, err := os.ReadFile(*tsigSecretFile)
	if err != nil {
		fatal(err)
	}
	service, err := secondary.New(secondary.Config{
		Primary: *primary, ProbePrimary: *probePrimary, Listen: *listen, Zones: zoneList, OutputDir: *output,
		StatusFile: *status, Refresh: *refresh, Timeout: *timeout, NotifyFrom: net.ParseIP(*notifyFrom),
		TSIGName: *tsigName, TSIGSecret: strings.TrimSpace(string(secret)), DiscoverZones: *discoverZones, MaxZones: *maxZones,
		RetryMin: *retryMin, RetryMax: *retryMax,
	})
	if err != nil {
		fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := service.Run(ctx); err != nil {
		fatal(err)
	}
}

// parseZones requires an explicit zone list. A missing list used to fall back
// to a placeholder zone, which replicated nothing while refresh alerts fired.
func parseZones(value string) ([]string, error) {
	var zones []string
	for _, zone := range strings.Split(value, ",") {
		zone = strings.TrimSpace(zone)
		if zone == "" {
			continue
		}
		if strings.HasPrefix(zone, "-") {
			return nil, fmt.Errorf("invalid zone %q: -zones appears to be missing its value", zone)
		}
		zones = append(zones, zone)
	}
	if len(zones) == 0 {
		return nil, errors.New("-zones is required: list the authoritative zones to replicate")
	}
	return zones, nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
