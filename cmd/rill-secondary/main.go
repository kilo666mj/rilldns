package main

import (
	"context"
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
	zones := flag.String("zones", "example.test", "comma-separated secondary zones")
	output := flag.String("output", "/var/lib/rilldns/imported-zones", "published zone directory")
	status := flag.String("status", "/var/lib/rilldns/status/secondary.json", "status JSON path")
	refresh := flag.Duration("refresh", time.Hour, "SOA polling interval")
	timeout := flag.Duration("timeout", 15*time.Second, "DNS operation timeout")
	notifyFrom := flag.String("notify-from", "127.0.0.1", "only accepted NOTIFY source IP")
	discoverZones := flag.Bool("discover-zones", false, "discover existing zone files and accept new zones notified by the trusted primary")
	maxZones := flag.Int("max-zones", 1000, "maximum configured and dynamically discovered zones")
	tsigName := flag.String("tsig-name", "rilldns-transfer.", "TSIG key name")
	tsigSecretFile := flag.String("tsig-secret-file", "/etc/rilldns/transfer.secret", "file containing base64 TSIG secret")
	flag.Parse()
	secret, err := os.ReadFile(*tsigSecretFile)
	if err != nil {
		fatal(err)
	}
	service, err := secondary.New(secondary.Config{
		Primary: *primary, ProbePrimary: *probePrimary, Listen: *listen, Zones: strings.Split(*zones, ","), OutputDir: *output,
		StatusFile: *status, Refresh: *refresh, Timeout: *timeout, NotifyFrom: net.ParseIP(*notifyFrom),
		TSIGName: *tsigName, TSIGSecret: strings.TrimSpace(string(secret)), DiscoverZones: *discoverZones, MaxZones: *maxZones,
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

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
