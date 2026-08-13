package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/kilo666mj/rilldns/internal/zones"
)

func main() {
	dnsAddress := flag.String("dns-address", "127.0.0.1:1053", "CoreDNS address used to verify publication")
	notifyAddress := flag.String("notify-address", "", "secondary DNS NOTIFY address")
	timeout := flag.Duration("timeout", 60*time.Second, "maximum publication wait")
	flag.Parse()
	if flag.NArg() != 2 || *notifyAddress == "" {
		fmt.Fprintln(os.Stderr, "usage: rill-notify -notify-address host:port zone serial")
		os.Exit(2)
	}
	serial, err := strconv.ParseUint(flag.Arg(1), 10, 32)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid serial: %v\n", err)
		os.Exit(2)
	}
	verifier := zones.DNSVerifier{Address: *dnsAddress, NotifyAddress: *notifyAddress, Interval: 200 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	if err := verifier.WaitForSerial(ctx, flag.Arg(0), uint32(serial)); err != nil {
		fmt.Fprintf(os.Stderr, "publication verification failed: %v\n", err)
		os.Exit(1)
	}
	if err := verifier.Notify(ctx, flag.Arg(0)); err != nil {
		fmt.Fprintf(os.Stderr, "NOTIFY failed: %v\n", err)
		os.Exit(1)
	}
}
