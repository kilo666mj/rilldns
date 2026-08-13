package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kilo666mj/rilldns/internal/refreshstatus"
	"github.com/kilo666mj/rilldns/internal/statusfile"
	"github.com/miekg/dns"
)

func main() {
	zoneDir := flag.String("zone-dir", "/var/lib/rilldns/zones", "zone file directory")
	statusPath := flag.String("status-file", "/var/lib/rilldns/status/zones.json", "status output")
	source := flag.String("source", "local-zone-files", "status source label")
	flag.Parse()
	zones := flag.Args()
	if len(zones) == 0 {
		matches, err := filepath.Glob(filepath.Join(*zoneDir, "*.zone"))
		if err != nil || len(matches) == 0 {
			fmt.Fprintln(os.Stderr, "no zone files found")
			os.Exit(1)
		}
		for _, match := range matches {
			zones = append(zones, strings.TrimSuffix(filepath.Base(match), ".zone"))
		}
	}
	attempt := time.Now().UTC()
	result := refreshstatus.Status{Kind: "zones", LastAttempt: attempt, Source: *source, Zones: []refreshstatus.Zone{}}
	for _, zone := range zones {
		z, err := inspect(filepath.Join(*zoneDir, strings.TrimSuffix(zone, ".")+".zone"), dns.Fqdn(zone))
		if err != nil {
			result.Error = err.Error()
			_ = statusfile.WriteJSON(*statusPath, result, 0440)
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		result.Zones = append(result.Zones, z)
	}
	result.Success = true
	result.LastSuccess = time.Now().UTC()
	if err := statusfile.WriteJSON(*statusPath, result, 0440); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func inspect(path, name string) (refreshstatus.Zone, error) {
	f, err := os.Open(path)
	if err != nil {
		return refreshstatus.Zone{}, err
	}
	defer f.Close()
	p := dns.NewZoneParser(f, name, path)
	count := 0
	var serial uint32
	soa := 0
	for rr, ok := p.Next(); ok; rr, ok = p.Next() {
		count++
		if record, yes := rr.(*dns.SOA); yes {
			soa++
			serial = record.Serial
		}
	}
	if err := p.Err(); err != nil {
		return refreshstatus.Zone{}, fmt.Errorf("%s: %w", name, err)
	}
	if soa != 1 || count < 2 {
		return refreshstatus.Zone{}, fmt.Errorf("%s: expected one SOA and at least two records (got %d/%d)", name, soa, count)
	}
	return refreshstatus.Zone{Name: name, Serial: serial, Records: count}, nil
}
