// rill-diff compares authoritative AXFR snapshots from two DNS servers.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kilo666mj/rilldns/internal/refreshstatus"
	"github.com/kilo666mj/rilldns/internal/statusfile"
	"github.com/miekg/dns"
)

type ZoneResult struct {
	Zone            string          `json:"zone"`
	Equal           bool            `json:"equal"`
	SourceSOA       uint32          `json:"source_serial"`
	TargetSOA       uint32          `json:"target_serial"`
	SourceRRs       int             `json:"source_records"`
	TargetRRs       int             `json:"target_records"`
	OnlySource      []string        `json:"only_source,omitempty"`
	OnlyTarget      []string        `json:"only_target,omitempty"`
	Queries         int             `json:"queries"`
	QueryMismatches []QueryMismatch `json:"query_mismatches,omitempty"`
	Error           string          `json:"error,omitempty"`
}

type Probe struct {
	Name string
	Type uint16
}

type QueryMismatch struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	Transport string `json:"transport"`
	Source    string `json:"source"`
	Target    string `json:"target"`
}

type Report struct {
	Source     string       `json:"source"`
	Target     string       `json:"target"`
	CheckedAt  time.Time    `json:"checked_at"`
	Equal      bool         `json:"equal"`
	Mismatches int          `json:"mismatches"`
	Zones      []ZoneResult `json:"zones"`
}

type tsigCredential struct {
	name   string
	secret string
}

func main() {
	source := flag.String("source", "192.0.2.10:53", "source DNS server")
	target := flag.String("target", "127.0.0.1:1053", "target DNS server")
	targetZoneDir := flag.String("target-zone-dir", "", "optional directory of persisted target zone files used instead of target AXFR")
	sourceTSIGName := flag.String("source-tsig-name", "", "optional source TSIG key name")
	sourceTSIGSecretFile := flag.String("source-tsig-secret-file", "", "file containing the source TSIG secret")
	targetTSIGName := flag.String("target-tsig-name", "", "optional target TSIG key name")
	targetTSIGSecretFile := flag.String("target-tsig-secret-file", "", "file containing the target TSIG secret")
	timeout := flag.Duration("timeout", 15*time.Second, "timeout per transfer")
	reportFile := flag.String("report-file", "", "atomically write the full report to this file")
	statusFile := flag.String("status-file", "", "atomically write refresh health to this file")
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: rill-diff [flags] ZONE...")
		os.Exit(2)
	}
	sourceCredential, err := loadTSIG(*sourceTSIGName, *sourceTSIGSecretFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	targetCredential, err := loadTSIG(*targetTSIGName, *targetTSIGSecretFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	report := Report{Source: *source, Target: *target, CheckedAt: time.Now().UTC(), Equal: true, Zones: []ZoneResult{}}
	for _, zone := range flag.Args() {
		result := compare(zone, *source, *target, *targetZoneDir, sourceCredential, targetCredential, *timeout)
		report.Zones = append(report.Zones, result)
		if !result.Equal {
			report.Equal = false
			report.Mismatches += len(result.OnlySource) + len(result.OnlyTarget)
			report.Mismatches += len(result.QueryMismatches)
			if result.Error != "" {
				report.Mismatches++
			}
		}
	}
	if *reportFile != "" {
		err = statusfile.WriteJSON(*reportFile, report, 0440)
		if err == nil && !report.Equal {
			err = statusfile.WriteJSON(*reportFile+".failed", report, 0440)
		}
	} else {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		err = encoder.Encode(report)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *statusFile != "" {
		queries := 0
		for _, zone := range report.Zones {
			queries += zone.Queries
		}
		status := differentialStatus(report, queries, loadPreviousStatus(*statusFile))
		if report.Equal {
			status.LastSuccess = time.Now().UTC()
		}
		if err := statusfile.WriteJSON(*statusFile, status, 0440); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if !report.Equal && *statusFile == "" {
		os.Exit(1)
	}
}

func loadPreviousStatus(path string) refreshstatus.Status {
	content, err := os.ReadFile(path)
	if err != nil {
		return refreshstatus.Status{}
	}
	var status refreshstatus.Status
	if json.Unmarshal(content, &status) != nil {
		return refreshstatus.Status{}
	}
	return status
}

func differentialStatus(report Report, queries int, previous refreshstatus.Status) refreshstatus.Status {
	status := refreshstatus.Status{
		Kind:         "differential",
		Success:      report.Equal,
		LastAttempt:  report.CheckedAt,
		LastSuccess:  previous.LastSuccess,
		CheckedZones: len(report.Zones),
		Queries:      queries,
		Mismatches:   report.Mismatches,
	}
	if !report.Equal {
		status.Error = "RillDNS primary and secondary differ"
		status.ConsecutiveFailures = previous.ConsecutiveFailures + 1
	}
	return status
}

func compare(zone, source, target, targetZoneDir string, sourceCredential, targetCredential *tsigCredential, timeout time.Duration) ZoneResult {
	zone = dns.Fqdn(zone)
	result := ZoneResult{Zone: zone, Equal: false, OnlySource: []string{}, OnlyTarget: []string{}}
	sourceRRs, err := transfer(zone, source, sourceCredential, timeout)
	if err != nil {
		result.Error = "source: " + err.Error()
		return result
	}
	var targetRRs []dns.RR
	if targetZoneDir == "" {
		targetRRs, err = transfer(zone, target, targetCredential, timeout)
	} else {
		targetRRs, err = loadZone(filepath.Join(targetZoneDir, strings.TrimSuffix(zone, ".")+".zone"))
	}
	if err != nil {
		result.Error = "target: " + err.Error()
		return result
	}
	result.SourceSOA, result.TargetSOA = serial(sourceRRs), serial(targetRRs)
	result.SourceRRs, result.TargetRRs = len(sourceRRs), len(targetRRs)
	left, right := multiset(sourceRRs), multiset(targetRRs)
	for rr, count := range left {
		for i := 0; i < count-right[rr]; i++ {
			result.OnlySource = append(result.OnlySource, rr)
		}
	}
	for rr, count := range right {
		for i := 0; i < count-left[rr]; i++ {
			result.OnlyTarget = append(result.OnlyTarget, rr)
		}
	}
	sort.Strings(result.OnlySource)
	sort.Strings(result.OnlyTarget)
	for _, probe := range probes(zone, sourceRRs) {
		for _, network := range []string{"udp", "tcp"} {
			result.Queries++
			left, leftErr := query(source, probe, network, sourceCredential, timeout)
			right, rightErr := query(target, probe, network, targetCredential, timeout)
			if leftErr != nil || rightErr != nil || left != right {
				result.QueryMismatches = append(result.QueryMismatches, QueryMismatch{Name: probe.Name, Type: dns.TypeToString[probe.Type], Transport: network, Source: responseText(left, leftErr), Target: responseText(right, rightErr)})
			}
		}
	}
	result.Equal = len(result.OnlySource) == 0 && len(result.OnlyTarget) == 0 && result.SourceSOA == result.TargetSOA && len(result.QueryMismatches) == 0
	return result
}

func probes(zone string, records []dns.RR) []Probe {
	seen := map[string]Probe{}
	add := func(name string, qtype uint16) {
		key := strings.ToLower(dns.Fqdn(name)) + "/" + fmt.Sprint(qtype)
		seen[key] = Probe{dns.Fqdn(name), qtype}
	}
	add(zone, dns.TypeSOA)
	add(zone, dns.TypeNS)
	for _, rr := range records {
		typeCode := rr.Header().Rrtype
		if typeCode == dns.TypeRRSIG || typeCode == dns.TypeNSEC {
			continue
		}
		owner := rr.Header().Name
		add(owner, typeCode)
		labels := dns.SplitDomainName(owner)
		if len(labels) > 0 && labels[0] == "*" {
			add("rilldns-wildcard-probe."+strings.Join(labels[1:], "."), typeCode)
		}
		if typeCode == dns.TypeNS && !strings.EqualFold(dns.Fqdn(owner), zone) {
			add("rilldns-delegation-probe."+dns.Fqdn(owner), dns.TypeA)
		}
	}
	// Deterministic negative probes: a nonexistent owner and an absent type at
	// the apex distinguish NXDOMAIN from NODATA behavior.
	add("rilldns-nxdomain-probe."+zone, dns.TypeA)
	add(zone, dns.TypeAAAA)
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]Probe, 0, len(keys))
	for _, key := range keys {
		result = append(result, seen[key])
	}
	return result
}

func query(address string, probe Probe, network string, credential *tsigCredential, timeout time.Duration) (string, error) {
	message := new(dns.Msg)
	message.SetQuestion(probe.Name, probe.Type)
	message.SetEdns0(1232, true)
	client := &dns.Client{Net: network, Timeout: timeout}
	applyTSIG(message, client, credential)
	response, _, err := client.Exchange(message, address)
	if err != nil {
		return "", err
	}
	return normalizeResponse(response), nil
}

func normalizeResponse(message *dns.Msg) string {
	answers := behavioralRRStrings(message.Answer)
	// Authoritative implementations may add apex NS records or different but
	// valid DNSSEC denial proofs to the authority section. AXFR comparison
	// already checks those records exactly; query behavior compares the rcode,
	// AA/truncation flags, and answer/CNAME chain.
	result := fmt.Sprintf("rcode=%s aa=%t tc=%t answer=[%s]", dns.RcodeToString[message.Rcode], message.Authoritative, message.Truncated, strings.Join(answers, "|"))
	// Referrals are non-authoritative NOERROR responses. Their delegated NS set
	// and in-bailiwick A/AAAA glue are part of observable DNS behavior and must
	// match even though optional authority data on authoritative answers is not.
	if message.Rcode == dns.RcodeSuccess && !message.Authoritative && len(message.Answer) == 0 {
		result += fmt.Sprintf(" authority=[%s] glue=[%s]", strings.Join(behavioralRRStringsOfTypes(message.Ns, dns.TypeNS), "|"), strings.Join(behavioralRRStringsOfTypes(message.Extra, dns.TypeA, dns.TypeAAAA), "|"))
	}
	return result
}

func behavioralRRStringsOfTypes(records []dns.RR, recordTypes ...uint16) []string {
	wanted := make(map[uint16]struct{}, len(recordTypes))
	for _, recordType := range recordTypes {
		wanted[recordType] = struct{}{}
	}
	filtered := make([]dns.RR, 0, len(records))
	for _, rr := range records {
		if _, ok := wanted[rr.Header().Rrtype]; ok {
			filtered = append(filtered, rr)
		}
	}
	return behavioralRRStrings(filtered)
}

func behavioralRRStrings(records []dns.RR) []string {
	copied := make([]dns.RR, 0, len(records))
	for _, rr := range records {
		clone := dns.Copy(rr)
		clone.Header().Ttl = 0
		copied = append(copied, clone)
	}
	return rrStrings(copied)
}

func rrStringsOfType(records []dns.RR, recordType uint16) []string {
	return rrStringsOfTypes(records, recordType)
}

func rrStringsOfTypes(records []dns.RR, recordTypes ...uint16) []string {
	wanted := make(map[uint16]struct{}, len(recordTypes))
	for _, recordType := range recordTypes {
		wanted[recordType] = struct{}{}
	}
	filtered := make([]dns.RR, 0, len(records))
	for _, rr := range records {
		if _, ok := wanted[rr.Header().Rrtype]; ok {
			filtered = append(filtered, rr)
		}
	}
	return rrStrings(filtered)
}

func rrStrings(records []dns.RR) []string {
	result := make([]string, 0, len(records))
	for _, rr := range records {
		result = append(result, strings.ToLower(rr.String()))
	}
	sort.Strings(result)
	return result
}

func responseText(value string, err error) string {
	if err != nil {
		return "error: " + err.Error()
	}
	return value
}

func transfer(zone, address string, credential *tsigCredential, timeout time.Duration) ([]dns.RR, error) {
	if _, _, err := net.SplitHostPort(address); err != nil {
		return nil, fmt.Errorf("invalid address %q", address)
	}
	message := new(dns.Msg)
	message.SetAxfr(zone)
	transfer := &dns.Transfer{DialTimeout: timeout, ReadTimeout: timeout, WriteTimeout: timeout}
	if credential != nil {
		message.SetTsig(credential.name, dns.HmacSHA256, 300, time.Now().Unix())
		transfer.TsigSecret = map[string]string{credential.name: credential.secret}
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	channel, err := transfer.In(message, address)
	if err != nil {
		return nil, err
	}
	var records []dns.RR
	for envelope := range channel {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		if envelope.Error != nil {
			return nil, envelope.Error
		}
		records = append(records, envelope.RR...)
	}
	if len(records) < 2 {
		return nil, fmt.Errorf("incomplete AXFR")
	}
	// AXFR repeats the SOA as its closing record; compare one canonical copy.
	if records[0].Header().Rrtype == dns.TypeSOA && records[len(records)-1].Header().Rrtype == dns.TypeSOA {
		records = records[:len(records)-1]
	}
	return records, nil
}

func loadZone(path string) ([]dns.RR, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	// Read-only: nothing was written, so a close failure changes nothing.
	defer func() { _ = file.Close() }()
	parser := dns.NewZoneParser(file, "", path)
	var records []dns.RR
	for record, ok := parser.Next(); ok; record, ok = parser.Next() {
		records = append(records, record)
	}
	if err := parser.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

func loadTSIG(name, secretFile string) (*tsigCredential, error) {
	if name == "" && secretFile == "" {
		return nil, nil
	}
	if name == "" || secretFile == "" {
		return nil, errors.New("target TSIG name and secret file must be specified together")
	}
	secret, err := os.ReadFile(secretFile)
	if err != nil {
		return nil, fmt.Errorf("read TSIG secret: %w", err)
	}
	return &tsigCredential{name: strings.ToLower(dns.Fqdn(name)), secret: strings.TrimSpace(string(secret))}, nil
}

func applyTSIG(message *dns.Msg, client *dns.Client, credential *tsigCredential) {
	if credential == nil {
		return
	}
	message.SetTsig(credential.name, dns.HmacSHA256, 300, time.Now().Unix())
	client.TsigSecret = map[string]string{credential.name: credential.secret}
}

func multiset(records []dns.RR) map[string]int {
	result := map[string]int{}
	for _, rr := range records {
		result[strings.ToLower(rr.String())]++
	}
	return result
}

func serial(records []dns.RR) uint32 {
	for _, rr := range records {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa.Serial
		}
	}
	return 0
}
