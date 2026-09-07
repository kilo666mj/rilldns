// rill-reconcile compares forward A records with a reverse PTR zone and emits
// conservative, reviewable change proposals. It never modifies DNS data.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

type Proposal struct {
	Action string `json:"action"`
	IP     string `json:"ip"`
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

type Finding struct {
	Kind       string   `json:"kind"`
	IP         string   `json:"ip"`
	PTR        []string `json:"ptr,omitempty"`
	Forward    []string `json:"forward,omitempty"`
	Resolution string   `json:"resolution"`
}

type Report struct {
	Subnet           string     `json:"subnet"`
	ForwardAddresses int        `json:"forward_addresses"`
	ReverseAddresses int        `json:"reverse_addresses"`
	Aligned          int        `json:"aligned"`
	Proposals        []Proposal `json:"proposals"`
	Findings         []Finding  `json:"findings"`
}

type Policy struct {
	ExcludedSuffixes []string
	AllowedNames     map[string]struct{}
}

type stringList []string

func (values *stringList) String() string { return strings.Join(*values, ",") }
func (values *stringList) Set(value string) error {
	*values = append(*values, strings.ToLower(dns.Fqdn(strings.TrimSpace(value))))
	return nil
}

func main() {
	reverse := flag.String("reverse", "", "reverse zone file")
	subnet := flag.String("subnet", "192.0.2.0/24", "IPv4 subnet to reconcile")
	var excludedSuffixes stringList
	var allowedNames stringList
	flag.Var(&excludedSuffixes, "exclude-ptr-suffix", "suffix prohibited as a PTR target; repeatable")
	flag.Var(&allowedNames, "allow-ptr-name", "exact PTR target allowed as an exception; repeatable")
	flag.Parse()
	if *reverse == "" || flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: rill-reconcile -reverse FILE [-subnet CIDR] FORWARD_ZONE...")
		os.Exit(2)
	}
	policy := Policy{ExcludedSuffixes: excludedSuffixes, AllowedNames: map[string]struct{}{}}
	for _, name := range allowedNames {
		policy.AllowedNames[name] = struct{}{}
	}
	report, err := reconcile(flag.Args(), *reverse, *subnet, policy)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func reconcile(forwardPaths []string, reversePath, cidr string, policy Policy) (Report, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return Report{}, fmt.Errorf("parse subnet: %w", err)
	}
	forwardByIP := map[string]map[string]struct{}{}
	forwardIPs := map[string]map[string]struct{}{}
	for _, path := range forwardPaths {
		rrs, err := parseZone(path)
		if err != nil {
			return Report{}, err
		}
		for _, rr := range rrs {
			a, ok := rr.(*dns.A)
			if !ok || !network.Contains(a.A) {
				continue
			}
			ip, name := a.A.String(), strings.ToLower(a.Hdr.Name)
			if forwardByIP[ip] == nil {
				forwardByIP[ip] = map[string]struct{}{}
			}
			forwardByIP[ip][name] = struct{}{}
			if forwardIPs[name] == nil {
				forwardIPs[name] = map[string]struct{}{}
			}
			forwardIPs[name][ip] = struct{}{}
		}
	}

	ptrByIP := map[string]map[string]struct{}{}
	rrs, err := parseZone(reversePath)
	if err != nil {
		return Report{}, err
	}
	for _, rr := range rrs {
		ptr, ok := rr.(*dns.PTR)
		if !ok {
			continue
		}
		ip := reverseIPv4(ptr.Hdr.Name)
		if ip == "" || !network.Contains(net.ParseIP(ip)) {
			continue
		}
		if ptrByIP[ip] == nil {
			ptrByIP[ip] = map[string]struct{}{}
		}
		ptrByIP[ip][strings.ToLower(ptr.Ptr)] = struct{}{}
	}

	report := Report{Subnet: cidr, ForwardAddresses: len(forwardByIP), ReverseAddresses: len(ptrByIP), Proposals: []Proposal{}, Findings: []Finding{}}
	for _, ip := range sortedKeys(forwardByIP) {
		names := setValues(forwardByIP[ip])
		ptrs := setValues(ptrByIP[ip])
		if len(ptrs) == 0 {
			eligible := policy.filter(names)
			if candidate := canonicalName(eligible); candidate != "" {
				if len(forwardIPs[candidate]) == 1 {
					report.Proposals = append(report.Proposals, Proposal{Action: "upsert_ptr", IP: ip, Name: candidate, Reason: "missing PTR with one unambiguous canonical forward name"})
				} else {
					report.Findings = append(report.Findings, Finding{Kind: "missing_ptr_shared_name", IP: ip, Forward: names, Resolution: "the candidate name has multiple A addresses; choose a node-specific PTR target"})
				}
			} else {
				kind := "missing_ptr_ambiguous"
				resolution := "choose one canonical PTR target"
				if len(eligible) == 0 {
					kind = "missing_ptr_no_allowed_name"
					resolution = "create or select a canonical name permitted by PTR policy"
				}
				report.Findings = append(report.Findings, Finding{Kind: kind, IP: ip, Forward: names, Resolution: resolution})
			}
			continue
		}
		aligned := false
		for _, ptr := range ptrs {
			if !policy.allowed(ptr) {
				report.Findings = append(report.Findings, Finding{Kind: "disallowed_ptr_target", IP: ip, PTR: []string{ptr}, Forward: names, Resolution: "replace with a canonical name permitted by PTR policy"})
				continue
			}
			if _, ok := forwardIPs[ptr][ip]; ok {
				aligned = true
				continue
			}
			kind := "ptr_without_a"
			if len(forwardIPs[ptr]) != 0 {
				kind = "ptr_a_mismatch"
			}
			report.Findings = append(report.Findings, Finding{Kind: kind, IP: ip, PTR: []string{ptr}, Forward: names, Resolution: "review or replace the PTR target"})
		}
		if aligned {
			report.Aligned++
		}
		if len(ptrs) > 1 {
			report.Findings = append(report.Findings, Finding{Kind: "multiple_ptr", IP: ip, PTR: ptrs, Forward: names, Resolution: "confirm whether multiple PTR records are intentional"})
		}
	}
	for _, ip := range sortedKeys(ptrByIP) {
		if _, ok := forwardByIP[ip]; !ok {
			ptrs := setValues(ptrByIP[ip])
			kind := "ptr_without_forward_address"
			resolution := "confirm the address is still in use"
			for _, ptr := range ptrs {
				if len(forwardIPs[ptr]) != 0 {
					kind = "ptr_a_mismatch"
					resolution = "PTR target resolves to " + strings.Join(sortedKeys(forwardIPs[ptr]), ",") + "; choose the canonical target for this address"
					break
				}
			}
			report.Findings = append(report.Findings, Finding{Kind: kind, IP: ip, PTR: ptrs, Resolution: resolution})
		}
	}
	return report, nil
}

func (policy Policy) filter(names []string) []string {
	result := make([]string, 0, len(names))
	for _, name := range names {
		if policy.allowed(name) {
			result = append(result, name)
		}
	}
	return result
}

func (policy Policy) allowed(name string) bool {
	name = strings.ToLower(dns.Fqdn(name))
	if _, ok := policy.AllowedNames[name]; ok {
		return true
	}
	for _, suffix := range policy.ExcludedSuffixes {
		if strings.HasSuffix(name, strings.ToLower(dns.Fqdn(suffix))) {
			return false
		}
	}
	return true
}

func parseZone(path string) ([]dns.RR, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	// Read-only: nothing was written, so a close failure changes nothing.
	defer func() { _ = file.Close() }()
	parser := dns.NewZoneParser(file, "", path)
	var records []dns.RR
	for rr, ok := parser.Next(); ok; rr, ok = parser.Next() {
		records = append(records, rr)
	}
	if err := parser.Err(); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return records, nil
}

func reverseIPv4(name string) string {
	labels := dns.SplitDomainName(strings.ToLower(name))
	if len(labels) != 6 || labels[4] != "in-addr" || labels[5] != "arpa" {
		return ""
	}
	return strings.Join([]string{labels[3], labels[2], labels[1], labels[0]}, ".")
}

func canonicalName(names []string) string {
	if len(names) == 1 {
		return names[0]
	}
	return ""
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return bytesCompare(net.ParseIP(keys[i]).To4(), net.ParseIP(keys[j]).To4()) < 0
	})
	return keys
}

func bytesCompare(left, right net.IP) int {
	for i := range left {
		if left[i] < right[i] {
			return -1
		}
		if left[i] > right[i] {
			return 1
		}
	}
	return 0
}

func setValues(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
