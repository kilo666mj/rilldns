package main

import (
	"github.com/miekg/dns"
	"testing"
)

func TestMultiset(t *testing.T) {
	a, _ := dns.NewRR("example. 300 IN A 192.0.2.1")
	b, _ := dns.NewRR("EXAMPLE. 300 IN A 192.0.2.1")
	if multiset([]dns.RR{a})["example.\t300\tin\ta\t192.0.2.1"] != 1 || len(multiset([]dns.RR{b})) != 1 {
		t.Fatal("records were not normalized")
	}
}

func TestProbesIncludeNegativeAndCNAME(t *testing.T) {
	soa, _ := dns.NewRR("example. 300 IN SOA ns.example. hostmaster.example. 1 60 60 60 60")
	cname, _ := dns.NewRR("alias.example. 300 IN CNAME target.example.")
	result := probes("example.", []dns.RR{soa, cname})
	want := map[string]bool{"alias.example./CNAME": false, "rilldns-nxdomain-probe.example./A": false, "example./AAAA": false}
	for _, probe := range result {
		key := probe.Name + "/" + dns.TypeToString[probe.Type]
		if _, ok := want[key]; ok {
			want[key] = true
		}
	}
	for key, found := range want {
		if !found {
			t.Errorf("missing probe %s", key)
		}
	}
}

func TestProbesIncludeWildcardExpansionAndDelegatedChild(t *testing.T) {
	soa, _ := dns.NewRR("example. 300 IN SOA ns.example. hostmaster.example. 1 60 60 60 60")
	wildcard, _ := dns.NewRR("*.apps.example. 300 IN A 192.0.2.10")
	delegation, _ := dns.NewRR("child.example. 300 IN NS ns.child.example.")
	result := probes("example.", []dns.RR{soa, wildcard, delegation})
	want := map[string]bool{
		"rilldns-wildcard-probe.apps.example./A":    false,
		"rilldns-delegation-probe.child.example./A": false,
	}
	for _, probe := range result {
		key := probe.Name + "/" + dns.TypeToString[probe.Type]
		if _, ok := want[key]; ok {
			want[key] = true
		}
	}
	for key, found := range want {
		if !found {
			t.Errorf("missing probe %s", key)
		}
	}
}

func TestNormalizeResponseIgnoresOrdering(t *testing.T) {
	a, _ := dns.NewRR("a.example. 300 IN A 192.0.2.1")
	b, _ := dns.NewRR("b.example. 300 IN A 192.0.2.2")
	left := &dns.Msg{MsgHdr: dns.MsgHdr{Response: true, Authoritative: true}, Answer: []dns.RR{a, b}}
	right := &dns.Msg{MsgHdr: dns.MsgHdr{Response: true, Authoritative: true}, Answer: []dns.RR{b, a}}
	if normalizeResponse(left) != normalizeResponse(right) {
		t.Fatal("record ordering affected comparison")
	}
}

func TestNormalizeResponseIgnoresAgedTTL(t *testing.T) {
	leftRR, _ := dns.NewRR("a.example. 86400 IN A 192.0.2.1")
	rightRR, _ := dns.NewRR("a.example. 3600 IN A 192.0.2.1")
	left := &dns.Msg{MsgHdr: dns.MsgHdr{Response: true, Authoritative: true}, Answer: []dns.RR{leftRR}}
	right := &dns.Msg{MsgHdr: dns.MsgHdr{Response: true, Authoritative: true}, Answer: []dns.RR{rightRR}}
	if normalizeResponse(left) != normalizeResponse(right) {
		t.Fatal("cache-aged TTL affected behavioral comparison")
	}
}

func TestNormalizeResponseComparesReferralNSAndGlue(t *testing.T) {
	ns, _ := dns.NewRR("child.example. 300 IN NS ns.child.example.")
	glue, _ := dns.NewRR("ns.child.example. 300 IN A 192.0.2.53")
	left := &dns.Msg{MsgHdr: dns.MsgHdr{Response: true}, Ns: []dns.RR{ns}, Extra: []dns.RR{glue}}
	right := &dns.Msg{MsgHdr: dns.MsgHdr{Response: true}, Ns: []dns.RR{ns}}
	if normalizeResponse(left) == normalizeResponse(right) {
		t.Fatal("referral glue difference was ignored")
	}
}
