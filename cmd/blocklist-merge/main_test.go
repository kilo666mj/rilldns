package main

import (
	"strings"
	"testing"
)

func TestReadDomains(t *testing.T) {
	input := `
# comment
0.0.0.0 Ads.Example.COM tracker.example.com # trailing comment
127.0.0.1 localhost
plain.example.net
bad_domain
-bad.example
`
	domains := make(map[string]struct{})
	if err := readDomains(strings.NewReader(input), domains); err != nil {
		t.Fatal(err)
	}
	want := []string{"ads.example.com", "tracker.example.com", "plain.example.net"}
	if len(domains) != len(want) {
		t.Fatalf("got %d domains (%v), want %d", len(domains), domains, len(want))
	}
	for _, domain := range want {
		if _, ok := domains[domain]; !ok {
			t.Errorf("missing %q", domain)
		}
	}
}

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		input string
		want  string
		ok    bool
	}{
		{"WWW.Example.COM.", "www.example.com", true},
		{"_service._tcp.example.com", "_service._tcp.example.com", true},
		{"localhost", "", false},
		{"192.0.2.1", "", false},
		{"bad..example", "", false},
	}
	for _, test := range tests {
		got, ok := normalizeDomain(test.input)
		if got != test.want || ok != test.ok {
			t.Errorf("normalizeDomain(%q) = (%q, %v), want (%q, %v)", test.input, got, ok, test.want, test.ok)
		}
	}
}
