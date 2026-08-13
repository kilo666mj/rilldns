package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReconcileProposesOnlyUnambiguousNames(t *testing.T) {
	directory := t.TempDir()
	forward := filepath.Join(directory, "example.zone")
	reverse := filepath.Join(directory, "reverse.zone")
	writeTestFile(t, forward, `$ORIGIN example.test.
@ IN SOA ns.example.test. hostmaster.example.test. 1 60 60 60 60
@ IN NS ns.example.test.
one IN A 192.0.2.20
alias IN A 192.0.2.25
other IN A 192.0.2.25
wrong IN A 192.0.2.31
`)
	writeTestFile(t, reverse, `$ORIGIN 2.0.192.in-addr.arpa.
@ IN SOA ns.example.test. hostmaster.example.test. 1 60 60 60 60
@ IN NS ns.example.test.
30 IN PTR wrong.example.test.
`)
	report, err := reconcile([]string{forward}, reverse, "192.0.2.0/24", Policy{})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Proposals) != 2 || report.Proposals[0].IP != "192.0.2.20" || report.Proposals[0].Name != "one.example.test." || report.Proposals[1].IP != "192.0.2.31" {
		t.Fatalf("unexpected proposals: %+v", report.Proposals)
	}
	if len(report.Findings) != 2 {
		t.Fatalf("got findings: %+v", report.Findings)
	}
}

func TestReverseIPv4(t *testing.T) {
	if got := reverseIPv4("10.2.0.192.in-addr.arpa."); got != "192.0.2.10" {
		t.Fatalf("got %q", got)
	}
}

func TestReconcileDoesNotProposeSharedName(t *testing.T) {
	directory := t.TempDir()
	forward := filepath.Join(directory, "forward.zone")
	reverse := filepath.Join(directory, "reverse.zone")
	writeTestFile(t, forward, "$ORIGIN example.test.\n@ IN SOA ns.example.test. hostmaster.example.test. 1 60 60 60 60\n@ IN NS ns.example.test.\npool IN A 192.0.2.20\npool IN A 192.0.2.11\n")
	writeTestFile(t, reverse, "$ORIGIN 2.0.192.in-addr.arpa.\n@ IN SOA ns.example.test. hostmaster.example.test. 1 60 60 60 60\n@ IN NS ns.example.test.\n")
	report, err := reconcile([]string{forward}, reverse, "192.0.2.0/24", Policy{})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Proposals) != 0 || len(report.Findings) != 2 || report.Findings[0].Kind != "missing_ptr_shared_name" {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestReconcilePTRPolicy(t *testing.T) {
	directory := t.TempDir()
	forward := filepath.Join(directory, "forward.zone")
	reverse := filepath.Join(directory, "reverse.zone")
	writeTestFile(t, forward, "$ORIGIN lab.example.\n@ IN SOA ns.lab.example. hostmaster.lab.example. 1 60 60 60 60\n@ IN NS ns.lab.example.\nhost-b IN A 192.0.2.4\nhost-a IN A 192.0.2.98\n")
	writeTestFile(t, reverse, "$ORIGIN 2.0.192.in-addr.arpa.\n@ IN SOA ns.example.test. hostmaster.example.test. 1 60 60 60 60\n@ IN NS ns.example.test.\n")
	policy := Policy{ExcludedSuffixes: []string{"lab.example."}, AllowedNames: map[string]struct{}{"host-a.lab.example.": {}}}
	report, err := reconcile([]string{forward}, reverse, "192.0.2.0/24", policy)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Proposals) != 1 || report.Proposals[0].Name != "host-a.lab.example." {
		t.Fatalf("unexpected proposals: %+v", report.Proposals)
	}
	if len(report.Findings) != 1 || report.Findings[0].Kind != "missing_ptr_no_allowed_name" {
		t.Fatalf("unexpected findings: %+v", report.Findings)
	}
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
