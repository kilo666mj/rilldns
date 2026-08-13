package secondary

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestNewNormalizesAndRejectsDuplicateZones(t *testing.T) {
	config := testConfig(t)
	config.Zones = []string{"Example", "example."}
	if _, err := New(config); err == nil {
		t.Fatal("duplicate normalized zones were accepted")
	}
	config.Zones = []string{"Example"}
	service, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if service.config.Zones[0] != "example." || service.config.TSIGName != "rilldns-transfer." {
		t.Fatalf("configuration was not normalized: %#v", service.config)
	}
}

func TestPublishCompleteSnapshotAtomically(t *testing.T) {
	service, err := New(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	records := testSnapshot(t, 42)
	if err := service.publish("example.", records); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(service.config.OutputDir, "example.zone")
	serial, err := readSerial(path)
	if err != nil || serial != 42 {
		t.Fatalf("published serial = %d, %v", serial, err)
	}
	data, _ := os.ReadFile(path)
	parser := dns.NewZoneParser(bytes.NewReader(data), "", path)
	soaCount := 0
	for record, ok := parser.Next(); ok; record, ok = parser.Next() {
		if record.Header().Rrtype == dns.TypeSOA {
			soaCount++
		}
	}
	if err := parser.Err(); err != nil || soaCount != 1 {
		t.Fatalf("SOA count = %d, parse error = %v", soaCount, err)
	}
}

func TestPublishRejectsIncompleteSnapshotAndPreservesExisting(t *testing.T) {
	service, err := New(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := service.publish("example.", testSnapshot(t, 41)); err != nil {
		t.Fatal(err)
	}
	if err := service.publish("example.", testSnapshot(t, 42)[:2]); err == nil {
		t.Fatal("incomplete snapshot was accepted")
	}
	serial, _ := readSerial(filepath.Join(service.config.OutputDir, "example.zone"))
	if serial != 41 {
		t.Fatalf("last-good serial changed to %d", serial)
	}
}

func TestRemoteAddressIP(t *testing.T) {
	address := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 53}
	if !remoteAddressIP(address).Equal(net.ParseIP("192.0.2.1")) {
		t.Fatal("remote IP was not parsed")
	}
}

func TestJoinedErrorsIsStableAndDoesNotHideFailures(t *testing.T) {
	errorsByZone := map[string]string{"z.example.": "timeout", "a.example.": "refused"}
	got := joinedErrors(errorsByZone)
	if got != "a.example.: refused; z.example.: timeout" {
		t.Fatalf("joined errors = %q", got)
	}
}

func testConfig(t *testing.T) Config {
	t.Helper()
	directory := t.TempDir()
	return Config{
		Primary: "192.0.2.1:53", Listen: "127.0.0.1:0", Zones: []string{"example."},
		OutputDir: directory, StatusFile: filepath.Join(directory, "status.json"),
		Refresh: time.Hour, Timeout: time.Second, NotifyFrom: net.ParseIP("192.0.2.1"),
		TSIGName: "RILLDNS-TRANSFER", TSIGSecret: "c2VjcmV0",
	}
}

func testSnapshot(t *testing.T, serial uint32) []dns.RR {
	t.Helper()
	values := []string{
		"example. 300 IN SOA ns.example. hostmaster.example. " + strconv.FormatUint(uint64(serial), 10) + " 60 60 60 60",
		"example. 300 IN NS ns.example.",
		"ns.example. 300 IN A 192.0.2.53",
		"example. 300 IN SOA ns.example. hostmaster.example. " + strconv.FormatUint(uint64(serial), 10) + " 60 60 60 60",
	}
	records := make([]dns.RR, 0, len(values))
	for _, value := range values {
		record, err := dns.NewRR(value)
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	return records
}
