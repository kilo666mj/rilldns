package zones

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const testZone = `$ORIGIN example.test.
$TTL 300
@ IN SOA ns1.example.test. hostmaster.example.test. 2026081101 300 60 86400 60
@ IN NS ns1.example.test.
ns1 IN A 192.0.2.53
www IN A 192.0.2.10
api IN CNAME www.example.test.
`

type serialVerifier struct {
	got       uint32
	err       error
	notified  string
	absentErr error
}

func (v *serialVerifier) WaitForAbsence(_ context.Context, _ string) error { return v.absentErr }
func (v *serialVerifier) Notify(_ context.Context, zone string) error {
	v.notified = zone
	return nil
}

func (v *serialVerifier) WaitForSerial(_ context.Context, _ string, serial uint32) error {
	v.got = serial
	return v.err
}

func newTestStore(t *testing.T, verifier Verifier) (*Store, string) {
	t.Helper()
	directory := t.TempDir()
	zonePath := filepath.Join(directory, "example.test.zone")
	if err := os.WriteFile(zonePath, []byte(testZone), 0o640); err != nil {
		t.Fatal(err)
	}
	store := NewStore(directory, filepath.Join(directory, "audit.jsonl"), verifier)
	store.now = func() time.Time { return time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC) }
	return store, zonePath
}

func TestGetGroupsRRsets(t *testing.T) {
	store, _ := newTestStore(t, nil)
	zone, err := store.Get("EXAMPLE.TEST")
	if err != nil {
		t.Fatal(err)
	}
	if zone.Name != "example.test." || zone.Serial != 2026081101 {
		t.Fatalf("unexpected zone: %+v", zone)
	}
	if len(zone.RRsets) != 5 {
		t.Fatalf("got %d RRsets, want 5", len(zone.RRsets))
	}
}

func TestApplyDryRunDoesNotWrite(t *testing.T) {
	store, zonePath := newTestStore(t, nil)
	before, err := store.Get("example.test")
	if err != nil {
		t.Fatal(err)
	}
	result, err := store.Apply(context.Background(), before.Name, ChangeRequest{
		ExpectedRevision: before.Revision,
		DryRun:           true,
		Changes:          []Change{{Action: "upsert", Name: "new", Type: "A", TTL: 60, Records: []string{"192.0.2.20"}}},
	}, "test", "dry-1")
	if err != nil {
		t.Fatal(err)
	}
	if result.Published || result.Serial != 2026081102 {
		t.Fatalf("unexpected result: %+v", result)
	}
	content, err := os.ReadFile(zonePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != testZone {
		t.Fatal("dry run changed zone file")
	}
}

func TestApplyPublishesHistoryAndAudit(t *testing.T) {
	verifier := new(serialVerifier)
	store, _ := newTestStore(t, verifier)
	before, _ := store.Get("example.test")
	result, err := store.Apply(context.Background(), before.Name, ChangeRequest{
		ExpectedRevision: before.Revision,
		Changes:          []Change{{Action: "upsert", Name: "www", Type: "A", TTL: 120, Records: []string{"192.0.2.20", "192.0.2.21"}}},
	}, "unit-test", "req-1")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Published || verifier.got != result.Serial || result.Serial != 2026081102 {
		t.Fatalf("unexpected result: %+v verifier serial %d", result, verifier.got)
	}
	after, err := store.Get("example.test")
	if err != nil {
		t.Fatal(err)
	}
	if after.Revision != result.Revision || after.Serial != result.Serial {
		t.Fatalf("published zone does not match result: %+v", after)
	}
	joined := ""
	for _, set := range after.RRsets {
		if set.Name == "www.example.test." && set.Type == "A" {
			joined = strings.Join(set.Records, ",")
		}
	}
	if !strings.Contains(joined, "192.0.2.20") || !strings.Contains(joined, "192.0.2.21") {
		t.Fatalf("new RRset not found: %q", joined)
	}
	historyPath := filepath.Join(store.history, "example.test", before.Revision+".zone")
	if _, err := os.Stat(historyPath); err != nil {
		t.Fatalf("history missing: %v", err)
	}
	audit, err := os.ReadFile(store.audit)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(audit), `"request_id":"req-1"`) {
		t.Fatalf("audit event missing: %s", audit)
	}
}

func TestApplyRejectsStaleRevisionAndCNAMEConflict(t *testing.T) {
	store, _ := newTestStore(t, nil)
	_, err := store.Apply(context.Background(), "example.test", ChangeRequest{
		ExpectedRevision: "stale",
		Changes:          []Change{{Action: "delete", Name: "www", Type: "A"}},
	}, "test", "req")
	if !errors.Is(err, ErrRevisionMismatch) {
		t.Fatalf("got %v, want revision mismatch", err)
	}

	zone, _ := store.Get("example.test")
	_, err = store.Apply(context.Background(), zone.Name, ChangeRequest{
		ExpectedRevision: zone.Revision,
		Changes:          []Change{{Action: "upsert", Name: "api", Type: "A", TTL: 60, Records: []string{"192.0.2.30"}}},
	}, "test", "req")
	if !errors.Is(err, ErrInvalidChange) || !strings.Contains(err.Error(), "CNAME") {
		t.Fatalf("got %v, want CNAME conflict", err)
	}
}

func TestSignedCNAMEIsValid(t *testing.T) {
	zone, _, err := parseZoneText(testZone, "example.test.", "test.zone")
	if err != nil {
		t.Fatal(err)
	}
	rrs := zone.rrs
	cname, _ := dns.NewRR("signed.example.test. 300 IN CNAME www.example.test.")
	rrsig, _ := dns.NewRR("signed.example.test. 300 IN RRSIG CNAME 13 3 300 20260814000000 20260812000000 12345 example.test. AQID")
	rrs = append(rrs, cname, rrsig)
	if err := validate("example.test.", rrs); err != nil {
		t.Fatalf("DNSSEC metadata alongside CNAME was rejected: %v", err)
	}
}

func TestApplyRestoresZoneWhenVerificationFails(t *testing.T) {
	verifier := &serialVerifier{err: errors.New("not served")}
	store, zonePath := newTestStore(t, verifier)
	before, _ := store.Get("example.test")
	_, err := store.Apply(context.Background(), before.Name, ChangeRequest{
		ExpectedRevision: before.Revision,
		Changes:          []Change{{Action: "upsert", Name: "new", Type: "A", TTL: 60, Records: []string{"192.0.2.20"}}},
	}, "test", "req")
	if err == nil || !strings.Contains(err.Error(), "prior zone restored") {
		t.Fatalf("unexpected error: %v", err)
	}
	content, readErr := os.ReadFile(zonePath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(content) != testZone {
		t.Fatal("failed publication did not restore original zone")
	}
}

func TestNextSerial(t *testing.T) {
	now := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
	serial, err := nextSerial(2026081109, now)
	if err != nil || serial != 2026081200 {
		t.Fatalf("nextSerial date advance = %d, %v", serial, err)
	}
	serial, err = nextSerial(2026081299, now)
	if err != nil || serial != 2026081300 {
		t.Fatalf("nextSerial monotonic = %d, %v", serial, err)
	}
}

func TestCreateDryRunPublishRoleAndDelete(t *testing.T) {
	store, _ := newTestStore(t, nil)
	imported := strings.ReplaceAll(testZone, "example.test", "imported.example")
	dry, err := store.Create(context.Background(), "imported.example", LifecycleRequest{Role: "secondary", ZoneText: imported, DryRun: true}, "test", "create-dry")
	if err != nil || dry.Published || !dry.DryRun || dry.Role != "secondary" {
		t.Fatalf("unexpected dry-run result: %+v, %v", dry, err)
	}
	if _, err := store.Get("imported.example"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("dry run created zone: %v", err)
	}
	created, err := store.Create(context.Background(), "imported.example", LifecycleRequest{Role: "secondary", ZoneText: imported}, "test", "create")
	if err != nil || !created.Published {
		t.Fatalf("create result: %+v, %v", created, err)
	}
	zone, err := store.Get("imported.example")
	if err != nil || zone.Role != "secondary" {
		t.Fatalf("created zone: %+v, %v", zone, err)
	}
	_, err = store.Apply(context.Background(), zone.Name, ChangeRequest{ExpectedRevision: zone.Revision, Changes: []Change{{Action: "delete", Name: "www", Type: "A"}}}, "test", "change")
	if !errors.Is(err, ErrReadOnlyZone) {
		t.Fatalf("secondary mutation error = %v", err)
	}
	if _, err := store.Delete(context.Background(), zone.Name, LifecycleRequest{ExpectedRevision: "stale"}, "test", "delete"); !errors.Is(err, ErrRevisionMismatch) {
		t.Fatalf("stale delete error = %v", err)
	}
	deleted, err := store.Delete(context.Background(), zone.Name, LifecycleRequest{ExpectedRevision: zone.Revision}, "test", "delete")
	if err != nil || !deleted.Published {
		t.Fatalf("delete result: %+v, %v", deleted, err)
	}
	if _, err := store.Get(zone.Name); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted zone still exists: %v", err)
	}
}

func TestCreateRejectsOriginMismatchAndRollsBackVerification(t *testing.T) {
	store, _ := newTestStore(t, nil)
	if _, err := store.Create(context.Background(), "other.example", LifecycleRequest{ZoneText: testZone, DryRun: true}, "test", "bad"); !errors.Is(err, ErrInvalidChange) {
		t.Fatalf("origin mismatch error = %v", err)
	}
	store.verifier = &serialVerifier{err: errors.New("not served")}
	imported := strings.ReplaceAll(testZone, "example.test", "new.example")
	if _, err := store.Create(context.Background(), "new.example", LifecycleRequest{ZoneText: imported}, "test", "rollback"); err == nil {
		t.Fatal("verification failure was accepted")
	}
	if _, err := store.Get("new.example"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed create was not rolled back: %v", err)
	}
}
