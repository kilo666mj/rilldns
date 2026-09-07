package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kilo666mj/rilldns/internal/cloudflare"
	"github.com/kilo666mj/rilldns/internal/zones"
)

func writeHAStatusFiles(t *testing.T, directory string) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339)
	files := map[string]string{
		"zones.json":        `{"kind":"zones","success":true,"last_attempt":"` + now + `","last_success":"` + now + `","zones":[{"name":"example.test","serial":2026081601,"records":3}]}`,
		"blocklists.json":   `{"kind":"blocklists","success":true,"last_attempt":"` + now + `","last_success":"` + now + `","domains":100000}`,
		"differential.json": `{"kind":"differential","success":true,"last_attempt":"` + now + `","last_success":"` + now + `","checked_zones":1,"queries":10}`,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0o640); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHAStatusReportsRolePeerAndReplication(t *testing.T) {
	statusDir := t.TempDir()
	writeHAStatusFiles(t, statusDir)
	peer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/healthz" {
			writer.WriteHeader(http.StatusOK)
			return
		}
		if request.Header.Get("X-RillDNS-HA-Peer") != "1" {
			t.Errorf("peer status request missing recursion guard header")
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"node":"dns-a","role":"active","writable":true,"vip_owned":true,"healthy":true,"replication_healthy":true,"zones":{"last_success":"`+time.Now().UTC().Format(time.RFC3339)+`","zones":[{"name":"example.test"}]}}`)
	}))
	defer peer.Close()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := NewWithStatus(zones.NewStore(t.TempDir(), "", nil), logger, true, statusDir)
	server.SetHA("dns-b", "standby", "dns-a", peer.URL+"/healthz", peer.URL+"/v1/status/ha", "192.0.2.53")
	request := httptest.NewRequest(http.MethodGet, "/v1/status/ha", nil)
	response := httptest.NewRecorder()
	server.MetricsHandler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, expected := range []string{`"node":"dns-b"`, `"role":"standby"`, `"writable":false`, `"reachable":true`, `"name":"dns-a"`, `"role":"active"`, `"vip_owned":true`, `"zones":1`, `"replication_healthy":true`} {
		if !strings.Contains(body, expected) {
			t.Fatalf("missing %s in %s", expected, body)
		}
	}
}

func TestMetricsReportsDifferentialLastAttempt(t *testing.T) {
	statusDir := t.TempDir()
	writeHAStatusFiles(t, statusDir)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := NewWithStatus(zones.NewStore(t.TempDir(), "", nil), logger, true, statusDir)
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	response := httptest.NewRecorder()
	server.MetricsHandler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status %d: %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "rilldns_differential_last_attempt_seconds ") {
		t.Fatalf("missing differential last-attempt metric in %s", response.Body.String())
	}
}

const apiTestZone = `$ORIGIN example.test.
@ 300 IN SOA ns1.example.test. hostmaster.example.test. 2026081101 300 60 86400 60
@ 300 IN NS ns1.example.test.
ns1 300 IN A 192.0.2.53
`

func testHandler(t *testing.T) http.Handler {
	t.Helper()
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "example.test.zone"), []byte(apiTestZone), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, ".roles.json"), []byte("{\"roles\":{\"example.test.\":\"primary\"}}\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(zones.NewStore(directory, "", nil), logger, false).Handler()
}

type fakeCloudflare struct {
	result cloudflare.ZoneRecords
	err    error
}

func (f fakeCloudflare) ListRecords(_ context.Context, zone string) (cloudflare.ZoneRecords, error) {
	result := f.result
	result.Zone = zone
	return result, f.err
}

func (f fakeCloudflare) PlanChanges(_ context.Context, zone string, request cloudflare.PlanRequest) (cloudflare.Plan, error) {
	if request.ExpectedRevision != f.result.Revision {
		return cloudflare.Plan{}, cloudflare.ErrRevisionMismatch
	}
	return cloudflare.Plan{Zone: zone, DryRun: true, PreviousRevision: request.ExpectedRevision, Changes: request.Changes}, f.err
}

func (f fakeCloudflare) ApplyChanges(_ context.Context, zone string, request cloudflare.ApplyRequest) (cloudflare.ApplyResult, error) {
	if !request.Confirm {
		return cloudflare.ApplyResult{}, cloudflare.ErrConfirmationRequired
	}
	if request.ExpectedRevision != f.result.Revision {
		return cloudflare.ApplyResult{}, cloudflare.ErrRevisionMismatch
	}
	return cloudflare.ApplyResult{Zone: zone, PreviousRevision: request.ExpectedRevision, Revision: "next", Changes: request.Changes, Accepted: true, APIVerified: true, RequestID: request.RequestID}, f.err
}

func TestCloudflareReadEndpointsEnforceAllowlist(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "example.test.zone"), []byte(apiTestZone), 0o640); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := New(zones.NewStore(directory, "", nil), logger, false)
	server.SetCloudflare(fakeCloudflare{result: cloudflare.ZoneRecords{Revision: "revision", Records: []cloudflare.Record{{ID: "record", Name: "www.example.com", Type: "A", Content: "192.0.2.1", TTL: 300}}}}, []string{"example.com"})
	handler := server.Handler()

	request := httptest.NewRequest(http.MethodGet, "/v1/providers/cloudflare/zones", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"name":"example.com"`) {
		t.Fatalf("zones status %d: %s", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodGet, "/v1/providers/cloudflare/zones/example.com/records", nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"revision"` {
		t.Fatalf("records status %d etag %q: %s", response.Code, response.Header().Get("ETag"), response.Body.String())
	}

	request = httptest.NewRequest(http.MethodGet, "/v1/providers/cloudflare/zones/other.example/records", nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("unconfigured status %d: %s", response.Code, response.Body.String())
	}
}

func TestCloudflarePlanEndpointUsesRevision(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "example.test.zone"), []byte(apiTestZone), 0o640); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := New(zones.NewStore(directory, "", nil), logger, false)
	server.SetCloudflare(fakeCloudflare{result: cloudflare.ZoneRecords{Revision: "current"}}, []string{"example.com"})
	body := []byte(`{"changes":[{"action":"upsert","name":"www","type":"A","ttl":300,"records":["192.0.2.1"]}]}`)
	request := httptest.NewRequest(http.MethodPost, "/v1/providers/cloudflare/zones/example.com/plans", bytes.NewReader(body))
	request.Header.Set("If-Match", `"current"`)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"dry_run":true`) {
		t.Fatalf("plan status %d: %s", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodPost, "/v1/providers/cloudflare/zones/example.com/plans", bytes.NewReader(body))
	request.Header.Set("If-Match", `"stale"`)
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale status %d: %s", response.Code, response.Body.String())
	}
}

func TestReadOnlyRejectsMutation(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "example.test.zone"), []byte(apiTestZone), 0o640); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := New(zones.NewStore(directory, "", nil), logger, true).Handler()
	request := httptest.NewRequest(http.MethodPost, "/v1/zones/example.test/changes", bytes.NewReader([]byte(`{}`)))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status %d: %s", response.Code, response.Body.String())
	}
}

func TestGetZoneAndDryRun(t *testing.T) {
	handler := testHandler(t)
	request := httptest.NewRequest(http.MethodGet, "/v1/zones/example.test/rrsets", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("GET status %d: %s", response.Code, response.Body.String())
	}
	etag := response.Header().Get("ETag")
	if etag == "" {
		t.Fatal("missing ETag")
	}

	payload := map[string]any{
		"dry_run": true,
		"changes": []map[string]any{{
			"action": "upsert", "name": "www", "type": "A", "ttl": 60, "records": []string{"192.0.2.10"},
		}},
	}
	body, _ := json.Marshal(payload)
	request = httptest.NewRequest(http.MethodPost, "/v1/zones/example.test/changes", bytes.NewReader(body))
	request.Header.Set("If-Match", etag)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("POST status %d: %s", response.Code, response.Body.String())
	}
	var result zones.ChangeResult
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.DryRun || result.Published || result.Serial <= result.PreviousSerial {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestMutationRequiresRevision(t *testing.T) {
	handler := testHandler(t)
	body := []byte(`{"changes":[{"action":"delete","name":"ns1","type":"A"}]}`)
	request := httptest.NewRequest(http.MethodPost, "/v1/zones/example.test/changes", bytes.NewReader(body))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusPreconditionFailed {
		t.Fatalf("status %d: %s", response.Code, response.Body.String())
	}
}

func TestZoneLifecycleAPI(t *testing.T) {
	handler := testHandler(t)
	zoneText := strings.ReplaceAll(apiTestZone, "example.test", "created.example")
	body, _ := json.Marshal(zones.LifecycleRequest{Role: "primary", ZoneText: zoneText, DryRun: true})
	request := httptest.NewRequest(http.MethodPut, "/v1/zones/created.example", bytes.NewReader(body))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"dry_run":true`) {
		t.Fatalf("dry-run create status %d: %s", response.Code, response.Body.String())
	}
	body, _ = json.Marshal(zones.LifecycleRequest{Role: "primary", ZoneText: zoneText})
	request = httptest.NewRequest(http.MethodPut, "/v1/zones/created.example", bytes.NewReader(body))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("create status %d: %s", response.Code, response.Body.String())
	}
	var created zones.LifecycleResult
	_ = json.Unmarshal(response.Body.Bytes(), &created)
	body, _ = json.Marshal(zones.LifecycleRequest{ExpectedRevision: created.Revision})
	request = httptest.NewRequest(http.MethodDelete, "/v1/zones/created.example", bytes.NewReader(body))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"published":true`) {
		t.Fatalf("delete status %d: %s", response.Code, response.Body.String())
	}
}
