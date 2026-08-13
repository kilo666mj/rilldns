package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kilo666mj/rilldns/internal/zones"
)

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
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(zones.NewStore(directory, "", nil), logger, false).Handler()
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
