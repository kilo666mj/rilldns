package api

import (
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

const testAudit = `{"timestamp":"2026-10-01T00:00:00Z","actor":"mcp:apply","request_id":"1","zone":"example.test.","serial":1}
not json
{"timestamp":"2026-10-01T00:01:00Z","actor":"operator","request_id":"2","provider":"cloudflare","zone":"example.net","outcome":"applied"}
{"timestamp":"2026-10-01T00:02:00Z","actor":"operator","request_id":"3","zone":"example.test.","serial":2}

{"timestamp":"2026-10-01T00:03:00Z","actor":"mcp:apply","request_id":"4","zone":"other.test.","serial":5}
`

func auditHandler(t *testing.T, content string) http.Handler {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if content != "" {
		if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	server := New(zones.NewStore(t.TempDir(), "", nil), slog.New(slog.NewTextHandler(io.Discard, nil)), true)
	server.SetAuditPath(path)
	return server.Handler()
}

func auditRequestIDs(t *testing.T, handler http.Handler, query string) ([]string, int) {
	t.Helper()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/audit"+query, nil))
	if response.Code != http.StatusOK {
		t.Fatalf("GET %s status %d: %s", query, response.Code, response.Body.String())
	}
	var body struct {
		Events []struct {
			RequestID string `json:"request_id"`
		} `json:"events"`
		Skipped int `json:"skipped_lines"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	ids := make([]string, len(body.Events))
	for i, event := range body.Events {
		ids[i] = event.RequestID
	}
	return ids, body.Skipped
}

func TestAuditListsNewestFirstWithFilters(t *testing.T) {
	handler := auditHandler(t, testAudit)
	cases := map[string]string{
		"":                                  "4,3,2,1",
		"?limit=2":                          "4,3",
		"?limit=1":                          "4",
		"?zone=EXAMPLE.TEST":                "3,1",
		"?zone=example.net.":                "2",
		"?provider=cloudflare":              "2",
		"?provider=rilldns":                 "4,3,1",
		"?actor=mcp:apply":                  "4,1",
		"?actor=operator&zone=example.test": "3",
	}
	for query, want := range cases {
		ids, skipped := auditRequestIDs(t, handler, query)
		if got := strings.Join(ids, ","); got != want || skipped != 1 {
			t.Errorf("%q: ids %s skipped %d, want %s skipped 1", query, got, skipped, want)
		}
	}
}

func TestAuditRejectsBadParametersAndToleratesMissingLog(t *testing.T) {
	handler := auditHandler(t, testAudit)
	for _, query := range []string{"?limit=0", "?limit=501", "?limit=x", "?provider=route53"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/audit"+query, nil))
		if response.Code != http.StatusBadRequest {
			t.Errorf("%s status %d", query, response.Code)
		}
	}
	if ids, _ := auditRequestIDs(t, auditHandler(t, ""), ""); len(ids) != 0 {
		t.Fatalf("missing log returned %v", ids)
	}
}
