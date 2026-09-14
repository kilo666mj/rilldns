package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/kilo666mj/rilldns/internal/zones"
)

func TestQueryAnalyticsProxiesOnlySupportedFilters(t *testing.T) {
	var received url.Values
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		received = request.URL.Query()
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"enabled":true,"mode":"statistics","queries":42}`))
	}))
	defer upstream.Close()

	server := New(zones.NewStore(t.TempDir(), "", nil), slog.New(slog.NewTextHandler(io.Discard, nil)), true)
	server.SetTelemetryAnalyticsSource(upstream.URL + "/analytics")
	request := httptest.NewRequest(http.MethodGet, "/v1/query-analytics?range=24h&limit=5&recent=20&unexpected=value", nil)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if received.Get("range") != "24h" || received.Get("limit") != "5" || received.Get("recent") != "20" || received.Has("unexpected") {
		t.Fatalf("upstream query = %v", received)
	}
	var payload map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["mode"] != "statistics" || payload["queries"] != float64(42) {
		t.Fatalf("payload = %#v", payload)
	}
}

func TestQueryAnalyticsReportsUnconfiguredSource(t *testing.T) {
	server := New(zones.NewStore(t.TempDir(), "", nil), slog.New(slog.NewTextHandler(io.Discard, nil)), true)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/query-analytics", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}
