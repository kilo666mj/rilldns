package mcpserver

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kilo666mj/rilldns/internal/controlclient"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func connectTestMCP(t *testing.T, apiHandler http.Handler) (*mcp.ClientSession, func()) {
	t.Helper()
	apiServer := httptest.NewServer(apiHandler)
	apiClient, err := controlclient.New(apiServer.URL)
	if err != nil {
		apiServer.Close()
		t.Fatal(err)
	}
	server := New(apiClient, "127.0.0.1:1")
	client := mcp.NewClient(&mcp.Implementation{Name: "rilldns-test", Version: "0.1.0"}, nil)
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(context.Background(), serverTransport, nil)
	if err != nil {
		apiServer.Close()
		t.Fatal(err)
	}
	clientSession, err := client.Connect(context.Background(), clientTransport, nil)
	if err != nil {
		_ = serverSession.Close()
		apiServer.Close()
		t.Fatal(err)
	}
	cleanup := func() {
		_ = clientSession.Close()
		_ = serverSession.Close()
		apiServer.Close()
	}
	return clientSession, cleanup
}

func TestListZonesTool(t *testing.T) {
	session, cleanup := connectTestMCP(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/zones" {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"zones":[{"name":"example.test.","serial":42,"revision":"rev"}]}`))
	}))
	defer cleanup()

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "dns_list_zones", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError || !strings.Contains(result.Content[0].(*mcp.TextContent).Text, "example.test") {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestApplyRequiresConfirmationWithoutCallingAPI(t *testing.T) {
	called := false
	session, cleanup := connectTestMCP(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		called = true
		http.Error(writer, "unexpected API call", http.StatusInternalServerError)
	}))
	defer cleanup()

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "dns_apply_changes",
		Arguments: map[string]any{
			"zone": "example.test", "expected_revision": "rev", "confirm": false,
			"changes": []map[string]any{{"action": "delete", "name": "old", "type": "A"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError || called {
		t.Fatalf("result error=%v, API called=%v", result.IsError, called)
	}
}

func TestRefreshBlocklistsTool(t *testing.T) {
	var gotMethod, gotPath, gotActor string
	session, cleanup := connectTestMCP(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		gotMethod, gotPath, gotActor = request.Method, request.URL.Path, request.Header.Get("X-RillDNS-Actor")
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusAccepted)
		_, _ = writer.Write([]byte(`{"requested_at":"2026-10-03T12:00:00Z","actor":"mcp:blocklist-refresh","request_id":"r"}`))
	}))
	defer cleanup()

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "dns_refresh_blocklists", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError || gotMethod != http.MethodPost || gotPath != "/v1/blocklists/refresh" || gotActor != "mcp:blocklist-refresh" {
		t.Fatalf("error=%v %s %s actor=%q", result.IsError, gotMethod, gotPath, gotActor)
	}
}

func TestRollbackToolPreviewsUnlessConfirmed(t *testing.T) {
	var gotPath, gotBody string
	session, cleanup := connectTestMCP(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		gotPath, gotBody = request.URL.Path, string(body)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"zone":"example.test.","rollback_to":"target","dry_run":true}`))
	}))
	defer cleanup()

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "dns_rollback_zone",
		Arguments: map[string]any{"zone": "example.test", "expected_revision": "current", "target_revision": "target", "confirm": false},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError || gotPath != "/v1/zones/example.test/rollback" || !strings.Contains(gotBody, `"dry_run":true`) || !strings.Contains(gotBody, `"target_revision":"target"`) {
		t.Fatalf("result error=%v path=%q body=%s", result.IsError, gotPath, gotBody)
	}
}

func TestListAuditEventsTool(t *testing.T) {
	var gotQuery string
	session, cleanup := connectTestMCP(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		gotQuery = request.URL.RawQuery
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"events":[{"request_id":"1","zone":"example.test.","changes":[{"action":"delete"}]}],"skipped_lines":0}`))
	}))
	defer cleanup()

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "dns_list_audit_events", Arguments: map[string]any{"zone": "example.test", "limit": 5},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError || gotQuery != "limit=5&zone=example.test" {
		t.Fatalf("error=%v query=%q content=%+v", result.IsError, gotQuery, result.Content)
	}
}
