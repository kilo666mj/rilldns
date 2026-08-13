package controlclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kilo666mj/rilldns/internal/zones"
)

func TestClientReadsAndApplies(t *testing.T) {
	var actor string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/v1/zones":
			_, _ = writer.Write([]byte(`{"zones":[{"name":"example.test.","serial":42,"revision":"rev"}]}`))
		case request.Method == http.MethodPost && request.URL.Path == "/v1/zones/example.test/changes":
			actor = request.Header.Get("X-RillDNS-Actor")
			var input zones.ChangeRequest
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
				t.Fatal(err)
			}
			if !input.DryRun || input.ExpectedRevision != "rev" {
				t.Fatalf("unexpected input: %+v", input)
			}
			_, _ = writer.Write([]byte(`{"zone":"example.test.","dry_run":true,"previous_revision":"rev","revision":"next","previous_serial":42,"serial":43}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	listed, err := client.ListZones(context.Background())
	if err != nil || len(listed) != 1 || listed[0].Revision != "rev" {
		t.Fatalf("ListZones = %+v, %v", listed, err)
	}
	result, err := client.Apply(context.Background(), "example.test.", zones.ChangeRequest{
		ExpectedRevision: "rev", DryRun: true,
		Changes: []zones.Change{{Action: "delete", Name: "old", Type: "A"}},
	}, "mcp:plan")
	if err != nil || result.Revision != "next" || actor != "mcp:plan" {
		t.Fatalf("Apply = %+v, %v, actor %q", result, err, actor)
	}
}

func TestClientReturnsAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusPreconditionFailed)
		_, _ = writer.Write([]byte(`{"error":{"message":"zone revision mismatch"}}`))
	}))
	defer server.Close()
	client, _ := New(server.URL)
	_, err := client.GetZone(context.Background(), "example.test")
	if err == nil || !strings.Contains(err.Error(), "zone revision mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}
}
