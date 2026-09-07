package cloudflare

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestApplyRequiresConfirmation(t *testing.T) {
	client, _ := newClient("https://example.invalid", "secret", nil)
	_, err := client.ApplyChanges(context.Background(), "example.com", ApplyRequest{})
	if err != ErrConfirmationRequired {
		t.Fatalf("error = %v", err)
	}
}

func TestApplyBatchesAndVerifies(t *testing.T) {
	current := []Record{{ID: "old", Name: "www.example.com", Type: "A", Content: "192.0.2.1", TTL: 300}}
	var batches int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/zones":
			_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"zone-id","name":"example.com","name_servers":["ns.example"]}]}`))
		case r.URL.Path == "/zones/zone-id/dns_records" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": current})
		case r.URL.Path == "/zones/zone-id/dns_records/batch" && r.Method == http.MethodPost:
			batches++
			var body batchRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if len(body.Patches) != 1 || body.Patches[0].ID != "old" {
				t.Fatalf("batch = %+v", body)
			}
			current[0].TTL = body.Patches[0].TTL
			_, _ = w.Write([]byte(`{"success":true,"result":{}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, _ := newClient(server.URL, "secret", server.Client())
	client.dnsVerifier = func(context.Context, string, Plan, time.Duration) error { return nil }
	initial, err := client.ListRecords(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.ApplyChanges(context.Background(), "example.com", ApplyRequest{
		ExpectedRevision: initial.Revision,
		Confirm:          true,
		Changes:          []Change{{Action: "upsert", Name: "www", Type: "A", TTL: 600, Records: []string{"192.0.2.1"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if batches != 1 || !result.Accepted || !result.APIVerified || !result.DNSVerified || result.Revision == initial.Revision {
		t.Fatalf("result = %+v batches=%d", result, batches)
	}
}
