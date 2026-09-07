package cloudflare

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestListRecordsPaginatesNormalizesAndHashes(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if got := r.Header.Get("Authorization"); got != "Bearer secret" {
			t.Fatalf("authorization = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/zones" {
			_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"zone-id","name":"example.com"}]}`))
			return
		}
		if r.URL.Query().Get("page") == "1" {
			_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"b","name":"WWW.Example.COM.","type":"a","content":" 192.0.2.2 ","ttl":300,"proxied":true,"tags":["two","one"]}],"result_info":{"page":1,"total_pages":2}}`))
			return
		}
		_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"a","name":"example.com","type":"MX","content":"mail.example.com","ttl":300,"priority":10}],"result_info":{"page":2,"total_pages":2}}`))
	}))
	defer server.Close()
	client, err := newClient(server.URL, " secret ", server.Client())
	if err != nil {
		t.Fatal(err)
	}

	got, err := client.ListRecords(context.Background(), "Example.COM.")
	if err != nil {
		t.Fatal(err)
	}
	if requests != 3 || got.Zone != "example.com" || len(got.Records) != 2 {
		t.Fatalf("unexpected result: %+v (requests %d)", got, requests)
	}
	if got.Records[1].Name != "www.example.com" || got.Records[1].Type != "A" || got.Records[1].Tags[0] != "one" {
		t.Fatalf("record not normalized: %+v", got.Records[1])
	}
	if len(got.Revision) != 64 {
		t.Fatalf("revision = %q", got.Revision)
	}

	again, err := client.ListRecords(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if again.Revision != got.Revision {
		t.Fatalf("unstable revision: %s != %s", again.Revision, got.Revision)
	}
}

func TestListRecordsRejectsCrossZoneData(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "dns_records") {
			_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"x","name":"notexample.com","type":"A","content":"192.0.2.1","ttl":300}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"zone-id","name":"example.com"}]}`))
	}))
	defer server.Close()
	client, _ := newClient(server.URL, "secret", server.Client())
	_, err := client.ListRecords(context.Background(), "example.com")
	if err == nil || !strings.Contains(err.Error(), "outside configured zone") {
		t.Fatalf("error = %v", err)
	}
}

func TestAPIErrorDoesNotExposeToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":9109,"message":"Invalid access token"}]}`))
	}))
	defer server.Close()
	client, _ := newClient(server.URL, "super-secret", server.Client())
	_, err := client.ListRecords(context.Background(), "example.com")
	if err == nil || !strings.Contains(err.Error(), "9109") || strings.Contains(err.Error(), "super-secret") {
		t.Fatalf("error = %v", err)
	}
}
