package main

import (
	"github.com/kilo666mj/rilldns/internal/refreshstatus"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestParseRemoteURLRequiresHTTPS(t *testing.T) {
	for _, raw := range []string{"http://example.test/list", "file:///etc/passwd", "https://user:pass@example.test/list"} {
		if _, err := parseRemoteURL(raw); err == nil {
			t.Errorf("accepted unsafe URL %q", raw)
		}
	}
	if _, err := parseRemoteURL("https://example.test/list"); err != nil {
		t.Fatalf("rejected HTTPS URL: %v", err)
	}
}

func TestParseConfigURLAllowsOnlyPrivateHTTP(t *testing.T) {
	for _, raw := range []string{"http://192.168.0.10:18053/config", "http://127.0.0.1/config", "http://[fd00::1]/config"} {
		if _, err := parseConfigURL(raw); err != nil {
			t.Errorf("rejected private config URL %q: %v", raw, err)
		}
	}
	for _, raw := range []string{"http://example.test/config", "http://8.8.8.8/config", "http://user@192.168.0.10/config"} {
		if _, err := parseConfigURL(raw); err == nil {
			t.Errorf("accepted unsafe config URL %q", raw)
		}
	}
}

func TestLoadBlocklistStatusPreservesLastKnownGoodMetadata(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/status.json"
	lastSuccess := time.Date(2026, 8, 13, 16, 19, 13, 0, time.UTC)
	content := `{"kind":"blocklists","success":true,"last_success":"2026-08-13T16:19:13Z","domains":271407,"sources":2,"sha256":"abc"}`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	got := loadBlocklistStatus(path)
	want := refreshstatus.Status{LastSuccess: lastSuccess, Domains: 271407, Sources: 2, SHA256: "abc"}
	if !got.LastSuccess.Equal(want.LastSuccess) || got.Domains != want.Domains || got.Sources != want.Sources || got.SHA256 != want.SHA256 {
		t.Fatalf("loaded status = %+v, want last-known-good metadata %+v", got, want)
	}
}

func TestRedirectPolicyRejectsDowngrade(t *testing.T) {
	client := &http.Client{CheckRedirect: func(request *http.Request, _ []*http.Request) error {
		return validateRemoteURL(request.URL)
	}}
	request, _ := http.NewRequest(http.MethodGet, "http://example.test/list", nil)
	if err := client.CheckRedirect(request, nil); err == nil {
		t.Fatal("accepted redirect downgrade to HTTP")
	}
}
