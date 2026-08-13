package main

import (
	"net/http"
	"testing"
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

func TestRedirectPolicyRejectsDowngrade(t *testing.T) {
	client := &http.Client{CheckRedirect: func(request *http.Request, _ []*http.Request) error {
		return validateRemoteURL(request.URL)
	}}
	request, _ := http.NewRequest(http.MethodGet, "http://example.test/list", nil)
	if err := client.CheckRedirect(request, nil); err == nil {
		t.Fatal("accepted redirect downgrade to HTTP")
	}
}
