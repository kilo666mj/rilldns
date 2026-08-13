package webui

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kilo666mj/oidcrp"
)

func testOIDCConfig() OIDCConfig {
	return OIDCConfig{
		Issuer: "https://id.example", ClientID: "rilldns", RedirectURL: "https://dns.example/api/auth/callback",
		AllowedSubjects: []string{"subject-1"},
		SessionKey:      base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")),
	}
}

func TestOIDCConfigurationFailsClosed(t *testing.T) {
	config := testOIDCConfig()
	config.AllowedSubjects = nil
	if _, err := New(http.NotFoundHandler(), config); err == nil || !strings.Contains(err.Error(), "allowlist") {
		t.Fatalf("empty allowlist error = %v", err)
	}
	config.AllowedSubjects = []string{"subject-1"}
	config.RedirectURL = "http://dns.example/api/auth/callback"
	if _, err := New(http.NotFoundHandler(), config); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("insecure redirect error = %v", err)
	}
}

func TestBrowserMutationsRequireSameOrigin(t *testing.T) {
	handler, err := New(http.NotFoundHandler(), testOIDCConfig())
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("missing Origin status = %d", response.Code)
	}
	request = httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	request.Header.Set("Origin", "https://dns.example")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusFound {
		t.Fatalf("same-origin status = %d", response.Code)
	}
}

func TestEncryptedSessionRoundTripAndTamperRejection(t *testing.T) {
	auth, err := newAuth(testOIDCConfig())
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "https://dns.example/", nil)
	if err := auth.Issue(response, request, oidcrp.Identity{Subject: "subject-1", Email: "operator@example.test"}); err != nil {
		t.Fatal(err)
	}
	cookie := response.Result().Cookies()[0]
	request.AddCookie(cookie)
	if !auth.Valid(request) || auth.actor(request) != "oidc:operator@example.test" {
		t.Fatal("issued session was not valid")
	}
	cookie.Value = cookie.Value[:len(cookie.Value)-1] + "A"
	tampered := httptest.NewRequest(http.MethodGet, "https://dns.example/", nil)
	tampered.AddCookie(cookie)
	if auth.Valid(tampered) {
		t.Fatal("tampered session was accepted")
	}
}

func TestUIProtectsAPIAndLeavesHealthPublic(t *testing.T) {
	backend := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusTeapot) })
	handler, err := New(backend, testOIDCConfig())
	if err != nil {
		t.Fatal(err)
	}
	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if health.Code != http.StatusOK || !strings.Contains(health.Body.String(), "ok") {
		t.Fatalf("health response: %d %s", health.Code, health.Body.String())
	}
	protected := httptest.NewRecorder()
	handler.ServeHTTP(protected, httptest.NewRequest(http.MethodGet, "/v1/zones", nil))
	if protected.Code != http.StatusUnauthorized {
		t.Fatalf("protected API status = %d", protected.Code)
	}
	if protected.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("security headers missing")
	}
}
