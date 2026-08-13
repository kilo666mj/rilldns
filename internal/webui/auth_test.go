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
		SessionKey: base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")),
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
