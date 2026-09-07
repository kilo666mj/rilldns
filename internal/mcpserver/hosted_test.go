package mcpserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kilo666mj/rilldns/internal/controlclient"
)

func TestHostedRequiresBearerToken(t *testing.T) {
	api, err := controlclient.New("http://127.0.0.1:8053")
	if err != nil {
		t.Fatal(err)
	}
	handler, err := Hosted(api, "127.0.0.1:53", "secret")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{}`))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}
