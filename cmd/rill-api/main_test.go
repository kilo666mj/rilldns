package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLoopbackAPIURL(t *testing.T) {
	t.Parallel()
	for input, want := range map[string]string{
		"0.0.0.0:8053": "http://127.0.0.1:8053",
		":8053":        "http://127.0.0.1:8053",
		"127.0.0.1:9":  "http://127.0.0.1:9",
	} {
		if got := loopbackAPIURL(input); got != want {
			t.Errorf("loopbackAPIURL(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestMountHostedMCP(t *testing.T) {
	fallback := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	hosted := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	handler := mountHostedMCP(fallback, hosted)

	mcpResponse := httptest.NewRecorder()
	handler.ServeHTTP(mcpResponse, httptest.NewRequest(http.MethodPost, "/mcp", nil))
	if mcpResponse.Code != http.StatusNoContent {
		t.Fatalf("POST /mcp status = %d", mcpResponse.Code)
	}
	fallbackResponse := httptest.NewRecorder()
	handler.ServeHTTP(fallbackResponse, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if fallbackResponse.Code != http.StatusTeapot {
		t.Fatalf("fallback status = %d", fallbackResponse.Code)
	}
}
