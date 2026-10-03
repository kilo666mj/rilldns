package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIdempotencyKeyReplaysCommittedChange(t *testing.T) {
	handler := testHandler(t)
	revision := currentETag(t, handler)
	body := `{"changes":[{"action":"upsert","name":"retry","type":"A","ttl":60,"records":["192.0.2.30"]}]}`
	send := func(payload string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/v1/zones/example.test/changes", strings.NewReader(payload))
		request.Header.Set("If-Match", revision)
		request.Header.Set("Idempotency-Key", "change-1")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	first := send(body)
	if first.Code != http.StatusOK || first.Header().Get("Idempotent-Replayed") != "" {
		t.Fatalf("first status %d: %s", first.Code, first.Body.String())
	}
	retry := send(body)
	if retry.Code != http.StatusOK || retry.Header().Get("Idempotent-Replayed") != "true" || retry.Body.String() != first.Body.String() || retry.Header().Get("ETag") != first.Header().Get("ETag") {
		t.Fatalf("retry status %d replayed=%q: %s", retry.Code, retry.Header().Get("Idempotent-Replayed"), retry.Body.String())
	}
	if current := currentETag(t, handler); current != first.Header().Get("ETag") {
		t.Fatalf("zone revision %s after retry, want %s (change applied twice?)", current, first.Header().Get("ETag"))
	}
	if reused := send(strings.Replace(body, "192.0.2.30", "192.0.2.31", 1)); reused.Code != http.StatusUnprocessableEntity {
		t.Fatalf("reused key status %d: %s", reused.Code, reused.Body.String())
	}
}

func TestIdempotencyKeyValidationAndPassthrough(t *testing.T) {
	handler := testHandler(t)
	request := httptest.NewRequest(http.MethodPost, "/v1/zones/example.test/changes", strings.NewReader(`{}`))
	request.Header.Set("Idempotency-Key", "has space")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid key status %d", response.Code)
	}
	for range 2 {
		request = httptest.NewRequest(http.MethodPost, "/v1/zones/example.test/changes", strings.NewReader(`{"changes":[]}`))
		response = httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Header().Get("Idempotent-Replayed") != "" {
			t.Fatal("a request without a key was replayed")
		}
	}
}

func TestIdempotencyStorePersistsAndSkipsServerErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "idempotency.json")
	store, err := NewIdempotencyStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, state := store.begin("ok", "fp"); state != idempotencyNew {
		t.Fatalf("state = %v", state)
	}
	if _, state := store.begin("ok", "fp"); state != idempotencyInFlight {
		t.Fatalf("concurrent state = %v", state)
	}
	if err := store.finish("ok", "fp", http.StatusOK, []byte(`{"done":true}`), `"rev"`); err != nil {
		t.Fatal(err)
	}
	store.begin("failed", "fp")
	if err := store.finish("failed", "fp", http.StatusInternalServerError, []byte(`{}`), ""); err != nil {
		t.Fatal(err)
	}

	reloaded, err := NewIdempotencyStore(path)
	if err != nil {
		t.Fatal(err)
	}
	entry, state := reloaded.begin("ok", "fp")
	if state != idempotencyReplay || entry.Status != http.StatusOK || string(entry.Body) != `{"done":true}` || entry.ETag != `"rev"` {
		t.Fatalf("reloaded state %v entry %+v", state, entry)
	}
	if _, state := reloaded.begin("failed", "fp"); state != idempotencyNew {
		t.Fatalf("server error was retained: state %v", state)
	}

	reloaded.now = func() time.Time { return time.Now().Add(idempotencyTTL + time.Minute) }
	if _, state := reloaded.begin("ok", "fp"); state != idempotencyNew {
		t.Fatalf("expired entry state %v", state)
	}
}

func TestIdempotencyStoreIsBounded(t *testing.T) {
	store, _ := NewIdempotencyStore("")
	base := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	for i := range idempotencyMaxEntries + 5 {
		store.now = func() time.Time { return base.Add(time.Duration(i) * time.Second) }
		key := "k" + string(rune('a'+i%26)) + time.Duration(i).String()
		store.begin(key, "fp")
		if err := store.finish(key, "fp", http.StatusOK, nil, ""); err != nil {
			t.Fatal(err)
		}
	}
	if len(store.entries) != idempotencyMaxEntries {
		t.Fatalf("entries = %d", len(store.entries))
	}
}

func currentETag(t *testing.T, handler http.Handler) string {
	t.Helper()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/zones/example.test/rrsets", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("GET status %d", response.Code)
	}
	return response.Header().Get("ETag")
}

func TestIdempotencyKeyReplaysRollback(t *testing.T) {
	handler := testHandler(t)
	original := currentETag(t, handler)
	change := httptest.NewRequest(http.MethodPost, "/v1/zones/example.test/changes", strings.NewReader(`{"changes":[{"action":"delete","name":"www","type":"A"}]}`))
	change.Header.Set("If-Match", original)
	changed := httptest.NewRecorder()
	handler.ServeHTTP(changed, change)
	if changed.Code != http.StatusOK {
		t.Fatalf("change status %d: %s", changed.Code, changed.Body.String())
	}
	body := `{"target_revision":"` + strings.Trim(original, `"`) + `"}`
	rollback := func() *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/v1/zones/example.test/rollback", strings.NewReader(body))
		request.Header.Set("If-Match", changed.Header().Get("ETag"))
		request.Header.Set("Idempotency-Key", "rollback-1")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	first, retry := rollback(), rollback()
	if first.Code != http.StatusOK || retry.Code != http.StatusOK || retry.Header().Get("Idempotent-Replayed") != "true" || retry.Body.String() != first.Body.String() {
		t.Fatalf("first %d, retry %d replayed=%q: %s", first.Code, retry.Code, retry.Header().Get("Idempotent-Replayed"), retry.Body.String())
	}
	if current := currentETag(t, handler); current != first.Header().Get("ETag") {
		t.Fatalf("zone revision %s, want %s", current, first.Header().Get("ETag"))
	}
}
