package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const (
	idempotencyTTL        = 24 * time.Hour
	idempotencyMaxEntries = 1000
	idempotencyMaxKey     = 255
)

type idempotencyState int

const (
	idempotencyNew idempotencyState = iota
	idempotencyReplay
	idempotencyInFlight
	idempotencyMismatch
)

type idempotencyEntry struct {
	Fingerprint string    `json:"fingerprint"`
	Status      int       `json:"status"`
	Body        []byte    `json:"body"`
	ETag        string    `json:"etag,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// IdempotencyStore remembers the responses to mutating requests that carried an
// Idempotency-Key header so that a client retrying after a lost response gets
// the original result instead of a revision mismatch or a second mutation.
// With a path, completed entries survive API restarts.
type IdempotencyStore struct {
	mu       sync.Mutex
	path     string
	now      func() time.Time
	entries  map[string]idempotencyEntry
	inFlight map[string]string
}

func NewIdempotencyStore(path string) (*IdempotencyStore, error) {
	store := &IdempotencyStore{path: path, now: time.Now, entries: map[string]idempotencyEntry{}, inFlight: map[string]string{}}
	if path == "" {
		return store, nil
	}
	content, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(content, &store.entries); err != nil {
		return nil, err
	}
	store.pruneLocked()
	return store, nil
}

func (s *IdempotencyStore) begin(key, fingerprint string) (idempotencyEntry, idempotencyState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry, ok := s.entries[key]; ok && s.now().Sub(entry.CreatedAt) < idempotencyTTL {
		if entry.Fingerprint != fingerprint {
			return idempotencyEntry{}, idempotencyMismatch
		}
		return entry, idempotencyReplay
	}
	if pending, ok := s.inFlight[key]; ok {
		if pending != fingerprint {
			return idempotencyEntry{}, idempotencyMismatch
		}
		return idempotencyEntry{}, idempotencyInFlight
	}
	s.inFlight[key] = fingerprint
	return idempotencyEntry{}, idempotencyNew
}

// finish records a completed response. Server errors are not recorded, so a
// retry re-executes; the zone revision check still prevents a double apply.
func (s *IdempotencyStore) finish(key, fingerprint string, status int, body []byte, etag string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.inFlight, key)
	if status >= 500 {
		return nil
	}
	s.entries[key] = idempotencyEntry{Fingerprint: fingerprint, Status: status, Body: body, ETag: etag, CreatedAt: s.now().UTC()}
	s.pruneLocked()
	return s.saveLocked()
}

func (s *IdempotencyStore) pruneLocked() {
	now := s.now()
	for key, entry := range s.entries {
		if now.Sub(entry.CreatedAt) >= idempotencyTTL {
			delete(s.entries, key)
		}
	}
	if len(s.entries) <= idempotencyMaxEntries {
		return
	}
	keys := make([]string, 0, len(s.entries))
	for key := range s.entries {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return s.entries[keys[i]].CreatedAt.Before(s.entries[keys[j]].CreatedAt) })
	for _, key := range keys[:len(keys)-idempotencyMaxEntries] {
		delete(s.entries, key)
	}
}

func (s *IdempotencyStore) saveLocked() (err error) {
	if s.path == "" {
		return nil
	}
	content, err := json.Marshal(s.entries)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(s.path), ".idempotency-*")
	if err != nil {
		return err
	}
	// Best effort: after a successful rename the name no longer exists.
	defer func() { _ = os.Remove(temporary.Name()) }()
	if _, err = temporary.Write(content); err == nil {
		err = temporary.Sync()
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(temporary.Name(), s.path)
}

func validIdempotencyKey(key string) bool {
	if len(key) == 0 || len(key) > idempotencyMaxKey {
		return false
	}
	for i := 0; i < len(key); i++ {
		if key[i] < 0x21 || key[i] > 0x7e {
			return false
		}
	}
	return true
}

// idempotent wraps a mutating handler. Requests without an Idempotency-Key
// header are passed through unchanged.
func (s *Server) idempotent(next http.HandlerFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		key := request.Header.Get("Idempotency-Key")
		if key == "" || s.idempotency == nil {
			next(writer, request)
			return
		}
		if !validIdempotencyKey(key) {
			writeError(writer, http.StatusBadRequest, "Idempotency-Key must be 1 to 255 visible ASCII characters")
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(writer, request.Body, maxRequestBytes))
		if err != nil {
			writeError(writer, http.StatusBadRequest, "read request body: "+err.Error())
			return
		}
		request.Body = io.NopCloser(bytes.NewReader(body))
		hash := sha256.New()
		for _, part := range []string{request.Method, request.URL.Path, request.Header.Get("If-Match")} {
			hash.Write([]byte(part))
			hash.Write([]byte{0})
		}
		hash.Write(body)
		fingerprint := hex.EncodeToString(hash.Sum(nil))

		entry, state := s.idempotency.begin(key, fingerprint)
		switch state {
		case idempotencyReplay:
			writer.Header().Set("Content-Type", "application/json")
			writer.Header().Set("Cache-Control", "no-store")
			writer.Header().Set("Idempotent-Replayed", "true")
			if entry.ETag != "" {
				writer.Header().Set("ETag", entry.ETag)
			}
			writer.WriteHeader(entry.Status)
			_, _ = writer.Write(entry.Body)
			return
		case idempotencyInFlight:
			writeError(writer, http.StatusConflict, "a request with this Idempotency-Key is still being processed")
			return
		case idempotencyMismatch:
			writeError(writer, http.StatusUnprocessableEntity, "Idempotency-Key was already used for a different request")
			return
		}
		capture := &capturingWriter{ResponseWriter: writer, status: http.StatusOK}
		next(capture, request)
		if err := s.idempotency.finish(key, fingerprint, capture.status, capture.body.Bytes(), capture.Header().Get("ETag")); err != nil {
			s.logger.Error("record idempotent response", "error", err)
		}
	}
}

type capturingWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
	body        bytes.Buffer
}

func (w *capturingWriter) WriteHeader(status int) {
	if !w.wroteHeader {
		w.status, w.wroteHeader = status, true
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *capturingWriter) Write(content []byte) (int, error) {
	w.wroteHeader = true
	w.body.Write(content)
	return w.ResponseWriter.Write(content)
}
