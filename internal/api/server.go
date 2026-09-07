package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/kilo666mj/rilldns/internal/blocking"
	"github.com/kilo666mj/rilldns/internal/refreshstatus"
	"github.com/kilo666mj/rilldns/internal/zones"
)

const maxRequestBytes = 1 << 20

type Server struct {
	store               *zones.Store
	blocking            *blocking.Store
	logger              *slog.Logger
	readOnly            bool
	statusDir           string
	prometheusURL       string
	coreDNSMetricsURL   string
	telemetryMetricsURL string
	seq                 atomic.Uint64
}

func New(store *zones.Store, logger *slog.Logger, readOnly bool) *Server {
	return NewWithStatus(store, logger, readOnly, "/var/lib/rilldns/status")
}

func NewWithStatus(store *zones.Store, logger *slog.Logger, readOnly bool, statusDir string) *Server {
	return &Server{store: store, blocking: blocking.NewStore("/var/lib/rilldns/blocking"), logger: logger, readOnly: readOnly, statusDir: statusDir}
}

func (s *Server) SetBlockingStore(store *blocking.Store) { s.blocking = store }
func (s *Server) SetMetricsSources(prometheusURL, coreDNSMetricsURL string, telemetryMetricsURL ...string) {
	s.prometheusURL = strings.TrimRight(prometheusURL, "/")
	s.coreDNSMetricsURL = coreDNSMetricsURL
	if len(telemetryMetricsURL) > 0 {
		s.telemetryMetricsURL = telemetryMetricsURL[0]
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /readyz", s.ready)
	mux.HandleFunc("GET /v1/zones", s.listZones)
	mux.HandleFunc("PUT /v1/zones/{zone}", s.createZone)
	mux.HandleFunc("DELETE /v1/zones/{zone}", s.deleteZone)
	mux.HandleFunc("GET /v1/status/refresh", s.refreshStatus)
	mux.HandleFunc("GET /v1/metrics/history", s.metricsHistory)
	mux.HandleFunc("GET /v1/blocklists/config", s.getBlocklistConfig)
	mux.HandleFunc("PUT /v1/blocklists/config", s.updateBlocklistConfig)
	mux.HandleFunc("GET /metrics", s.metrics)
	mux.HandleFunc("GET /v1/zones/{zone}/rrsets", s.getZone)
	mux.HandleFunc("POST /v1/zones/{zone}/changes", s.changeZone)
	return s.requestLog(mux)
}

func (s *Server) getBlocklistConfig(writer http.ResponseWriter, _ *http.Request) {
	config, err := s.blocking.Get()
	if err != nil {
		s.logger.Error("read blocklist configuration", "error", err)
		writeError(writer, http.StatusInternalServerError, err.Error())
		return
	}
	writer.Header().Set("ETag", quoteETag(config.Revision))
	writeJSON(writer, http.StatusOK, config)
}

func (s *Server) updateBlocklistConfig(writer http.ResponseWriter, request *http.Request) {
	if s.readOnly {
		writeError(writer, http.StatusForbidden, "this RillDNS API instance is read-only")
		return
	}
	var input blocking.UpdateRequest
	if !s.decodeJSON(writer, request, &input) {
		return
	}
	if match := request.Header.Get("If-Match"); match != "" {
		match = strings.Trim(match, `"`)
		if input.ExpectedRevision != "" && input.ExpectedRevision != match {
			writeError(writer, http.StatusBadRequest, "If-Match and expected_revision disagree")
			return
		}
		input.ExpectedRevision = match
	}
	_, requestID := s.actorAndRequestID(request)
	result, err := s.blocking.Update(input, requestID)
	if err != nil {
		switch {
		case errors.Is(err, blocking.ErrRevisionMismatch):
			writeError(writer, http.StatusPreconditionFailed, err.Error())
		case errors.Is(err, blocking.ErrInvalid):
			writeError(writer, http.StatusBadRequest, err.Error())
		default:
			s.logger.Error("update blocklist configuration", "error", err)
			writeError(writer, http.StatusInternalServerError, err.Error())
		}
		return
	}
	writer.Header().Set("ETag", quoteETag(result.Config.Revision))
	writeJSON(writer, http.StatusOK, result)
}

func (s *Server) createZone(writer http.ResponseWriter, request *http.Request) {
	if s.readOnly {
		writeError(writer, http.StatusForbidden, "this RillDNS API instance is read-only")
		return
	}
	var input zones.LifecycleRequest
	if !s.decodeJSON(writer, request, &input) {
		return
	}
	actor, requestID := s.actorAndRequestID(request)
	result, err := s.store.Create(request.Context(), request.PathValue("zone"), input, actor, requestID)
	if err != nil {
		s.writeStoreError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, result)
}

func (s *Server) deleteZone(writer http.ResponseWriter, request *http.Request) {
	if s.readOnly {
		writeError(writer, http.StatusForbidden, "this RillDNS API instance is read-only")
		return
	}
	var input zones.LifecycleRequest
	if !s.decodeJSON(writer, request, &input) {
		return
	}
	if match := request.Header.Get("If-Match"); match != "" {
		match = strings.Trim(match, `"`)
		if input.ExpectedRevision != "" && input.ExpectedRevision != match {
			writeError(writer, http.StatusBadRequest, "If-Match and expected_revision disagree")
			return
		}
		input.ExpectedRevision = match
	}
	actor, requestID := s.actorAndRequestID(request)
	result, err := s.store.Delete(request.Context(), request.PathValue("zone"), input, actor, requestID)
	if err != nil {
		s.writeStoreError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, result)
}

// MetricsHandler exposes only read-only operational endpoints and is safe to
// bind separately from the loopback management API.
func (s *Server) MetricsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /metrics", s.metrics)
	mux.HandleFunc("GET /v1/blocklists/config", s.getBlocklistConfig)
	return s.requestLog(mux)
}

func (s *Server) refreshStatus(writer http.ResponseWriter, _ *http.Request) {
	report, err := refreshstatus.Load(s.statusDir, time.Now().UTC())
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeJSON(writer, http.StatusOK, report)
}

func (s *Server) metrics(writer http.ResponseWriter, _ *http.Request) {
	report, err := refreshstatus.Load(s.statusDir, time.Now().UTC())
	if err != nil {
		http.Error(writer, err.Error(), http.StatusServiceUnavailable)
		return
	}
	expiry, _ := report.Zones.RRSIGExpiry()
	healthy := 0
	if report.Healthy {
		healthy = 1
	}
	writer.Header().Set("Content-Type", "text/plain; version=0.0.4")
	// The status line is already sent, so a scrape that disconnects mid-body
	// cannot be reported to the client. Keep the first failure and log it once
	// instead of checking ten writes individually.
	var writeErr error
	emit := func(format string, args ...any) {
		if writeErr != nil {
			return
		}
		_, writeErr = fmt.Fprintf(writer, format, args...)
	}
	emit("# HELP rilldns_refresh_healthy Whether all refresh pipelines are healthy.\n")
	emit("# TYPE rilldns_refresh_healthy gauge\n")
	emit("rilldns_refresh_healthy %d\n", healthy)
	emit("rilldns_zone_refresh_last_success_seconds %d\n", report.Zones.LastSuccess.Unix())
	emit("rilldns_blocklist_refresh_last_success_seconds %d\n", report.Blocklists.LastSuccess.Unix())
	emit("rilldns_blocklist_domains %d\n", report.Blocklists.Domains)
	emit("rilldns_differential_last_success_seconds %d\n", report.Differential.LastSuccess.Unix())
	emit("rilldns_differential_mismatches %d\n", report.Differential.Mismatches)
	emit("rilldns_differential_queries %d\n", report.Differential.Queries)
	if !expiry.IsZero() {
		emit("rilldns_dnssec_earliest_expiry_seconds %d\n", expiry.Unix())
	}
	defer func() {
		if writeErr != nil {
			s.logger.Warn("write metrics response", "error", writeErr)
		}
	}()
	if s.coreDNSMetricsURL != "" {
		request, _ := http.NewRequest(http.MethodGet, s.coreDNSMetricsURL, nil)
		client := &http.Client{Timeout: 3 * time.Second}
		if response, err := client.Do(request); err == nil {
			defer func() { _ = response.Body.Close() }()
			if response.StatusCode == http.StatusOK {
				_, _ = io.Copy(writer, response.Body)
			}
		}
	}
	if s.telemetryMetricsURL != "" {
		request, _ := http.NewRequest(http.MethodGet, s.telemetryMetricsURL, nil)
		client := &http.Client{Timeout: 3 * time.Second}
		if response, err := client.Do(request); err == nil {
			defer func() { _ = response.Body.Close() }()
			if response.StatusCode == http.StatusOK {
				_, _ = io.Copy(writer, response.Body)
			}
		}
	}
}

func (s *Server) health(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) ready(writer http.ResponseWriter, _ *http.Request) {
	if _, err := s.store.List(); err != nil {
		writeError(writer, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) listZones(writer http.ResponseWriter, _ *http.Request) {
	result, err := s.store.List()
	if err != nil {
		writeError(writer, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"zones": result})
}

func (s *Server) getZone(writer http.ResponseWriter, request *http.Request) {
	zone, err := s.store.Get(request.PathValue("zone"))
	if err != nil {
		s.writeStoreError(writer, err)
		return
	}
	writer.Header().Set("ETag", quoteETag(zone.Revision))
	writeJSON(writer, http.StatusOK, zone)
}

func (s *Server) changeZone(writer http.ResponseWriter, request *http.Request) {
	if s.readOnly {
		writeError(writer, http.StatusForbidden, "this RillDNS API instance is read-only")
		return
	}
	body := http.MaxBytesReader(writer, request.Body, maxRequestBytes)
	// net/http closes the underlying request body itself; this wrapper's close
	// is a formality and has nothing to report.
	defer func() { _ = body.Close() }()
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	var input zones.ChangeRequest
	if err := decoder.Decode(&input); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if err := ensureEOF(decoder); err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	if match := request.Header.Get("If-Match"); match != "" {
		match = strings.Trim(match, `"`)
		if input.ExpectedRevision != "" && input.ExpectedRevision != match {
			writeError(writer, http.StatusBadRequest, "If-Match and expected_revision disagree")
			return
		}
		input.ExpectedRevision = match
	}
	requestID := request.Header.Get("X-Request-ID")
	if requestID == "" {
		requestID = fmt.Sprintf("%d-%d", time.Now().UTC().UnixMilli(), s.seq.Add(1))
	}
	actor := request.Header.Get("X-RillDNS-Actor")
	if actor == "" {
		actor = request.RemoteAddr
	}
	result, err := s.store.Apply(request.Context(), request.PathValue("zone"), input, actor, requestID)
	if err != nil {
		s.writeStoreError(writer, err)
		return
	}
	writer.Header().Set("ETag", quoteETag(result.Revision))
	writeJSON(writer, http.StatusOK, result)
}

func (s *Server) decodeJSON(writer http.ResponseWriter, request *http.Request, output any) bool {
	body := http.MaxBytesReader(writer, request.Body, maxRequestBytes)
	// net/http closes the underlying request body itself; this wrapper's close
	// is a formality and has nothing to report.
	defer func() { _ = body.Close() }()
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}
	if err := ensureEOF(decoder); err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return false
	}
	return true
}

func (s *Server) actorAndRequestID(request *http.Request) (string, string) {
	requestID := request.Header.Get("X-Request-ID")
	if requestID == "" {
		requestID = fmt.Sprintf("%d-%d", time.Now().UTC().UnixMilli(), s.seq.Add(1))
	}
	actor := request.Header.Get("X-RillDNS-Actor")
	if actor == "" {
		actor = request.RemoteAddr
	}
	return actor, requestID
}

func (s *Server) writeStoreError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, zones.ErrNotFound):
		writeError(writer, http.StatusNotFound, err.Error())
	case errors.Is(err, zones.ErrRevisionMismatch):
		writeError(writer, http.StatusPreconditionFailed, err.Error())
	case errors.Is(err, zones.ErrAlreadyExists):
		writeError(writer, http.StatusConflict, err.Error())
	case errors.Is(err, zones.ErrReadOnlyZone):
		writeError(writer, http.StatusForbidden, err.Error())
	case errors.Is(err, zones.ErrInvalidChange):
		writeError(writer, http.StatusBadRequest, err.Error())
	default:
		s.logger.Error("request failed", "error", err)
		writeError(writer, http.StatusInternalServerError, err.Error())
	}
}

func (s *Server) requestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		started := time.Now()
		next.ServeHTTP(writer, request)
		s.logger.Info("HTTP request", "method", request.Method, "path", request.URL.Path, "remote", request.RemoteAddr, "duration", time.Since(started))
	})
}

func ensureEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("request body must contain exactly one JSON value")
	}
	return nil
}

func quoteETag(value string) string { return `"` + value + `"` }

func writeError(writer http.ResponseWriter, status int, message string) {
	writeJSON(writer, status, map[string]any{"error": map[string]string{"message": message}})
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
