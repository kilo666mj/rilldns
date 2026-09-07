package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kilo666mj/rilldns/internal/blocking"
	"github.com/kilo666mj/rilldns/internal/cloudflare"
	"github.com/kilo666mj/rilldns/internal/refreshstatus"
	"github.com/kilo666mj/rilldns/internal/zones"
)

const maxRequestBytes = 1 << 20

type Server struct {
	store                *zones.Store
	blocking             *blocking.Store
	logger               *slog.Logger
	readOnly             bool
	statusDir            string
	prometheusURL        string
	coreDNSMetricsURL    string
	telemetryMetricsURL  string
	seq                  atomic.Uint64
	cloudflare           CloudflareReader
	cloudflareZones      []string
	cloudflareApplies    atomic.Uint64
	cloudflareFailures   atomic.Uint64
	cloudflareRollbacks  atomic.Uint64
	cloudflareMu         sync.RWMutex
	cloudflareConfig     cloudflare.Config
	cloudflareConfigPath string
	haNode               string
	haRole               string
	haPeerName           string
	haPeerHealthURL      string
	haPeerStatusURL      string
	haVIP                string
}

type CloudflareReader interface {
	ListRecords(ctx context.Context, zone string) (cloudflare.ZoneRecords, error)
	PlanChanges(ctx context.Context, zone string, request cloudflare.PlanRequest) (cloudflare.Plan, error)
	ApplyChanges(ctx context.Context, zone string, request cloudflare.ApplyRequest) (cloudflare.ApplyResult, error)
}

func New(store *zones.Store, logger *slog.Logger, readOnly bool) *Server {
	return NewWithStatus(store, logger, readOnly, "/var/lib/rilldns/status")
}

func NewWithStatus(store *zones.Store, logger *slog.Logger, readOnly bool, statusDir string) *Server {
	return &Server{store: store, blocking: blocking.NewStore("/var/lib/rilldns/blocking"), logger: logger, readOnly: readOnly, statusDir: statusDir}
}

func (s *Server) SetBlockingStore(store *blocking.Store) { s.blocking = store }
func (s *Server) SetCloudflare(reader CloudflareReader, zoneNames []string) {
	s.cloudflare = reader
	s.cloudflareConfig = cloudflare.MakeConfig(zoneNames)
	s.cloudflareZones = append([]string(nil), s.cloudflareConfig.Zones...)
}
func (s *Server) SetCloudflareConfigPath(path string) { s.cloudflareConfigPath = path }
func (s *Server) SetHA(node, role, peerName, peerHealthURL, peerStatusURL, vip string) {
	s.haNode = strings.TrimSpace(node)
	s.haRole = strings.ToLower(strings.TrimSpace(role))
	s.haPeerName = strings.TrimSpace(peerName)
	s.haPeerHealthURL = strings.TrimSpace(peerHealthURL)
	s.haPeerStatusURL = strings.TrimSpace(peerStatusURL)
	s.haVIP = strings.TrimSpace(vip)
}
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
	mux.HandleFunc("GET /v1/providers/cloudflare/zones", s.listCloudflareZones)
	mux.HandleFunc("GET /v1/providers/cloudflare/config", s.getCloudflareConfig)
	mux.HandleFunc("PUT /v1/providers/cloudflare/config", s.updateCloudflareConfig)
	mux.HandleFunc("GET /v1/providers/cloudflare/zones/{zone}/records", s.getCloudflareRecords)
	mux.HandleFunc("POST /v1/providers/cloudflare/zones/{zone}/plans", s.planCloudflareChanges)
	mux.HandleFunc("POST /v1/providers/cloudflare/zones/{zone}/changes", s.applyCloudflareChanges)
	mux.HandleFunc("PUT /v1/zones/{zone}", s.createZone)
	mux.HandleFunc("DELETE /v1/zones/{zone}", s.deleteZone)
	mux.HandleFunc("GET /v1/status/refresh", s.refreshStatus)
	mux.HandleFunc("GET /v1/status/ha", s.haStatus)
	mux.HandleFunc("GET /v1/metrics/history", s.metricsHistory)
	mux.HandleFunc("GET /v1/blocklists/config", s.getBlocklistConfig)
	mux.HandleFunc("PUT /v1/blocklists/config", s.updateBlocklistConfig)
	mux.HandleFunc("GET /metrics", s.metrics)
	mux.HandleFunc("GET /v1/zones/{zone}/rrsets", s.getZone)
	mux.HandleFunc("POST /v1/zones/{zone}/changes", s.changeZone)
	return s.requestLog(mux)
}

func (s *Server) listCloudflareZones(writer http.ResponseWriter, _ *http.Request) {
	if s.cloudflare == nil {
		writeError(writer, http.StatusNotFound, "Cloudflare integration is not configured")
		return
	}
	type externalZone struct {
		Name    string `json:"name"`
		Backend string `json:"backend"`
	}
	s.cloudflareMu.RLock()
	configured := append([]string(nil), s.cloudflareZones...)
	s.cloudflareMu.RUnlock()
	zones := make([]externalZone, 0, len(configured))
	for _, name := range configured {
		zones = append(zones, externalZone{Name: name, Backend: "cloudflare"})
	}
	writeJSON(writer, http.StatusOK, map[string]any{"zones": zones})
}

func (s *Server) getCloudflareConfig(writer http.ResponseWriter, _ *http.Request) {
	if s.cloudflare == nil {
		writeError(writer, http.StatusNotFound, "Cloudflare integration is not configured")
		return
	}
	s.cloudflareMu.RLock()
	config := s.cloudflareConfig
	config.Zones = append([]string(nil), config.Zones...)
	s.cloudflareMu.RUnlock()
	writer.Header().Set("ETag", quoteETag(config.Revision))
	writeJSON(writer, http.StatusOK, config)
}

func (s *Server) updateCloudflareConfig(writer http.ResponseWriter, request *http.Request) {
	if s.readOnly {
		writeError(writer, http.StatusForbidden, "this RillDNS API instance is read-only")
		return
	}
	if s.cloudflare == nil || s.cloudflareConfigPath == "" {
		writeError(writer, http.StatusNotFound, "Cloudflare integration is not configured")
		return
	}
	var input struct {
		Zones            []string `json:"zones"`
		ExpectedRevision string   `json:"expected_revision"`
		DryRun           bool     `json:"dry_run"`
	}
	if !s.decodeJSON(writer, request, &input) {
		return
	}
	s.cloudflareMu.RLock()
	current := s.cloudflareConfig
	s.cloudflareMu.RUnlock()
	if input.ExpectedRevision == "" || input.ExpectedRevision != current.Revision {
		writeError(writer, http.StatusPreconditionFailed, "Cloudflare configuration revision mismatch")
		return
	}
	proposed := cloudflare.MakeConfig(input.Zones)
	for _, zone := range proposed.Zones {
		if _, err := s.cloudflare.ListRecords(request.Context(), zone); err != nil {
			writeError(writer, http.StatusBadRequest, fmt.Sprintf("validate Cloudflare zone %s: %v", zone, err))
			return
		}
	}
	if !input.DryRun {
		saved, err := cloudflare.SaveConfig(s.cloudflareConfigPath, proposed.Zones)
		if err != nil {
			writeError(writer, http.StatusInternalServerError, err.Error())
			return
		}
		s.cloudflareMu.Lock()
		s.cloudflareConfig = saved
		s.cloudflareZones = append([]string(nil), saved.Zones...)
		s.cloudflareMu.Unlock()
		proposed = saved
	}
	writer.Header().Set("ETag", quoteETag(proposed.Revision))
	writeJSON(writer, http.StatusOK, proposed)
}

func (s *Server) getCloudflareRecords(writer http.ResponseWriter, request *http.Request) {
	if s.cloudflare == nil {
		writeError(writer, http.StatusNotFound, "Cloudflare integration is not configured")
		return
	}
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(request.PathValue("zone")), "."))
	if !s.cloudflareZoneAllowed(name) {
		writeError(writer, http.StatusNotFound, "Cloudflare zone is not configured")
		return
	}
	result, err := s.cloudflare.ListRecords(request.Context(), name)
	if err != nil {
		s.logger.Error("read Cloudflare records", "zone", name, "error", err)
		writeError(writer, http.StatusBadGateway, err.Error())
		return
	}
	writer.Header().Set("ETag", quoteETag(result.Revision))
	writeJSON(writer, http.StatusOK, result)
}

func (s *Server) planCloudflareChanges(writer http.ResponseWriter, request *http.Request) {
	if s.cloudflare == nil {
		writeError(writer, http.StatusNotFound, "Cloudflare integration is not configured")
		return
	}
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(request.PathValue("zone")), "."))
	if !s.cloudflareZoneAllowed(name) {
		writeError(writer, http.StatusNotFound, "Cloudflare zone is not configured")
		return
	}
	var input cloudflare.PlanRequest
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
	result, err := s.cloudflare.PlanChanges(request.Context(), name, input)
	if err != nil {
		switch {
		case errors.Is(err, cloudflare.ErrRevisionMismatch):
			writeError(writer, http.StatusPreconditionFailed, err.Error())
		case errors.Is(err, cloudflare.ErrInvalidChange):
			writeError(writer, http.StatusBadRequest, err.Error())
		default:
			s.logger.Error("plan Cloudflare changes", "zone", name, "error", err)
			writeError(writer, http.StatusBadGateway, err.Error())
		}
		return
	}
	writeJSON(writer, http.StatusOK, result)
}

func (s *Server) applyCloudflareChanges(writer http.ResponseWriter, request *http.Request) {
	if s.readOnly {
		writeError(writer, http.StatusForbidden, "this RillDNS API instance is read-only")
		return
	}
	if s.cloudflare == nil {
		writeError(writer, http.StatusNotFound, "Cloudflare integration is not configured")
		return
	}
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(request.PathValue("zone")), "."))
	if !s.cloudflareZoneAllowed(name) {
		writeError(writer, http.StatusNotFound, "Cloudflare zone is not configured")
		return
	}
	var input cloudflare.ApplyRequest
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
	input.Actor, input.RequestID = s.actorAndRequestID(request)
	result, err := s.cloudflare.ApplyChanges(request.Context(), name, input)
	if err != nil {
		s.cloudflareFailures.Add(1)
		switch {
		case errors.Is(err, cloudflare.ErrConfirmationRequired):
			writeError(writer, http.StatusBadRequest, err.Error())
		case errors.Is(err, cloudflare.ErrRevisionMismatch):
			writeError(writer, http.StatusPreconditionFailed, err.Error())
		case errors.Is(err, cloudflare.ErrInvalidChange):
			writeError(writer, http.StatusBadRequest, err.Error())
		default:
			s.logger.Error("apply Cloudflare changes", "zone", name, "request_id", input.RequestID, "error", err)
			writeError(writer, http.StatusBadGateway, err.Error())
		}
		return
	}
	s.cloudflareApplies.Add(1)
	if result.RolledBack {
		s.cloudflareRollbacks.Add(1)
	}
	writer.Header().Set("ETag", quoteETag(result.Revision))
	writeJSON(writer, http.StatusOK, result)
}

func (s *Server) cloudflareZoneAllowed(name string) bool {
	s.cloudflareMu.RLock()
	defer s.cloudflareMu.RUnlock()
	for _, configured := range s.cloudflareZones {
		if name == configured {
			return true
		}
	}
	return false
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
	mux.HandleFunc("GET /v1/status/ha", s.haStatus)
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

type haPeerStatus struct {
	Name               string    `json:"name,omitempty"`
	Reachable          bool      `json:"reachable"`
	LatencyMS          int64     `json:"latency_ms,omitempty"`
	Error              string    `json:"error,omitempty"`
	Role               string    `json:"role,omitempty"`
	Writable           bool      `json:"writable"`
	VIPOwned           bool      `json:"vip_owned"`
	Healthy            bool      `json:"healthy"`
	ReplicationHealthy bool      `json:"replication_healthy"`
	ZoneLastSuccess    time.Time `json:"zone_last_success,omitempty"`
	Zones              int       `json:"zones"`
}

type haStatusResponse struct {
	Node               string               `json:"node"`
	Role               string               `json:"role"`
	Writable           bool                 `json:"writable"`
	VIP                string               `json:"vip,omitempty"`
	VIPOwned           bool                 `json:"vip_owned"`
	Healthy            bool                 `json:"healthy"`
	Reason             string               `json:"reason,omitempty"`
	Peer               haPeerStatus         `json:"peer"`
	ReplicationHealthy bool                 `json:"replication_healthy"`
	Replication        refreshstatus.Status `json:"replication"`
	Zones              refreshstatus.Status `json:"zones"`
}

func (s *Server) haStatus(writer http.ResponseWriter, request *http.Request) {
	report, reportErr := refreshstatus.Load(s.statusDir, time.Now().UTC())
	peerRequest := request.Header.Get("X-RillDNS-HA-Peer") == "1"
	role := s.haRole
	if role == "" {
		if s.readOnly {
			role = "standby"
		} else {
			role = "active"
		}
	}
	status := haStatusResponse{Node: s.haNode, Role: role, Writable: !s.readOnly, VIP: s.haVIP, VIPOwned: localAddressOwned(s.haVIP), Peer: haPeerStatus{Name: s.haPeerName}, Replication: report.Differential, Zones: report.Zones}
	status.ReplicationHealthy = reportErr == nil && report.Differential.Success && report.Differential.Mismatches == 0 && time.Since(report.Differential.LastSuccess) <= 2*time.Hour
	if peerRequest {
		status.Peer = haPeerStatus{Name: s.haPeerName}
	} else {
		status.Peer = s.probePeer(request.Context())
	}
	status.Healthy = reportErr == nil && status.ReplicationHealthy && (peerRequest || s.haPeerHealthURL == "" || status.Peer.Reachable)
	if reportErr != nil {
		status.Reason = reportErr.Error()
	} else if !status.ReplicationHealthy {
		status.Reason = "replication check is failed or stale"
	} else if !peerRequest && s.haPeerHealthURL != "" && !status.Peer.Reachable {
		status.Reason = "peer is unreachable"
	}
	writeJSON(writer, http.StatusOK, status)
}

func (s *Server) probePeer(ctx context.Context) haPeerStatus {
	peer := haPeerStatus{Name: s.haPeerName}
	if s.haPeerHealthURL == "" {
		return peer
	}
	started := time.Now()
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(probeCtx, http.MethodGet, s.haPeerHealthURL, nil)
	if err == nil {
		response, requestErr := (&http.Client{}).Do(request)
		if requestErr == nil {
			defer func() { _ = response.Body.Close() }()
			peer.Reachable = response.StatusCode == http.StatusOK
			if !peer.Reachable {
				peer.Error = response.Status
			}
		} else {
			err = requestErr
		}
	}
	peer.LatencyMS = time.Since(started).Milliseconds()
	if err != nil {
		peer.Error = err.Error()
	}
	if peer.Reachable && s.haPeerStatusURL != "" {
		statusCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		request, requestErr := http.NewRequestWithContext(statusCtx, http.MethodGet, s.haPeerStatusURL, nil)
		if requestErr == nil {
			request.Header.Set("X-RillDNS-HA-Peer", "1")
			response, responseErr := (&http.Client{}).Do(request)
			if responseErr == nil {
				defer func() { _ = response.Body.Close() }()
				var remote haStatusResponse
				if response.StatusCode == http.StatusOK && json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&remote) == nil {
					peer.Name, peer.Role, peer.Writable = remote.Node, remote.Role, remote.Writable
					peer.VIPOwned, peer.Healthy, peer.ReplicationHealthy = remote.VIPOwned, remote.Healthy, remote.ReplicationHealthy
					peer.ZoneLastSuccess, peer.Zones = remote.Zones.LastSuccess, len(remote.Zones.Zones)
				}
			}
		}
	}
	return peer
}

func localAddressOwned(address string) bool {
	ip := net.ParseIP(strings.TrimSpace(address))
	if ip == nil {
		return false
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, address := range addresses {
		candidate, _, err := net.ParseCIDR(address.String())
		if err == nil && candidate.Equal(ip) {
			return true
		}
	}
	return false
}

func (s *Server) metrics(writer http.ResponseWriter, request *http.Request) {
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
	// instead of checking every write.
	var writeErr error
	emit := func(format string, args ...any) {
		if writeErr != nil {
			return
		}
		_, writeErr = fmt.Fprintf(writer, format, args...)
	}
	defer func() {
		if writeErr != nil {
			s.logger.Warn("write metrics response", "error", writeErr)
		}
	}()
	emit("# HELP rilldns_refresh_healthy Whether all refresh pipelines are healthy.\n")
	emit("# TYPE rilldns_refresh_healthy gauge\n")
	emit("rilldns_refresh_healthy %d\n", healthy)
	emit("rilldns_zone_refresh_last_success_seconds %d\n", report.Zones.LastSuccess.Unix())
	emit("rilldns_blocklist_refresh_last_success_seconds %d\n", report.Blocklists.LastSuccess.Unix())
	emit("rilldns_blocklist_domains %d\n", report.Blocklists.Domains)
	emit("rilldns_differential_last_success_seconds %d\n", report.Differential.LastSuccess.Unix())
	emit("rilldns_differential_last_attempt_seconds %d\n", report.Differential.LastAttempt.Unix())
	emit("rilldns_differential_mismatches %d\n", report.Differential.Mismatches)
	emit("rilldns_differential_consecutive_failures %d\n", report.Differential.ConsecutiveFailures)
	emit("rilldns_differential_queries %d\n", report.Differential.Queries)
	if !expiry.IsZero() {
		emit("rilldns_dnssec_earliest_expiry_seconds %d\n", expiry.Unix())
	}
	emit("# HELP rilldns_cloudflare_applies_total Successfully verified Cloudflare DNS apply operations.\n")
	emit("# TYPE rilldns_cloudflare_applies_total counter\n")
	emit("rilldns_cloudflare_applies_total %d\n", s.cloudflareApplies.Load())
	emit("# HELP rilldns_cloudflare_apply_failures_total Failed Cloudflare DNS apply operations.\n")
	emit("# TYPE rilldns_cloudflare_apply_failures_total counter\n")
	emit("rilldns_cloudflare_apply_failures_total %d\n", s.cloudflareFailures.Load())
	emit("# HELP rilldns_cloudflare_rollbacks_total Cloudflare DNS compensating rollbacks.\n")
	emit("# TYPE rilldns_cloudflare_rollbacks_total counter\n")
	emit("rilldns_cloudflare_rollbacks_total %d\n", s.cloudflareRollbacks.Load())
	writable := 0
	if !s.readOnly {
		writable = 1
	}
	vipOwned := 0
	if localAddressOwned(s.haVIP) {
		vipOwned = 1
	}
	peerReachable := 0
	if s.haPeerHealthURL == "" || s.probePeer(request.Context()).Reachable {
		peerReachable = 1
	}
	emit("# HELP rilldns_ha_writable Whether this node accepts control-plane mutations.\n")
	emit("# TYPE rilldns_ha_writable gauge\n")
	emit("rilldns_ha_writable %d\n", writable)
	emit("# HELP rilldns_ha_vip_owned Whether this node currently owns the configured DNS VIP.\n")
	emit("# TYPE rilldns_ha_vip_owned gauge\n")
	emit("rilldns_ha_vip_owned %d\n", vipOwned)
	emit("# HELP rilldns_ha_peer_reachable Whether the configured HA peer health endpoint is reachable.\n")
	emit("# TYPE rilldns_ha_peer_reachable gauge\n")
	emit("rilldns_ha_peer_reachable %d\n", peerReachable)
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
	// net/http closes the underlying request body itself; this wrapper's
	// close is a formality and has nothing to report.
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
	// net/http closes the underlying request body itself; this wrapper's
	// close is a formality and has nothing to report.
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
