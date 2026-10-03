package api

import (
	"bufio"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
)

const (
	defaultAuditLimit = 100
	maxAuditLimit     = 500
	maxAuditLineBytes = 4 << 20
)

type auditFilter struct {
	zone     string
	provider string
	actor    string
	limit    int
}

// SetAuditPath enables GET /v1/audit over the append-only audit log shared by
// native zone changes and Cloudflare changes.
func (s *Server) SetAuditPath(path string) { s.auditPath = path }

func (s *Server) listAudit(writer http.ResponseWriter, request *http.Request) {
	if s.auditPath == "" {
		writeError(writer, http.StatusNotFound, "audit log is not configured")
		return
	}
	query := request.URL.Query()
	filter := auditFilter{
		zone:     normalizeAuditZone(query.Get("zone")),
		provider: strings.ToLower(strings.TrimSpace(query.Get("provider"))),
		actor:    query.Get("actor"),
		limit:    defaultAuditLimit,
	}
	if filter.provider != "" && filter.provider != "rilldns" && filter.provider != "cloudflare" {
		writeError(writer, http.StatusBadRequest, "provider must be rilldns or cloudflare")
		return
	}
	if value := query.Get("limit"); value != "" {
		limit, err := strconv.Atoi(value)
		if err != nil || limit < 1 || limit > maxAuditLimit {
			writeError(writer, http.StatusBadRequest, "limit must be between 1 and "+strconv.Itoa(maxAuditLimit))
			return
		}
		filter.limit = limit
	}
	events, skipped, err := readAudit(s.auditPath, filter)
	if err != nil {
		s.logger.Error("read audit log", "error", err)
		writeError(writer, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"events": events, "skipped_lines": skipped})
}

// readAudit returns the newest matching events first. Records are returned as
// stored, because native and Cloudflare events carry different fields. Lines
// that are not JSON objects are counted rather than failing the request.
func readAudit(path string, filter auditFilter) ([]json.RawMessage, int, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return []json.RawMessage{}, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	// Read-only: nothing was written, so a close failure changes nothing.
	defer func() { _ = file.Close() }()

	ring := make([]json.RawMessage, 0, filter.limit)
	next, skipped := 0, 0
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), maxAuditLineBytes)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		var fields struct {
			Zone     string `json:"zone"`
			Provider string `json:"provider"`
			Actor    string `json:"actor"`
		}
		if err := json.Unmarshal(line, &fields); err != nil {
			skipped++
			continue
		}
		provider := fields.Provider
		if provider == "" {
			provider = "rilldns"
		}
		if (filter.zone != "" && normalizeAuditZone(fields.Zone) != filter.zone) ||
			(filter.provider != "" && provider != filter.provider) ||
			(filter.actor != "" && fields.Actor != filter.actor) {
			continue
		}
		event := json.RawMessage(append([]byte(nil), line...))
		if len(ring) < filter.limit {
			ring = append(ring, event)
		} else {
			ring[next] = event
		}
		next = (next + 1) % filter.limit
	}
	if err := scanner.Err(); err != nil {
		return nil, skipped, err
	}
	events := make([]json.RawMessage, 0, len(ring))
	for i := range ring {
		// Walk backwards from the most recently written slot.
		events = append(events, ring[(next-1-i+2*len(ring))%len(ring)])
	}
	return events, skipped, nil
}

func normalizeAuditZone(zone string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")
}
