package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const maxAnalyticsResponseBytes = 4 << 20

func (s *Server) queryAnalytics(writer http.ResponseWriter, request *http.Request) {
	if s.telemetryAnalyticsURL == "" {
		writeError(writer, http.StatusServiceUnavailable, "Query analytics are not configured")
		return
	}
	endpoint, err := url.Parse(s.telemetryAnalyticsURL)
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "Query analytics source is invalid")
		return
	}
	query := endpoint.Query()
	for _, name := range []string{"range", "limit", "recent"} {
		if value := request.URL.Query().Get(name); value != "" {
			query.Set(name, value)
		}
	}
	endpoint.RawQuery = query.Encode()
	status, payload, err := fetchAnalytics(request.Context(), endpoint.String())
	if err != nil {
		s.logger.Warn("read query analytics", "error", err)
		writeError(writer, http.StatusBadGateway, "Query analytics are unavailable")
		return
	}
	writeJSON(writer, status, payload)
}

func fetchAnalytics(ctx context.Context, endpoint string) (_ int, payload any, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, nil, err
	}
	client := &http.Client{Timeout: 8 * time.Second}
	response, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer closeWithError(&err, "close query analytics response", response.Body.Close)
	limited := io.LimitReader(response.Body, maxAnalyticsResponseBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return 0, nil, err
	}
	if len(body) > maxAnalyticsResponseBytes {
		return 0, nil, fmt.Errorf("query analytics response exceeds %d bytes", maxAnalyticsResponseBytes)
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return 0, nil, fmt.Errorf("decode query analytics response: %w", err)
	}
	return response.StatusCode, payload, nil
}
