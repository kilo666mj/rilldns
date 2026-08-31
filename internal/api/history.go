package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type historyDefinition struct {
	Key, Label, Unit, Query string
}

var historyDefinitions = []historyDefinition{
	{Key: "queries", Label: "Queries / second", Unit: "qps", Query: `sum(rate(coredns_dns_requests_total{job="rilldns"}[5m]))`},
	{Key: "blocked_queries", Label: "Blocked / second", Unit: "qps", Query: `sum(rate(rilldns_blocked_queries_total{job="rilldns"}[5m]))`},
	{Key: "blocked_percent", Label: "Queries blocked", Unit: "%", Query: `100 * sum(rate(rilldns_blocked_queries_total{job="rilldns"}[5m])) / clamp_min(sum(rate(rilldns_dns_queries_total{job="rilldns"}[5m])), 0.000001)`},
	{Key: "cache_hit_ratio", Label: "Cache hit ratio", Unit: "%", Query: `100 * sum(rate(coredns_cache_hits_total{job="rilldns"}[5m])) / clamp_min(sum(rate(coredns_cache_requests_total{job="rilldns"}[5m])), 0.000001)`},
}

type historyPoint [2]float64
type historySeries struct {
	Key    string         `json:"key"`
	Label  string         `json:"label"`
	Unit   string         `json:"unit"`
	Points []historyPoint `json:"points"`
}

func (s *Server) metricsHistory(writer http.ResponseWriter, request *http.Request) {
	if s.prometheusURL == "" {
		writeError(writer, http.StatusServiceUnavailable, "Prometheus history is not configured")
		return
	}
	duration, step, label, ok := historyRange(request.URL.Query().Get("range"))
	if !ok {
		writeError(writer, http.StatusBadRequest, "range must be one of 1h, 6h, 24h, or 7d")
		return
	}
	end := time.Now().UTC()
	start := end.Add(-duration)
	result := make([]historySeries, 0, len(historyDefinitions))
	for _, definition := range historyDefinitions {
		points, err := s.prometheusRange(request, definition.Query, start, end, step)
		if err != nil {
			s.logger.Warn("query Prometheus history", "series", definition.Key, "error", err)
			points = []historyPoint{}
		}
		result = append(result, historySeries{Key: definition.Key, Label: definition.Label, Unit: definition.Unit, Points: points})
	}
	writeJSON(writer, http.StatusOK, map[string]any{"range": label, "start": start, "end": end, "step_seconds": int(step.Seconds()), "series": result})
}

func historyRange(value string) (time.Duration, time.Duration, string, bool) {
	switch value {
	case "", "6h":
		return 6 * time.Hour, time.Minute, "6h", true
	case "1h":
		return time.Hour, 30 * time.Second, "1h", true
	case "24h":
		return 24 * time.Hour, 5 * time.Minute, "24h", true
	case "7d":
		return 7 * 24 * time.Hour, 30 * time.Minute, "7d", true
	default:
		return 0, 0, "", false
	}
}

func (s *Server) prometheusRange(parent *http.Request, query string, start, end time.Time, step time.Duration) ([]historyPoint, error) {
	endpoint, err := url.Parse(s.prometheusURL + "/api/v1/query_range")
	if err != nil {
		return nil, err
	}
	values := endpoint.Query()
	values.Set("query", query)
	values.Set("start", strconv.FormatInt(start.Unix(), 10))
	values.Set("end", strconv.FormatInt(end.Unix(), 10))
	values.Set("step", strconv.Itoa(int(step.Seconds())))
	endpoint.RawQuery = values.Encode()
	req, err := http.NewRequestWithContext(parent.Context(), http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 8 * time.Second}
	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected Prometheus response %s", response.Status)
	}
	var payload struct {
		Status string `json:"status"`
		Data   struct {
			Result []struct {
				Values [][]json.RawMessage `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return nil, err
	}
	if payload.Status != "success" {
		return nil, errors.New("unsuccessful Prometheus query")
	}
	points := []historyPoint{}
	for _, series := range payload.Data.Result {
		for _, pair := range series.Values {
			if len(pair) != 2 {
				continue
			}
			var timestamp float64
			var raw string
			if json.Unmarshal(pair[0], &timestamp) != nil || json.Unmarshal(pair[1], &raw) != nil {
				continue
			}
			value, err := strconv.ParseFloat(raw, 64)
			if err == nil {
				points = append(points, historyPoint{timestamp, value})
			}
		}
	}
	return points, nil
}
