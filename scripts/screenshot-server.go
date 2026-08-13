//go:build ignore

// Run with: go run ./scripts/screenshot-server.go
// This serves the real embedded UI assets with sanitized synthetic API data.
package main

import (
	"encoding/json"
	"log"
	"math"
	"net/http"
	"time"
)

func main() {
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.Dir("internal/webui/static"))))
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "internal/webui/static/index.html")
	})
	mux.HandleFunc("GET /v1/zones", jsonHandler(map[string]any{"zones": []map[string]any{
		{"name": "example.test.", "role": "primary", "serial": 2026081307, "revision": "f73b91c84df2af5d19425f58d955b020c597dd39"},
		{"name": "lab.example.", "role": "primary", "serial": 2026081304, "revision": "941ea7aa90f15b35ca24acc398efbd4741566cf1"},
		{"name": "2.0.192.in-addr.arpa.", "role": "secondary", "serial": 2026081302, "revision": "252ca17bd1b75053f82cd4723c048a433e40e52c"},
	}}))
	mux.HandleFunc("GET /v1/status/refresh", jsonHandler(map[string]any{
		"healthy":      true,
		"zones":        map[string]any{"success": true, "last_success": time.Now().Add(-2 * time.Minute), "zones": []any{1, 2, 3}},
		"blocklists":   map[string]any{"success": true, "last_success": time.Now().Add(-38 * time.Minute), "domains": 271407, "sources": 2},
		"differential": map[string]any{"success": true, "last_success": time.Now().Add(-16 * time.Minute), "queries": 572, "mismatches": 0},
	}))
	mux.HandleFunc("GET /v1/blocklists/config", jsonHandler(map[string]any{
		"sources":  []string{"https://example.net/hosts.txt", "https://example.org/domains.txt"},
		"allow":    []string{"useful.example", "updates.example"},
		"deny":     []string{"telemetry.example", "ads.example"},
		"revision": "demo-revision-8fa3d1",
	}))
	mux.HandleFunc("GET /v1/metrics/history", func(w http.ResponseWriter, r *http.Request) {
		now := time.Now().Add(-30 * time.Second)
		series := []map[string]any{
			chart("queries", "Queries / second", "qps", now, 8.8, 2.3, 0.2),
			chart("blocked_queries", "Blocked / second", "qps", now, 0.72, 0.24, 1.1),
			chart("blocked_percent", "Queries blocked", "%", now, 8.4, 2.1, 1.7),
			chart("cache_hit_ratio", "Cache hit ratio", "%", now, 89.6, 4.2, 2.2),
		}
		writeJSON(w, map[string]any{"range": "6h", "series": series})
	})
	log.Println("screenshot UI: http://127.0.0.1:18088")
	log.Fatal(http.ListenAndServe("127.0.0.1:18088", mux))
}

func chart(key, label, unit string, end time.Time, base, amplitude, phase float64) map[string]any {
	points := make([][2]float64, 72)
	for i := range points {
		value := base + amplitude*math.Sin(float64(i)/7+phase) + amplitude*.35*math.Sin(float64(i)/2.7)
		points[i] = [2]float64{float64(end.Add(time.Duration(i-71) * 5 * time.Minute).Unix()), math.Max(0, value)}
	}
	return map[string]any{"key": key, "label": label, "unit": unit, "points": points}
}

func jsonHandler(value any) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, value) }
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Print(err)
	}
}
