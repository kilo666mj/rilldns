package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

type zone struct {
	Name   string `json:"name"`
	Serial uint32 `json:"serial"`
}

type status struct {
	Node               string `json:"node"`
	Role               string `json:"role"`
	Writable           bool   `json:"writable"`
	Healthy            bool   `json:"healthy"`
	ReplicationHealthy bool   `json:"replication_healthy"`
	Peer               struct {
		Reachable bool `json:"reachable"`
	} `json:"peer"`
	Zones struct {
		LastSuccess time.Time `json:"last_success"`
		Zones       []zone    `json:"zones"`
	} `json:"zones"`
}

type result struct {
	Ready   bool     `json:"ready"`
	Active  string   `json:"active"`
	Standby string   `json:"standby"`
	Reasons []string `json:"reasons,omitempty"`
}

func main() {
	activeURL := flag.String("active-url", "", "active node read-only HA status URL")
	standbyURL := flag.String("standby-url", "", "standby node read-only HA status URL")
	maxAge := flag.Duration("max-age", 2*time.Hour, "maximum acceptable zone snapshot age")
	flag.Parse()
	if *activeURL == "" || *standbyURL == "" {
		fmt.Fprintln(os.Stderr, "usage: rill-ha -active-url URL -standby-url URL")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	active, activeErr := readStatus(ctx, *activeURL)
	standby, standbyErr := readStatus(ctx, *standbyURL)
	check := evaluate(active, standby, activeErr, standbyErr, *maxAge, time.Now().UTC())
	encoded, _ := json.MarshalIndent(check, "", "  ")
	fmt.Println(string(encoded))
	if !check.Ready {
		os.Exit(1)
	}
}

func readStatus(ctx context.Context, endpoint string) (_ status, err error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return status{}, err
	}
	response, err := (&http.Client{Timeout: 4 * time.Second}).Do(request)
	if err != nil {
		return status{}, err
	}
	defer closeWithError(&err, "close response body", response.Body.Close)
	if response.StatusCode != http.StatusOK {
		return status{}, fmt.Errorf("%s returned %s", endpoint, response.Status)
	}
	var value status
	if err := json.NewDecoder(response.Body).Decode(&value); err != nil {
		return status{}, err
	}
	return value, nil
}

func evaluate(active, standby status, activeErr, standbyErr error, maxAge time.Duration, now time.Time) result {
	check := result{Active: active.Node, Standby: standby.Node}
	if activeErr != nil {
		check.Reasons = append(check.Reasons, "active status unavailable: "+activeErr.Error())
	}
	if standbyErr != nil {
		check.Reasons = append(check.Reasons, "standby status unavailable: "+standbyErr.Error())
	}
	if activeErr == nil && (active.Role != "active" || !active.Writable) {
		check.Reasons = append(check.Reasons, "source is not the writable active node")
	}
	if standbyErr == nil && (standby.Role != "standby" || standby.Writable) {
		check.Reasons = append(check.Reasons, "target is not a read-only standby")
	}
	if standbyErr == nil && (!standby.Healthy || !standby.ReplicationHealthy || !standby.Peer.Reachable) {
		check.Reasons = append(check.Reasons, "standby health, replication, or peer check is not clean")
	}
	if standbyErr == nil && (standby.Zones.LastSuccess.IsZero() || now.Sub(standby.Zones.LastSuccess) > maxAge) {
		check.Reasons = append(check.Reasons, "standby zone snapshot is stale")
	}
	if activeErr == nil && standbyErr == nil {
		activeZones := zoneSerials(active.Zones.Zones)
		standbyZones := zoneSerials(standby.Zones.Zones)
		for name, serial := range activeZones {
			if standbyZones[name] != serial {
				check.Reasons = append(check.Reasons, fmt.Sprintf("zone %s serial differs: active=%d standby=%d", name, serial, standbyZones[name]))
			}
		}
		for name := range standbyZones {
			if _, exists := activeZones[name]; !exists {
				check.Reasons = append(check.Reasons, "standby has unexpected zone "+name)
			}
		}
	}
	sort.Strings(check.Reasons)
	check.Ready = len(check.Reasons) == 0
	return check
}

func zoneSerials(zones []zone) map[string]uint32 {
	result := make(map[string]uint32, len(zones))
	for _, item := range zones {
		result[strings.TrimSuffix(strings.ToLower(item.Name), ".")] = item.Serial
	}
	return result
}

// closeWithError joins a cleanup failure onto a named error return without
// discarding the primary error.
func closeWithError(errp *error, context string, closeFn func() error) {
	if err := closeFn(); err != nil {
		*errp = errors.Join(*errp, fmt.Errorf("%s: %w", context, err))
	}
}
