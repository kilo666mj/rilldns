package refreshstatus

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type Zone struct {
	Name    string `json:"name"`
	Serial  uint32 `json:"serial"`
	Records int    `json:"records"`
}

type Status struct {
	Kind                string    `json:"kind"`
	Success             bool      `json:"success"`
	LastAttempt         time.Time `json:"last_attempt"`
	LastSuccess         time.Time `json:"last_success,omitempty"`
	Error               string    `json:"error,omitempty"`
	Source              string    `json:"source,omitempty"`
	EarliestRRSIGExpiry string    `json:"earliest_rrsig_expiry,omitempty"`
	Zones               []Zone    `json:"zones,omitempty"`
	Domains             int       `json:"domains,omitempty"`
	Sources             int       `json:"sources,omitempty"`
	SHA256              string    `json:"sha256,omitempty"`
	Mismatches          int       `json:"mismatches,omitempty"`
	CheckedZones        int       `json:"checked_zones,omitempty"`
	Queries             int       `json:"queries,omitempty"`
}

type Report struct {
	Healthy      bool   `json:"healthy"`
	Reason       string `json:"reason,omitempty"`
	Zones        Status `json:"zones"`
	Blocklists   Status `json:"blocklists"`
	Differential Status `json:"differential"`
}

func Load(directory string, now time.Time) (Report, error) {
	zones, err := read(filepath.Join(directory, "zones.json"))
	if err != nil {
		return Report{}, fmt.Errorf("read zone refresh status: %w", err)
	}
	blocklists, err := read(filepath.Join(directory, "blocklists.json"))
	if err != nil {
		return Report{}, fmt.Errorf("read blocklist refresh status: %w", err)
	}
	differential, err := read(filepath.Join(directory, "differential.json"))
	if err != nil {
		return Report{}, fmt.Errorf("read differential status: %w", err)
	}
	report := Report{Healthy: true, Zones: zones, Blocklists: blocklists, Differential: differential}
	expiry, expiryErr := zones.RRSIGExpiry()
	switch {
	case !zones.Success:
		report.Healthy, report.Reason = false, "last zone refresh failed"
	case !blocklists.Success:
		report.Healthy, report.Reason = false, "last blocklist refresh failed"
	case !differential.Success || differential.Mismatches != 0:
		report.Healthy, report.Reason = false, "last differential DNS check failed"
	case now.Sub(zones.LastSuccess) > 2*time.Hour:
		report.Healthy, report.Reason = false, "zone refresh is stale"
	case now.Sub(blocklists.LastSuccess) > 26*time.Hour:
		report.Healthy, report.Reason = false, "blocklist refresh is stale"
	case now.Sub(differential.LastSuccess) > 2*time.Hour:
		report.Healthy, report.Reason = false, "differential DNS check is stale"
	case expiryErr != nil:
		report.Healthy, report.Reason = false, "DNSSEC signature expiry is invalid"
	case !expiry.IsZero() && expiry.Sub(now) < 12*time.Hour:
		report.Healthy, report.Reason = false, "DNSSEC signature expires within 12 hours"
	}
	return report, nil
}

func (s Status) RRSIGExpiry() (time.Time, error) {
	if s.EarliestRRSIGExpiry == "" {
		return time.Time{}, nil
	}
	return time.Parse("20060102150405", s.EarliestRRSIGExpiry)
}

func read(path string) (Status, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return Status{}, err
	}
	var status Status
	if err := json.Unmarshal(content, &status); err != nil {
		return Status{}, err
	}
	return status, nil
}
