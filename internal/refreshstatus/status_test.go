package refreshstatus

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	directory := t.TempDir()
	now := time.Date(2026, 8, 11, 20, 0, 0, 0, time.UTC)
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("zones.json", `{"kind":"zones","success":true,"last_attempt":"2026-08-11T19:30:00Z","last_success":"2026-08-11T19:30:00Z","earliest_rrsig_expiry":"20260812185736"}`)
	write("blocklists.json", `{"kind":"blocklists","success":true,"last_attempt":"2026-08-11T19:30:00Z","last_success":"2026-08-11T19:30:00Z","domains":273349}`)
	write("differential.json", `{"kind":"differential","success":true,"last_attempt":"2026-08-11T19:30:00Z","last_success":"2026-08-11T19:30:00Z","checked_zones":3}`)
	report, err := Load(directory, now)
	if err != nil || !report.Healthy || report.Blocklists.Domains != 273349 {
		t.Fatalf("unexpected report: %+v, %v", report, err)
	}
}

func TestLoadDetectsFailure(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "zones.json"), []byte(`{"kind":"zones","success":false,"last_attempt":"2026-08-11T19:30:00Z"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "blocklists.json"), []byte(`{"kind":"blocklists","success":true,"last_success":"2026-08-11T19:30:00Z"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "differential.json"), []byte(`{"kind":"differential","success":true,"last_success":"2026-08-11T19:30:00Z"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := Load(directory, time.Date(2026, 8, 11, 20, 0, 0, 0, time.UTC))
	if err != nil || report.Healthy || report.Reason != "last zone refresh failed" {
		t.Fatalf("unexpected report: %+v, %v", report, err)
	}
}
