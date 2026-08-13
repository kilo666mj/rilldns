package api

import (
	"testing"
	"time"
)

func TestHistoryRangeIsBounded(t *testing.T) {
	tests := map[string]time.Duration{"1h": time.Hour, "6h": 6 * time.Hour, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour}
	for value, expected := range tests {
		duration, step, label, ok := historyRange(value)
		if !ok || duration != expected || step <= 0 || label != value {
			t.Fatalf("historyRange(%q) = %v, %v, %q, %v", value, duration, step, label, ok)
		}
	}
	if _, _, _, ok := historyRange("30d"); ok {
		t.Fatal("unbounded history range was accepted")
	}
}

func TestHistoryIncludesAggregateBlockingSeries(t *testing.T) {
	wanted := map[string]bool{"blocked_queries": false, "blocked_percent": false}
	for _, definition := range historyDefinitions {
		if _, ok := wanted[definition.Key]; ok {
			wanted[definition.Key] = true
		}
	}
	for key, found := range wanted {
		if !found {
			t.Errorf("missing history series %q", key)
		}
	}
}
