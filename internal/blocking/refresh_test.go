package blocking

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRequestRefreshWritesWatchedFile(t *testing.T) {
	directory := t.TempDir()
	store := NewStore(directory)
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.FixedZone("offset", 3600))
	request, err := store.RequestRefresh("operator", "req-1", now)
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(directory, RefreshRequestFile))
	if err != nil {
		t.Fatal(err)
	}
	var written RefreshRequest
	if err := json.Unmarshal(content, &written); err != nil {
		t.Fatal(err)
	}
	if written != request || written.Actor != "operator" || written.RequestID != "req-1" || !written.RequestedAt.Equal(now) || written.RequestedAt.Location() != time.UTC {
		t.Fatalf("written request = %+v, returned %+v", written, request)
	}
}
