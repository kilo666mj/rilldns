package cloudflare

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestConfigPersistsNormalizedZones(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cloudflare-zones.json")
	saved, err := SaveConfig(path, []string{"B.example.", "a.example", "b.example"})
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadConfig(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loaded, saved) || !reflect.DeepEqual(loaded.Zones, []string{"a.example", "b.example"}) || len(loaded.Revision) != 64 {
		t.Fatalf("config = %+v", loaded)
	}
}
