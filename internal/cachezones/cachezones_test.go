package cachezones

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderUsesSOAOriginsAndSortsZones(t *testing.T) {
	directory := t.TempDir()
	files := map[string]string{
		"second.zone": "$ORIGIN second.example.\n@ 300 IN SOA ns.second.example. hostmaster.second.example. 1 300 60 86400 60\n",
		"first.zone":  "$ORIGIN first.example.\n@ 300 IN SOA ns.first.example. hostmaster.first.example. 1 300 60 86400 60\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	content, err := Render(directory)
	if err != nil {
		t.Fatal(err)
	}
	want := "disable success first.example. second.example.\ndisable denial first.example. second.example.\n"
	if !strings.Contains(string(content), want) {
		t.Fatalf("fragment %q does not contain %q", content, want)
	}
}

func TestRenderEmptyDirectoryDoesNotDisableGlobalCache(t *testing.T) {
	content, err := Render(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), "disable ") {
		t.Fatalf("empty inventory emitted a global cache disable: %q", content)
	}
}
