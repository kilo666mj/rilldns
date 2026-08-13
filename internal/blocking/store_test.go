package blocking

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestUpdateDryRunAndPublish(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"sources.txt": "https://example.test/list.txt\n",
		"allow.txt":   "allowed.example\n",
		"deny.txt":    "blocked.example\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	store := NewStore(dir)
	before, err := store.Get()
	if err != nil {
		t.Fatal(err)
	}
	request := UpdateRequest{Sources: []string{"https://example.test/new.txt"}, Allow: []string{"SAFE.Example."}, Deny: []string{"ads.example"}, ExpectedRevision: before.Revision, DryRun: true}
	dry, err := store.Update(request, "dry")
	if err != nil || dry.Published || dry.Config.Allow[0] != "safe.example" {
		t.Fatalf("dry run = %+v, %v", dry, err)
	}
	afterDry, _ := store.Get()
	if afterDry.Revision != before.Revision {
		t.Fatal("dry run changed configuration")
	}
	request.DryRun = false
	result, err := store.Update(request, "publish")
	if err != nil || !result.Published {
		t.Fatalf("publish = %+v, %v", result, err)
	}
	after, _ := store.Get()
	if after.Revision != result.Config.Revision || after.Deny[0] != "ads.example" {
		t.Fatalf("stored config = %+v", after)
	}
}

func TestUpdateRejectsStaleRevisionAndInvalidInputs(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"sources.txt", "allow.txt", "deny.txt"} {
		content := ""
		if name == "sources.txt" {
			content = "https://example.test/list.txt\n"
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	store := NewStore(dir)
	if _, err := store.Update(UpdateRequest{ExpectedRevision: "stale", Sources: []string{"https://example.test/list"}}, "test"); !errors.Is(err, ErrRevisionMismatch) {
		t.Fatalf("stale revision error = %v", err)
	}
	current, _ := store.Get()
	if _, err := store.Update(UpdateRequest{ExpectedRevision: current.Revision, Sources: []string{"http://example.test/list"}}, "test"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("insecure source error = %v", err)
	}
}
