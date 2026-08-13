package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInspect(t *testing.T) {
	p := filepath.Join(t.TempDir(), "test.zone")
	data := "$ORIGIN test.\n@ 60 IN SOA ns.test. hostmaster.test. 42 60 60 60 60\n@ 60 IN NS ns.test.\n"
	if err := os.WriteFile(p, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	z, err := inspect(p, "test.")
	if err != nil {
		t.Fatal(err)
	}
	if z.Serial != 42 || z.Records != 2 {
		t.Fatalf("unexpected result: %+v", z)
	}
}
