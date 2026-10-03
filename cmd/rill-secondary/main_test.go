package main

import (
	"reflect"
	"testing"
)

func TestParseZonesRequiresExplicitList(t *testing.T) {
	for _, value := range []string{"", " ", ",", " , "} {
		if _, err := parseZones(value); err == nil {
			t.Errorf("parseZones(%q) accepted an empty zone list", value)
		}
	}
}

func TestParseZonesRejectsSwallowedFlag(t *testing.T) {
	if _, err := parseZones("-discover-zones"); err == nil {
		t.Fatal("a flag name was accepted as a zone")
	}
}

func TestParseZonesTrimsAndSkipsBlanks(t *testing.T) {
	got, err := parseZones(" example.test, ,example.net ")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"example.test", "example.net"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("zones = %q, want %q", got, want)
	}
}
