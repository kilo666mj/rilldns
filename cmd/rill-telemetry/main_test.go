package main

import "testing"

func TestBoundedInt(t *testing.T) {
	tests := []struct {
		raw      string
		fallback int
		minimum  int
		maximum  int
		want     int
		wantErr  bool
	}{
		{raw: "", fallback: 10, minimum: 1, maximum: 100, want: 10},
		{raw: "25", fallback: 10, minimum: 1, maximum: 100, want: 25},
		{raw: "0", fallback: 10, minimum: 1, maximum: 100, wantErr: true},
		{raw: "many", fallback: 10, minimum: 1, maximum: 100, wantErr: true},
	}
	for _, test := range tests {
		got, err := boundedInt(test.raw, test.fallback, test.minimum, test.maximum)
		if (err != nil) != test.wantErr || got != test.want {
			t.Errorf("boundedInt(%q) = %d, %v; want %d, error=%v", test.raw, got, err, test.want, test.wantErr)
		}
	}
}
