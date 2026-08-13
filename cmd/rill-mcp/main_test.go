package main

import (
	"errors"
	"io"
	"testing"
)

func TestNormalClose(t *testing.T) {
	for _, err := range []error{io.EOF, errors.New("server is closing: EOF")} {
		if !normalClose(err) {
			t.Errorf("normalClose(%q) = false", err)
		}
	}
	if normalClose(errors.New("connection failed")) {
		t.Error("unexpected normal close for real failure")
	}
}
