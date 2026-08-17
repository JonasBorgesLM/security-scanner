package model

import (
	"errors"
	"strings"
	"testing"
)

func TestSkippedf_IsRecognisableAndExplains(t *testing.T) {
	err := Skippedf("no baseline for %s %s: %v", "GET", "/items", errors.New("connection refused"))

	// The engine keys off this to record a skip rather than a failure.
	if !errors.Is(err, ErrSkipped) {
		t.Fatalf("error = %v, want errors.Is(err, ErrSkipped)", err)
	}
	for _, want := range []string{"GET", "/items", "connection refused"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to mention %q", err, want)
		}
	}
}

func TestSkippedf_DoesNotMatchOrdinaryErrors(t *testing.T) {
	if errors.Is(errors.New("something else"), ErrSkipped) {
		t.Error("a plain error matched ErrSkipped")
	}
}
