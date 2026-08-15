package scope

import (
	"errors"
	"testing"
)

func TestScopeGuard_Check_AllowedHost(t *testing.T) {
	g := NewScopeGuard([]string{"localhost:8080", "127.0.0.1:8080"})

	if err := g.Check("localhost:8080"); err != nil {
		t.Errorf("Check(%q) error = %v, want nil", "localhost:8080", err)
	}
	if err := g.Check("127.0.0.1:8080"); err != nil {
		t.Errorf("Check(%q) error = %v, want nil", "127.0.0.1:8080", err)
	}
}

func TestScopeGuard_Check_BlockedHost(t *testing.T) {
	g := NewScopeGuard([]string{"localhost:8080"})

	err := g.Check("evil.example.com")
	if err == nil {
		t.Fatal("Check() error = nil, want ErrOutOfScope for a host outside the allowlist")
	}
	if !errors.Is(err, ErrOutOfScope) {
		t.Errorf("Check() error = %v, want errors.Is(err, ErrOutOfScope)", err)
	}
}

func TestScopeGuard_Check_EmptyAllowlistBlocksEverything(t *testing.T) {
	g := NewScopeGuard(nil)

	if err := g.Check("localhost:8080"); !errors.Is(err, ErrOutOfScope) {
		t.Errorf("Check() error = %v, want errors.Is(err, ErrOutOfScope) for an empty allowlist", err)
	}
}
