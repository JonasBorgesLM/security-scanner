// Package checks holds one vulnerability check per file. Each check
// registers itself from an init() function, the same way database/sql
// drivers do, so adding a check means adding a file and importing the
// package — no central list to keep in sync.
package checks

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"

	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
)

// registry is keyed by check name. The mutex guards against a caller
// reading it while a late init() is still registering; registration itself
// is expected to happen entirely during program startup.
var (
	mu       sync.RWMutex
	registry = make(map[string]model.Check)
)

// RegisterCheck adds c to the registry under the name in its metadata.
//
// It panics on a nil check, an empty name, an unknown Kind, or a duplicate
// name. These are all programming errors in first-party code, discoverable
// the moment the binary starts — following database/sql's Register rather
// than returning an error nobody could sensibly handle from an init().
func RegisterCheck(c model.Check) {
	if c == nil {
		panic("checks: RegisterCheck called with a nil Check")
	}

	meta := c.Metadata()
	if meta.Name == "" {
		panic("checks: RegisterCheck called with an empty CheckMetadata.Name")
	}
	if meta.Kind != model.KindPassive && meta.Kind != model.KindActive {
		panic(fmt.Sprintf("checks: check %q has Kind %q, want %q or %q",
			meta.Name, meta.Kind, model.KindPassive, model.KindActive))
	}

	mu.Lock()
	defer mu.Unlock()

	if _, exists := registry[meta.Name]; exists {
		panic(fmt.Sprintf("checks: duplicate check name %q", meta.Name))
	}
	registry[meta.Name] = c
}

// Names lists every registered check name, sorted. It backs the "registered
// checks are ..." half of an unknown-name error, and a future --list flag.
func Names() []string {
	mu.RLock()
	defer mu.RUnlock()

	return slices.Sorted(maps.Keys(registry))
}

// Enabled resolves the names from checks.enabled in config.yaml into the
// checks to run, in name order.
//
// An unrecognised name is an error listing what is available, not a silent
// skip: a typo in config.yaml would otherwise quietly disable a check and
// produce a clean-looking report that simply never ran it.
func Enabled(names []string) ([]model.Check, error) {
	mu.RLock()
	defer mu.RUnlock()

	var wanted, unknown []string
	seen := make(map[string]bool, len(names))

	for _, name := range names {
		if seen[name] {
			continue
		}
		seen[name] = true

		if _, ok := registry[name]; ok {
			wanted = append(wanted, name)
			continue
		}
		unknown = append(unknown, name)
	}

	if len(unknown) > 0 {
		available := slices.Sorted(maps.Keys(registry))
		if len(available) == 0 {
			return nil, fmt.Errorf("checks: unknown check(s) %s; no checks are registered",
				quoteAll(unknown))
		}
		return nil, fmt.Errorf("checks: unknown check(s) %s; registered checks are %s",
			quoteAll(unknown), quoteAll(available))
	}

	slices.Sort(wanted)
	return checksByName(wanted), nil
}

// checksByName maps names to checks. Callers must hold at least a read
// lock, and must have verified the names exist.
func checksByName(names []string) []model.Check {
	out := make([]model.Check, 0, len(names))
	for _, name := range names {
		out = append(out, registry[name])
	}
	return out
}

func quoteAll(names []string) string {
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = fmt.Sprintf("%q", n)
	}
	return strings.Join(quoted, ", ")
}
