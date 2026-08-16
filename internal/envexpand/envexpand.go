// Package envexpand expands ${VAR} references in configuration text using
// the process environment. It exists so secrets (LAB_PASSWORD and friends)
// can live in config.yaml as placeholders instead of committed literals —
// see invariant #6 in CLAUDE.md.
//
// An unset variable is an error, never a silent pass-through: sending a
// literal "${LAB_PASSWORD}" to the target as a credential would fail in a
// confusing way far from its cause.
package envexpand

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// pattern matches ${VAR} where VAR is a conventional shell identifier.
var pattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// MissingVarsError reports every ${VAR} reference that had no corresponding
// environment variable, so a caller can react to the specific names via
// errors.As instead of matching on message text.
type MissingVarsError struct {
	Names []string
}

func (e *MissingVarsError) Error() string {
	return fmt.Sprintf("environment variable(s) not set: %s", strings.Join(e.Names, ", "))
}

// Expand replaces every ${VAR} in s with that environment variable's value.
// If any referenced variable is unset it returns a *MissingVarsError naming
// all of them at once, so one run surfaces the whole list rather than
// making the caller fix them one at a time.
func Expand(s string) (string, error) {
	var missing []string
	seen := make(map[string]bool)

	expanded := pattern.ReplaceAllStringFunc(s, func(match string) string {
		name := pattern.FindStringSubmatch(match)[1]
		val, ok := os.LookupEnv(name)
		if !ok {
			if !seen[name] {
				seen[name] = true
				missing = append(missing, name)
			}
			return match
		}
		return val
	})

	if len(missing) > 0 {
		return "", &MissingVarsError{Names: missing}
	}
	return expanded, nil
}
