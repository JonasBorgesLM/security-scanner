// Package config loads and validates config.yaml, the file that drives
// every pipeline stage (scan/attack/report): target, scope allowlist, auth,
// engine tuning, and enabled checks. See doc/security-scanner-projeto.md §6
// for the format this package implements.
package config

import (
	"errors"
	"fmt"
	"maps"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/JonasBorgesLM/security-scanner/internal/envexpand"
)

// SupportedSchemaVersion is the only config.yaml schema_version this
// package currently understands. Load rejects anything else so a future
// format change fails loudly instead of being silently misread.
const SupportedSchemaVersion = 1

// Config is the root of config.yaml.
type Config struct {
	SchemaVersion int    `yaml:"schema_version"`
	Target        Target `yaml:"target"`
	Scope         Scope  `yaml:"scope"`
	Auth          Auth   `yaml:"auth"`
	Engine        Engine `yaml:"engine"`
	Checks        Checks `yaml:"checks"`
}

// Target is the scanned API's base URL.
type Target struct {
	BaseURL string `yaml:"base_url"`
}

// Scope is the ScopeGuard allowlist — see internal/core/scope.
type Scope struct {
	AllowedHosts []string `yaml:"allowed_hosts"`
}

// Credentials are the login form fields. Password commonly holds a ${VAR}
// reference (e.g. ${LAB_PASSWORD}); Load expands it from the environment,
// so real credentials never need to be committed.
type Credentials struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	// UsernameField is the JSON key Username is sent under in the login
	// request body. Optional; auth.New defaults it to "username" when
	// empty. Set it to e.g. "email" for a target that logs in by email
	// address instead of a literal username.
	UsernameField string `yaml:"username_field"`
}

// Auth configures the automatic login + re-auth described in
// internal/core/auth. Field names and semantics mirror auth.Config.
//
// The whole block is optional: a target whose spec declares no protected
// routes can be scanned with no auth section at all. When present, it must
// be complete — see validateAuth and Configured.
type Auth struct {
	LoginEndpoint string      `yaml:"login_endpoint"`
	Method        string      `yaml:"method"`
	Credentials   Credentials `yaml:"credentials"`
	TokenPath     string      `yaml:"token_path"`
	TokenHeader   string      `yaml:"token_header"`
	TokenPrefix   string      `yaml:"token_prefix"`
	// ExtraHeaders are set on the login request only, before any token
	// exists — every other request already carries TokenHeader.
	// Genuinely optional: validateAuth never requires it, since a target
	// with no such requirement needs nothing here at all. It does count
	// towards anyFieldSet, though — filling in only this field is a
	// half-written auth block, and reading it as "no auth block" would
	// swallow the mistake instead of reporting it. It exists for a login endpoint gated
	// on a header being merely *present*, independent of the
	// credential itself — a CSRF-on-unauthenticated-mutation defense
	// double-submit tokens can't satisfy here, since the scanner has no
	// cookie jar to carry the matching cookie half. Values may contain
	// ${VAR} references, expanded the same way Credentials.Password is.
	ExtraHeaders map[string]string `yaml:"extra_headers"`
}

// Configured reports whether an auth block was supplied. Validation
// guarantees that when this is true the block is complete, so callers can
// use it as the single signal for "credentials are available". LoginEndpoint
// is the anchor field: the login flow is meaningless without it.
func (a Auth) Configured() bool {
	return a.LoginEndpoint != ""
}

// anyFieldSet reports whether the user filled in any auth field at all. It
// distinguishes "no auth section" (valid, for a public target) from "a
// partial auth section" (a mistake worth reporting field by field).
func (a Auth) anyFieldSet() bool {
	return a.LoginEndpoint != "" ||
		a.Method != "" ||
		a.Credentials.Username != "" ||
		a.Credentials.Password != "" ||
		a.TokenPath != "" ||
		a.TokenHeader != "" ||
		a.TokenPrefix != "" ||
		a.Credentials.UsernameField != "" ||
		len(a.ExtraHeaders) > 0
}

// Engine tunes the worker pool + rate limiter that drive active checks.
type Engine struct {
	MaxConcurrency    int     `yaml:"max_concurrency"`
	RequestsPerSecond float64 `yaml:"requests_per_second"`
	// Burst is how many requests may go out at once before the sustained
	// rate applies. Optional; the engine defaults it to 1 (strictly paced).
	Burst   int      `yaml:"burst"`
	Timeout Duration `yaml:"timeout"`
	// RequestTimeout bounds one request, where Timeout bounds the whole
	// run. Without it the two are the same number, so a handful of routes
	// that accept a connection and never answer hold every worker until
	// the global deadline fires — and the run is then discarded as
	// incomplete. Optional; cmd/scanner supplies a default when unset.
	RequestTimeout  Duration `yaml:"request_timeout"`
	TestDestructive bool     `yaml:"test_destructive"`
}

// Checks lists which registered checks (see internal/checks) run.
type Checks struct {
	Enabled []string `yaml:"enabled"`
}

// Duration is a time.Duration that unmarshals from YAML duration strings
// like "5m", since YAML has no native duration type.
type Duration time.Duration

// UnmarshalYAML parses a scalar duration string via time.ParseDuration.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

// String renders the duration the same way time.Duration does, so it reads
// back as the "5m" form config.yaml uses.
func (d Duration) String() string { return time.Duration(d).String() }

// Load reads path, expands ${VAR} environment references, parses the YAML,
// and validates every required field. Any failure comes back as a single
// error with a clear, specific message — including, for missing required
// fields, every one of them at once rather than just the first.
//
// Load takes no context: it only reads and parses a local file, and adding
// a parameter nothing could act on would be noise. The stages that actually
// touch the network take one.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}

	var root yaml.Node
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}

	if err := expandTree(&root); err != nil {
		return nil, fmt.Errorf("config: %s: %w", path, err)
	}

	var cfg Config
	// An empty file parses to a zero node, which Decode would reject. Leave
	// cfg at its zero value instead and let validation list what's missing.
	if root.Kind != 0 {
		if err := root.Decode(&cfg); err != nil {
			return nil, fmt.Errorf("config: parse %s: %w", path, err)
		}
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config: %s: %w", path, err)
	}

	return &cfg, nil
}

// expandTree rewrites ${VAR} references inside the parsed document's scalar
// values, reporting every unset variable at once.
//
// Expansion happens on the parsed tree rather than on the raw file text so
// it cannot reach into comments: a config file that documents its own
// "password: ${LAB_PASSWORD}" convention in a comment is describing the
// syntax, not asking for a variable to be resolved.
func expandTree(root *yaml.Node) error {
	missing := make(map[string]bool)
	var others []error

	var walk func(*yaml.Node)
	walk = func(n *yaml.Node) {
		if n.Kind == yaml.ScalarNode {
			expanded, err := envexpand.Expand(n.Value)
			if err != nil {
				var e *envexpand.MissingVarsError
				if errors.As(err, &e) {
					for _, name := range e.Names {
						missing[name] = true
					}
				} else {
					// Anything Expand may report in the future that is not a
					// missing variable. Dropping it here would leave the node
					// holding its literal "${VAR}" and let Load return
					// success — sending the placeholder to the target as a
					// credential, which is the one outcome invariant #7
					// exists to forbid. Today Expand returns nothing else;
					// this is the guard for the day it does.
					others = append(others, err)
				}
				return
			}
			n.Value = expanded
			return
		}
		for _, child := range n.Content {
			walk(child)
		}
	}
	walk(root)

	if len(missing) > 0 {
		others = append(others, &envexpand.MissingVarsError{Names: slices.Sorted(maps.Keys(missing))})
	}
	return errors.Join(others...)
}

// validationErrors accumulates every problem found instead of failing on
// the first one, so a user fixing config.yaml sees the whole list at once.
type validationErrors struct {
	msgs []string
}

func (e *validationErrors) add(format string, args ...any) {
	e.msgs = append(e.msgs, fmt.Sprintf(format, args...))
}

func (e *validationErrors) errOrNil() error {
	if len(e.msgs) == 0 {
		return nil
	}
	return fmt.Errorf("invalid config:\n  - %s", strings.Join(e.msgs, "\n  - "))
}

func (c *Config) validate() error {
	var errs validationErrors

	if c.SchemaVersion == 0 {
		errs.add("schema_version is required")
	} else if c.SchemaVersion != SupportedSchemaVersion {
		errs.add("schema_version %d is not supported (this build only understands %d)", c.SchemaVersion, SupportedSchemaVersion)
	}

	targetHost := c.validateTarget(&errs)
	c.validateScope(&errs, targetHost)
	c.validateAuth(&errs)
	c.validateEngine(&errs)
	c.validateChecks(&errs)

	return errs.errOrNil()
}

// validateTarget validates target.base_url and, on success, returns its
// host (as it would appear on an outbound request's URL) for the
// cross-check against scope.allowed_hosts in validateScope.
func (c *Config) validateTarget(errs *validationErrors) string {
	if c.Target.BaseURL == "" {
		errs.add("target.base_url is required")
		return ""
	}
	u, err := url.Parse(c.Target.BaseURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		errs.add("target.base_url %q is not a valid absolute URL", c.Target.BaseURL)
		return ""
	}
	return u.Host
}

func (c *Config) validateScope(errs *validationErrors, targetHost string) {
	if len(c.Scope.AllowedHosts) == 0 {
		errs.add("scope.allowed_hosts is required and must list at least one host")
		return
	}
	for _, h := range c.Scope.AllowedHosts {
		if h == "" {
			errs.add("scope.allowed_hosts contains an empty entry")
		}
	}
	if targetHost == "" {
		return
	}
	if !slices.Contains(c.Scope.AllowedHosts, targetHost) {
		errs.add("target.base_url host %q is not in scope.allowed_hosts %v — the ScopeGuard would block every request to the target itself", targetHost, c.Scope.AllowedHosts)
	}
}

// validateAuth treats the auth block as optional but all-or-nothing. An
// empty block is valid: a target whose spec has no protected routes needs no
// credentials, and forcing dummy ones just to pass validation would be
// noise. But a half-filled block is almost always a mistake — a typo'd key,
// a credential left out — so once any field is set, the whole required set
// must be present. Whether the target actually needs auth is a question only
// the spec can answer, so that cross-check lives in the scan/attack commands,
// not here.
func (c *Config) validateAuth(errs *validationErrors) {
	if !c.Auth.anyFieldSet() {
		return
	}
	if c.Auth.LoginEndpoint == "" {
		errs.add("auth.login_endpoint is required when any auth field is set")
	}
	if c.Auth.TokenPath == "" {
		errs.add("auth.token_path is required when any auth field is set")
	}
	if c.Auth.Credentials.Username == "" {
		errs.add("auth.credentials.username is required when any auth field is set")
	}
	if c.Auth.Credentials.Password == "" {
		errs.add("auth.credentials.password is required when any auth field is set")
	}
}

func (c *Config) validateEngine(errs *validationErrors) {
	if c.Engine.MaxConcurrency <= 0 {
		errs.add("engine.max_concurrency must be greater than 0")
	}
	if c.Engine.RequestsPerSecond <= 0 {
		errs.add("engine.requests_per_second must be greater than 0")
	}
	if c.Engine.Burst < 0 {
		errs.add("engine.burst must not be negative")
	}
	if time.Duration(c.Engine.Timeout) <= 0 {
		errs.add("engine.timeout is required and must be greater than 0")
	}
	// Optional, so zero is "use the default" rather than an error — but a
	// negative value is a typo that would otherwise disable the per-request
	// bound silently, which is the whole failure this field exists to stop.
	if time.Duration(c.Engine.RequestTimeout) < 0 {
		errs.add("engine.request_timeout must not be negative")
	}
	if rt, total := time.Duration(c.Engine.RequestTimeout), time.Duration(c.Engine.Timeout); rt > 0 && total > 0 && rt > total {
		errs.add("engine.request_timeout (%s) is longer than engine.timeout (%s), so it could never fire", rt, total)
	}
}

func (c *Config) validateChecks(errs *validationErrors) {
	if len(c.Checks.Enabled) == 0 {
		errs.add("checks.enabled is required and must list at least one check")
		return
	}
	for _, name := range c.Checks.Enabled {
		if name == "" {
			errs.add("checks.enabled contains an empty entry")
		}
	}
}
