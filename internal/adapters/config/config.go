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
}

// Auth configures the automatic login + re-auth described in
// internal/core/auth. Field names and semantics mirror auth.Config.
type Auth struct {
	LoginEndpoint string      `yaml:"login_endpoint"`
	Method        string      `yaml:"method"`
	Credentials   Credentials `yaml:"credentials"`
	TokenPath     string      `yaml:"token_path"`
	TokenHeader   string      `yaml:"token_header"`
	TokenPrefix   string      `yaml:"token_prefix"`
}

// Engine tunes the worker pool + rate limiter that drive active checks.
type Engine struct {
	MaxConcurrency    int      `yaml:"max_concurrency"`
	RequestsPerSecond float64  `yaml:"requests_per_second"`
	Timeout           Duration `yaml:"timeout"`
	TestDestructive   bool     `yaml:"test_destructive"`
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

	var walk func(*yaml.Node)
	walk = func(n *yaml.Node) {
		if n.Kind == yaml.ScalarNode {
			expanded, err := envexpand.Expand(n.Value)
			if err != nil {
				if e, ok := errors.AsType[*envexpand.MissingVarsError](err); ok {
					for _, name := range e.Names {
						missing[name] = true
					}
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
		return &envexpand.MissingVarsError{Names: slices.Sorted(maps.Keys(missing))}
	}
	return nil
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

func (c *Config) validateAuth(errs *validationErrors) {
	if c.Auth.LoginEndpoint == "" {
		errs.add("auth.login_endpoint is required")
	}
	if c.Auth.TokenPath == "" {
		errs.add("auth.token_path is required")
	}
	if c.Auth.Credentials.Username == "" {
		errs.add("auth.credentials.username is required")
	}
	if c.Auth.Credentials.Password == "" {
		errs.add("auth.credentials.password is required")
	}
}

func (c *Config) validateEngine(errs *validationErrors) {
	if c.Engine.MaxConcurrency <= 0 {
		errs.add("engine.max_concurrency must be greater than 0")
	}
	if c.Engine.RequestsPerSecond <= 0 {
		errs.add("engine.requests_per_second must be greater than 0")
	}
	if time.Duration(c.Engine.Timeout) <= 0 {
		errs.add("engine.timeout is required and must be greater than 0")
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
