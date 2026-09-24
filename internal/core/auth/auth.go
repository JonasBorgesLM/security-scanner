// Package auth implements automatic login against the target's
// login_endpoint and transparent re-authentication: every request is
// retried once, with a freshly logged-in token, if it comes back 401. A
// route whose auth still fails after that retry is the caller's problem to
// mark "skipped" — this package never turns an auth failure into a finding.
package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/JonasBorgesLM/warden/internal/envexpand"
	"github.com/JonasBorgesLM/warden/internal/ports"
)

// ErrReAuthFailed is returned by Do when a request comes back 401 and the
// single allowed re-login attempt itself fails (network error, non-2xx
// status, or an unparsable/missing token). Callers should treat this as
// "route auth broken", not as a vulnerability signal.
var ErrReAuthFailed = errors.New("auth: re-authentication failed")

// maxLoginBodyBytes caps how much of a login response is read into memory.
// The target is always the operator's own lab, but an unbounded ReadAll on
// a response this process does not control is exactly the habit the tool
// exists to discourage.
const maxLoginBodyBytes = 1 << 20 // 1 MiB

// Credentials are the login form fields, as configured under
// auth.credentials in config.yaml.
type Credentials struct {
	Username string
	Password string
	// UsernameField is the JSON key Username is sent under in the login
	// body, e.g. "email" for an API that logs in by email address rather
	// than a literal username. Defaults to "username" when empty.
	UsernameField string
}

// Config mirrors the auth: section of config.yaml (see
// doc/warden-projeto.md §6). Password may contain a ${VAR}
// reference; New expands it from the environment so real credentials never
// need to be committed.
type Config struct {
	LoginEndpoint string // e.g. "/login", resolved against the target's base URL
	Method        string // HTTP method for the login request; defaults to POST
	Credentials   Credentials
	TokenPath     string // dot-notation path into the JSON login response, e.g. "data.access_token"
	TokenHeader   string // header the token is injected into; defaults to "Authorization"
	TokenPrefix   string // prepended to the token, e.g. "Bearer "
	// ExtraHeaders are set on the login request only — every other
	// request already carries TokenHeader once a token exists. Nil is
	// the common case (no extra headers).
	//
	// Content-Type is the one header this cannot set: login writes it
	// after applying these, because the body it builds is JSON and no
	// value here can change that.
	ExtraHeaders map[string]string
	// CSRF, optional, fetches a token before the login request and injects
	// it as a header on that request only — the pre-flight ExtraHeaders
	// cannot do, since ExtraHeaders' values are fixed at config time and a
	// signed double-submit CSRF token is minted per run. inner must carry
	// a cookie jar (New does not add one) for the fetch's Set-Cookie to
	// ride along to the login request: the token alone is not the whole
	// credential, the matching cookie is the other half.
	CSRF *CSRFConfig
}

// CSRFConfig describes the pre-login fetch a signed double-submit cookie
// defense needs: GET (or Method) FetchEndpoint, extract TokenPath from the
// JSON response the same way the login response's own token is extracted,
// and send it as TokenHeader on the login request that follows.
type CSRFConfig struct {
	FetchEndpoint string // resolved against baseURL, like LoginEndpoint
	Method        string // defaults to GET
	TokenPath     string // dot-notation, same rules as Config.TokenPath
	TokenHeader   string // defaults to "X-CSRF-Token"
}

// Authenticator wraps a ports.HTTPClient, logging in on first use and
// transparently re-authenticating once on any 401. It implements
// ports.HTTPClient itself, so it can be dropped in anywhere a plain client
// is expected.
type Authenticator struct {
	baseURL string
	cfg     Config
	inner   ports.HTTPClient

	// loginMu serializes actual login attempts so concurrent 401s from the
	// worker pool collapse into a single re-login instead of hammering the
	// login endpoint once per in-flight request.
	loginMu sync.Mutex

	mu    sync.Mutex
	token string
	gen   uint64 // bumped on every successful login
}

var _ ports.HTTPClient = (*Authenticator)(nil)

// New validates cfg, expands ${VAR} references in the password, and builds
// an Authenticator that logs in against baseURL + cfg.LoginEndpoint through
// inner.
//
// inner MUST be the ScopeGuard-enforcing client from
// internal/adapters/httpclient. This package cannot verify that — the whole
// point of ports.HTTPClient is that core code doesn't know which adapter it
// got — so the guarantee lives at the composition root in cmd/warden,
// which is the only place allowed to construct this. Passing a bare
// *http.Client here would silently disable the scanner's only security
// boundary (CLAUDE.md invariant #1) without any compile or test failure.
func New(baseURL string, cfg Config, inner ports.HTTPClient) (*Authenticator, error) {
	if baseURL == "" {
		return nil, errors.New("auth: baseURL must not be empty")
	}
	if cfg.LoginEndpoint == "" {
		return nil, errors.New("auth: LoginEndpoint must not be empty")
	}
	if cfg.TokenPath == "" {
		return nil, errors.New("auth: TokenPath must not be empty")
	}
	if inner == nil {
		return nil, errors.New("auth: inner HTTPClient must not be nil")
	}
	if cfg.Method == "" {
		cfg.Method = http.MethodPost
	}
	if cfg.TokenHeader == "" {
		cfg.TokenHeader = "Authorization"
	}
	if cfg.Credentials.UsernameField == "" {
		cfg.Credentials.UsernameField = "username"
	}
	if cfg.CSRF != nil {
		if cfg.CSRF.FetchEndpoint == "" {
			return nil, errors.New("auth: csrf.fetch_endpoint must not be empty")
		}
		if cfg.CSRF.TokenPath == "" {
			return nil, errors.New("auth: csrf.token_path must not be empty")
		}
		if cfg.CSRF.Method == "" {
			cfg.CSRF.Method = http.MethodGet
		}
		if cfg.CSRF.TokenHeader == "" {
			cfg.CSRF.TokenHeader = "X-CSRF-Token"
		}
	}

	password, err := envexpand.Expand(cfg.Credentials.Password)
	if err != nil {
		return nil, fmt.Errorf("auth: credentials.password: %w", err)
	}
	cfg.Credentials.Password = password

	return &Authenticator{baseURL: baseURL, cfg: cfg, inner: inner}, nil
}

// Authenticate performs an explicit login, useful for failing fast at
// startup instead of discovering bad credentials on the first check.
func (a *Authenticator) Authenticate(ctx context.Context) error {
	return a.login(ctx)
}

// Do injects the current token into req and sends it. On a 401 response it
// re-logs in exactly once and retries req with the fresh token; if that
// retry is still 401, the 401 response is returned as-is (still a valid
// HTTP response — it's on the caller to decide the route is "skipped"). If
// the re-login attempt itself fails, Do returns ErrReAuthFailed.
func (a *Authenticator) Do(req *http.Request) (*http.Response, error) {
	token, gen := a.currentToken()
	if token == "" {
		var err error
		if token, err = a.reAuth(req.Context(), gen); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrReAuthFailed, err)
		}
		_, gen = a.currentToken()
	}

	attempt, err := withToken(req, a.cfg.TokenHeader, a.cfg.TokenPrefix+token)
	if err != nil {
		return nil, err
	}
	resp, err := a.inner.Do(attempt)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}
	resp.Body.Close()

	newToken, err := a.reAuth(req.Context(), gen)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrReAuthFailed, err)
	}

	retry, err := withToken(req, a.cfg.TokenHeader, a.cfg.TokenPrefix+newToken)
	if err != nil {
		return nil, err
	}
	resp, err = a.inner.Do(retry)
	if err != nil {
		return nil, fmt.Errorf("auth: retry after re-authentication: %w", err)
	}
	return resp, nil
}

// Token returns the credential the Authenticator is currently holding, or
// "" before the first successful login. It is exported for the one check
// that inspects the token itself rather than merely carrying it — jwt-weak,
// which decodes it and forges a variant. Everything else should let Do
// inject it and never see the value.
func (a *Authenticator) Token() string {
	token, _ := a.currentToken()
	return token
}

func (a *Authenticator) currentToken() (token string, gen uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.token, a.gen
}

// reAuth logs in again unless another goroutine already refreshed the
// token past staleGen while this caller was waiting for the lock — in that
// case it just hands back the already-fresh token.
func (a *Authenticator) reAuth(ctx context.Context, staleGen uint64) (string, error) {
	a.loginMu.Lock()
	defer a.loginMu.Unlock()

	token, gen := a.currentToken()
	if gen != staleGen {
		return token, nil
	}

	if err := a.login(ctx); err != nil {
		return "", err
	}
	token, _ = a.currentToken()
	return token, nil
}

func (a *Authenticator) login(ctx context.Context) error {
	loginURL, err := url.JoinPath(a.baseURL, a.cfg.LoginEndpoint)
	if err != nil {
		return fmt.Errorf("auth: build login URL: %w", err)
	}

	var csrfToken string
	if a.cfg.CSRF != nil {
		if csrfToken, err = a.fetchCSRFToken(ctx); err != nil {
			return err
		}
	}

	body, err := json.Marshal(map[string]string{
		a.cfg.Credentials.UsernameField: a.cfg.Credentials.Username,
		"password":                      a.cfg.Credentials.Password,
	})
	if err != nil {
		return fmt.Errorf("auth: encode login body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, a.cfg.Method, loginURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("auth: build login request: %w", err)
	}
	// ExtraHeaders first, CSRF second, Content-Type third, so Content-Type
	// always wins. The body above is JSON and nothing here can change
	// that, so letting a config value relabel it would produce a request
	// whose declared type contradicts what it actually carries — and the
	// target would reject it for a reason that points nowhere near the
	// config line that caused it.
	for k, v := range a.cfg.ExtraHeaders {
		req.Header.Set(k, v)
	}
	if a.cfg.CSRF != nil {
		req.Header.Set(a.cfg.CSRF.TokenHeader, csrfToken)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.inner.Do(req)
	if err != nil {
		return fmt.Errorf("auth: login request: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxLoginBodyBytes))
	if err != nil {
		return fmt.Errorf("auth: read login response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("auth: login endpoint returned status %d: %s", resp.StatusCode, bodySnippet(data))
	}

	token, err := extractToken(data, a.cfg.TokenPath)
	if err != nil {
		return err
	}

	a.mu.Lock()
	a.token = token
	a.gen++
	a.mu.Unlock()

	return nil
}

// fetchCSRFToken performs the CSRF.FetchEndpoint request and extracts
// CSRF.TokenPath from its JSON body — the header half of the credential
// login needs. The cookie half is not read here at all: it rides in
// a.inner's own cookie jar (New's own doc comment says the caller must
// supply one), the same way a browser's does, and gets attached to the
// login request automatically by net/http without this function's
// involvement.
func (a *Authenticator) fetchCSRFToken(ctx context.Context) (string, error) {
	fetchURL, err := url.JoinPath(a.baseURL, a.cfg.CSRF.FetchEndpoint)
	if err != nil {
		return "", fmt.Errorf("auth: build csrf fetch URL: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, a.cfg.CSRF.Method, fetchURL, nil)
	if err != nil {
		return "", fmt.Errorf("auth: build csrf fetch request: %w", err)
	}
	resp, err := a.inner.Do(req)
	if err != nil {
		return "", fmt.Errorf("auth: csrf fetch request: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxLoginBodyBytes))
	if err != nil {
		return "", fmt.Errorf("auth: read csrf fetch response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("auth: csrf fetch endpoint returned status %d: %s", resp.StatusCode, bodySnippet(data))
	}

	token, err := extractToken(data, a.cfg.CSRF.TokenPath)
	if err != nil {
		return "", err
	}
	return token, nil
}

// bodySnippet renders a short single-line excerpt of a login response for
// error messages, so a lab API answering something unexpected is
// debuggable without dumping the whole payload into the terminal.
func bodySnippet(data []byte) string {
	const limit = 200

	s := strings.Join(strings.Fields(string(data)), " ")
	if s == "" {
		return "<empty body>"
	}
	if r := []rune(s); len(r) > limit {
		return string(r[:limit]) + "…"
	}
	return s
}

// extractToken walks a dot-notation path (e.g. "data.access_token") into a
// JSON object and returns the string value found there. It only supports
// nested objects, not array indexing — deliberately simple, matching what
// login responses in practice look like.
func extractToken(body []byte, path string) (string, error) {
	var data any
	if err := json.Unmarshal(body, &data); err != nil {
		return "", fmt.Errorf("auth: parse login response: %w", err)
	}

	cur := data
	for part := range strings.SplitSeq(path, ".") {
		obj, ok := cur.(map[string]any)
		if !ok {
			return "", fmt.Errorf("auth: token_path %q: %q is not an object in the login response", path, part)
		}
		val, ok := obj[part]
		if !ok {
			return "", fmt.Errorf("auth: token_path %q: key %q not found in the login response", path, part)
		}
		cur = val
	}

	token, ok := cur.(string)
	if !ok {
		return "", fmt.Errorf("auth: token_path %q: value is not a string", path)
	}
	if token == "" {
		return "", fmt.Errorf("auth: token_path %q: value is empty", path)
	}
	return token, nil
}

// withToken clones req and sets header to value, rewinding the body via
// GetBody so the same logical request can be sent twice (pre- and
// post-re-auth) without either attempt consuming the other's body.
func withToken(req *http.Request, header, value string) (*http.Request, error) {
	clone := req.Clone(req.Context())
	if req.Body != nil {
		if req.GetBody == nil {
			return nil, errors.New("auth: request body is not replayable (GetBody is nil) — build it with http.NewRequest and a bytes/strings body so it can be retried after re-auth")
		}
		body, err := req.GetBody()
		if err != nil {
			return nil, fmt.Errorf("auth: rewind request body: %w", err)
		}
		clone.Body = body
	}
	clone.Header.Set(header, value)
	return clone, nil
}
