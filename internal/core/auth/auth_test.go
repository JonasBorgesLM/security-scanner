package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/JonasBorgesLM/security-scanner/internal/envexpand"
	"github.com/JonasBorgesLM/security-scanner/internal/ports"
)

// fakeAPI simulates a lab API with a /login endpoint and a /protected
// endpoint that only accepts the most recently issued token — exactly the
// shape a real session-expiry scenario has.
type fakeAPI struct {
	mu          sync.Mutex
	validToken  string
	loginFails  bool
	loginCount  atomic.Int32
	protectHits atomic.Int32
}

// expireToken makes the server reject whatever token it last issued,
// simulating a session that timed out server-side.
func (api *fakeAPI) expireToken() {
	api.mu.Lock()
	defer api.mu.Unlock()
	api.validToken = "expired-server-side"
}

// breakLogin makes subsequent login attempts fail with a 500.
func (api *fakeAPI) breakLogin() {
	api.mu.Lock()
	defer api.mu.Unlock()
	api.loginFails = true
}

func newFakeAPI(t *testing.T) (*httptest.Server, *fakeAPI) {
	t.Helper()
	api := &fakeAPI{}

	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		api.mu.Lock()
		defer api.mu.Unlock()

		if api.loginFails {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		var creds struct{ Username, Password string }
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &creds)
		if creds.Username != "admin" || creds.Password != "s3cr3t" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		count := api.loginCount.Add(1)
		api.validToken = fmt.Sprintf("tok-%d", count)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"access_token": api.validToken},
		})
	})
	mux.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		api.protectHits.Add(1)
		api.mu.Lock()
		want := "Bearer " + api.validToken
		api.mu.Unlock()

		if r.Header.Get("Authorization") != want {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, api
}

func testConfig() Config {
	return Config{
		LoginEndpoint: "/login",
		Credentials:   Credentials{Username: "admin", Password: "s3cr3t"},
		TokenPath:     "data.access_token",
		TokenHeader:   "Authorization",
		TokenPrefix:   "Bearer ",
	}
}

// newAuthenticator builds an Authenticator against srv. Tests use
// http.DefaultClient as the inner client because it already satisfies
// ports.HTTPClient — no mocking library needed.
func newAuthenticator(t *testing.T, srv *httptest.Server) *Authenticator {
	t.Helper()
	a, err := New(srv.URL, testConfig(), http.DefaultClient)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return a
}

// getProtected issues a GET /protected through a and returns its status,
// closing the body. Any transport error fails the test.
func getProtected(t *testing.T, a *Authenticator, srv *httptest.Server) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/protected", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	resp, err := a.Do(req)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// primeToken performs the first successful request, so the Authenticator
// holds a valid token and the test can then expire it server-side.
func primeToken(t *testing.T, a *Authenticator, srv *httptest.Server) {
	t.Helper()
	if got := getProtected(t, a, srv); got != http.StatusOK {
		t.Fatalf("initial request status = %d, want 200", got)
	}
}

func TestAuthenticator_LogsInOnFirstRequest(t *testing.T) {
	srv, api := newFakeAPI(t)
	a := newAuthenticator(t, srv)

	if got := getProtected(t, a, srv); got != http.StatusOK {
		t.Errorf("StatusCode = %d, want 200", got)
	}
	if got := api.loginCount.Load(); got != 1 {
		t.Errorf("loginCount = %d, want 1", got)
	}
}

func TestAuthenticator_ReAuthsOnceOnExpiredToken(t *testing.T) {
	srv, api := newFakeAPI(t)
	a := newAuthenticator(t, srv)

	primeToken(t, a, srv)
	api.expireToken()

	if got := getProtected(t, a, srv); got != http.StatusOK {
		t.Errorf("StatusCode = %d, want 200 (should have re-authed and retried)", got)
	}
	if got := api.loginCount.Load(); got != 2 {
		t.Errorf("loginCount = %d, want 2 (one re-login after the 401)", got)
	}
	if got := api.protectHits.Load(); got != 3 {
		t.Errorf("protectHits = %d, want 3 (1 initial success + 1 stale 401 + 1 retry success)", got)
	}
}

func TestAuthenticator_GivesUpAfterOneFailedReAuth(t *testing.T) {
	srv, api := newFakeAPI(t)
	a := newAuthenticator(t, srv)

	primeToken(t, a, srv)
	api.expireToken()
	api.breakLogin()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/protected", nil)
	resp, err := a.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("Do() error = nil, want ErrReAuthFailed when the login retry itself fails")
	}
	if !errors.Is(err, ErrReAuthFailed) {
		t.Errorf("Do() error = %v, want errors.Is(err, ErrReAuthFailed)", err)
	}
	if got := api.loginCount.Load(); got != 1 {
		t.Errorf("loginCount = %d, want 1 (the failed re-login attempt must not have succeeded)", got)
	}
}

func TestAuthenticator_StillUnauthorizedAfterReAuthReturnsThe401(t *testing.T) {
	// A route that is protected by something other than the bearer token
	// (e.g. a role check) can legitimately still 401 even with a brand new,
	// valid token. Do must not treat that as a transport error — it hands
	// back the 401 response so the caller can mark the route "skipped".
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"access_token": "tok-always-rejected"},
		})
	})
	mux.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	a := newAuthenticator(t, srv)

	if got := getProtected(t, a, srv); got != http.StatusUnauthorized {
		t.Errorf("StatusCode = %d, want 401", got)
	}
}

func TestAuthenticator_ConcurrentExpiredRequestsShareOneReLogin(t *testing.T) {
	srv, api := newFakeAPI(t)
	a := newAuthenticator(t, srv)

	primeToken(t, a, srv)
	api.expireToken()

	const n = 10
	var wg sync.WaitGroup
	errs := make([]error, n)
	codes := make([]int, n)
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodGet, srv.URL+"/protected", nil)
			resp, err := a.Do(req)
			if err != nil {
				errs[i] = err
				return
			}
			defer resp.Body.Close()
			codes[i] = resp.StatusCode
		}(i)
	}
	wg.Wait()

	for i := range n {
		if errs[i] != nil {
			t.Errorf("goroutine %d: Do() error = %v", i, errs[i])
		}
		if codes[i] != http.StatusOK {
			t.Errorf("goroutine %d: StatusCode = %d, want 200", i, codes[i])
		}
	}

	if got := api.loginCount.Load(); got != 2 {
		t.Errorf("loginCount = %d, want 2 (1 initial + 1 shared re-login, not %d separate ones)", got, n)
	}
}

func TestAuthenticator_Authenticate(t *testing.T) {
	srv, api := newFakeAPI(t)
	a := newAuthenticator(t, srv)

	if err := a.Authenticate(t.Context()); err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if got := api.loginCount.Load(); got != 1 {
		t.Errorf("loginCount = %d, want 1", got)
	}

	// A request afterwards reuses the token instead of logging in again.
	if got := getProtected(t, a, srv); got != http.StatusOK {
		t.Errorf("StatusCode = %d, want 200", got)
	}
	if got := api.loginCount.Load(); got != 1 {
		t.Errorf("loginCount = %d, want 1 (the eager login should be reused)", got)
	}
}

func TestAuthenticator_AuthenticateReportsBadCredentials(t *testing.T) {
	srv, _ := newFakeAPI(t)

	cfg := testConfig()
	cfg.Credentials.Password = "wrong-password"
	a, err := New(srv.URL, cfg, http.DefaultClient)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	err = a.Authenticate(t.Context())
	if err == nil {
		t.Fatal("Authenticate() error = nil, want an error for rejected credentials")
	}
	// The status must be in the message so a failing lab login is
	// diagnosable without re-running under a proxy.
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error = %q, want it to report the login status code", err.Error())
	}
}

func TestAuthenticator_NonReplayableBodyIsRejected(t *testing.T) {
	srv, _ := newFakeAPI(t)
	a := newAuthenticator(t, srv)

	// A request whose body cannot be rewound can't survive the re-auth
	// retry. Do must say so plainly rather than silently sending an empty
	// body on the second attempt.
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/protected", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Body = io.NopCloser(strings.NewReader(`{"a":1}`))
	req.GetBody = nil

	resp, err := a.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("Do() error = nil, want an error for a non-replayable body")
	}
	if !strings.Contains(err.Error(), "GetBody") {
		t.Errorf("error = %q, want it to explain the GetBody requirement", err.Error())
	}
}

func TestAuthenticator_ReplayableBodySurvivesReAuth(t *testing.T) {
	var bodies []string
	var mu sync.Mutex

	mux := http.NewServeMux()
	tokens := 0
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		tokens++
		tok := fmt.Sprintf("tok-%d", tokens)
		mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"access_token": tok},
		})
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(body))
		n := len(bodies)
		mu.Unlock()

		// Reject the first attempt to force exactly one re-auth retry.
		if n == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	a := newAuthenticator(t, srv)

	const payload = `{"q":"value"}`
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/echo", strings.NewReader(payload))
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}

	resp, err := a.Do(req)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 2 {
		t.Fatalf("server saw %d requests, want 2", len(bodies))
	}
	for i, got := range bodies {
		if got != payload {
			t.Errorf("attempt %d body = %q, want %q — the body must be rewound for the retry", i+1, got, payload)
		}
	}
}

func TestNew_ExpandsPasswordFromEnv(t *testing.T) {
	t.Setenv("SCANNER_TEST_LAB_PASSWORD", "from-env")

	cfg := testConfig()
	cfg.Credentials.Password = "${SCANNER_TEST_LAB_PASSWORD}"

	a, err := New("http://example.invalid", cfg, http.DefaultClient)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if a.cfg.Credentials.Password != "from-env" {
		t.Errorf("Credentials.Password = %q, want %q", a.cfg.Credentials.Password, "from-env")
	}
}

func TestNew_MissingEnvVarErrors(t *testing.T) {
	cfg := testConfig()
	cfg.Credentials.Password = "${SCANNER_TEST_DEFINITELY_UNSET_VAR}"

	_, err := New("http://example.invalid", cfg, http.DefaultClient)
	if err == nil {
		t.Fatal("New() error = nil, want an error for an unset ${VAR}")
	}

	var missing *envexpand.MissingVarsError
	if !errors.As(err, &missing) {
		t.Errorf("New() error = %v, want it to wrap an *envexpand.MissingVarsError", err)
	}
}

func TestNew_RejectsMissingRequiredFields(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
		inner   ports.HTTPClient
		mutate  func(*Config)
	}{
		{"empty baseURL", "", http.DefaultClient, func(c *Config) {}},
		{"empty LoginEndpoint", "http://example.invalid", http.DefaultClient, func(c *Config) { c.LoginEndpoint = "" }},
		{"empty TokenPath", "http://example.invalid", http.DefaultClient, func(c *Config) { c.TokenPath = "" }},
		{"nil inner client", "http://example.invalid", nil, func(c *Config) {}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig()
			tt.mutate(&cfg)
			if _, err := New(tt.baseURL, cfg, tt.inner); err == nil {
				t.Errorf("New() error = nil, want an error")
			}
		})
	}
}

func TestNew_AppliesDefaults(t *testing.T) {
	cfg := testConfig()
	cfg.Method = ""
	cfg.TokenHeader = ""

	a, err := New("http://example.invalid", cfg, http.DefaultClient)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if a.cfg.Method != http.MethodPost {
		t.Errorf("Method = %q, want POST", a.cfg.Method)
	}
	if a.cfg.TokenHeader != "Authorization" {
		t.Errorf("TokenHeader = %q, want Authorization", a.cfg.TokenHeader)
	}
	if a.cfg.Credentials.UsernameField != "username" {
		t.Errorf("Credentials.UsernameField = %q, want %q", a.cfg.Credentials.UsernameField, "username")
	}
}

// TestAuthenticator_SendsCredentialsUnderCustomUsernameField covers a
// target that logs in by email rather than a literal username (e.g.
// task-api's POST /auth/login, which expects {"email": ...}): the login
// body must carry Credentials.Username under the configured
// UsernameField key, not a hardcoded "username".
func TestAuthenticator_SendsCredentialsUnderCustomUsernameField(t *testing.T) {
	var gotBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &gotBody); err != nil {
			t.Fatalf("unmarshal login body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"token": "tok-1"})
	}))
	t.Cleanup(srv.Close)

	cfg := testConfig()
	cfg.Credentials.UsernameField = "email"
	cfg.TokenPath = "token"
	a, err := New(srv.URL, cfg, http.DefaultClient)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if err := a.Authenticate(t.Context()); err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}

	if _, ok := gotBody["username"]; ok {
		t.Errorf("login body has key %q, want it absent when UsernameField overrides it", "username")
	}
	if got := gotBody["email"]; got != cfg.Credentials.Username {
		t.Errorf("login body[%q] = %q, want %q", "email", got, cfg.Credentials.Username)
	}
	if got := gotBody["password"]; got != cfg.Credentials.Password {
		t.Errorf("login body[%q] = %q, want %q", "password", got, cfg.Credentials.Password)
	}
}

func TestExtractToken(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		path    string
		want    string
		wantErr bool
	}{
		{"nested path", `{"data":{"access_token":"tok-1"}}`, "data.access_token", "tok-1", false},
		{"top-level path", `{"token":"tok-1"}`, "token", "tok-1", false},
		{"missing key", `{"data":{}}`, "data.access_token", "", true},
		{"non-object intermediate", `{"data":"oops"}`, "data.access_token", "", true},
		{"non-string leaf", `{"data":{"access_token":123}}`, "data.access_token", "", true},
		{"empty string leaf", `{"data":{"access_token":""}}`, "data.access_token", "", true},
		{"invalid json", `not json`, "data.access_token", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractToken([]byte(tt.body), tt.path)
			if (err != nil) != tt.wantErr {
				t.Fatalf("extractToken() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Errorf("extractToken() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBodySnippet(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", "<empty body>"},
		{"whitespace only", "  \n\t ", "<empty body>"},
		{"collapses whitespace", "{\n  \"error\": \"nope\"\n}", `{ "error": "nope" }`},
		{"short body kept whole", `{"error":"nope"}`, `{"error":"nope"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bodySnippet([]byte(tt.in)); got != tt.want {
				t.Errorf("bodySnippet() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBodySnippet_TruncatesLongBody(t *testing.T) {
	got := bodySnippet([]byte(strings.Repeat("x", 500)))
	if !strings.HasSuffix(got, "…") {
		t.Errorf("bodySnippet() = %q, want it truncated with an ellipsis", got)
	}
	if n := len([]rune(got)); n != 201 {
		t.Errorf("bodySnippet() length = %d runes, want 201 (200 + ellipsis)", n)
	}
}
