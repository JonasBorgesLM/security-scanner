package attack

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
)

// There is no xss-reflected check yet (design doc §7 puts it after
// sqli-boolean), so these findings are built by hand rather than produced
// by a real scan — exactly the situation this Confirmer will face the
// first time such a check exists: a Finding shaped like any other, with no
// special knowledge of which check produced it beyond CapturedRequest.

func xssFinding(srv *httptest.Server, param, payload string) model.Finding {
	return model.Finding{
		CheckName: "xss-reflected",
		Endpoint:  model.Endpoint{Method: "GET", Path: "/search"},
		Request: model.CapturedRequest{
			Method:        "GET",
			URL:           srv.URL + "/search?q=" + payload,
			InjectedParam: param,
			Payload:       payload,
		},
	}
}

func TestXSSConfirmer_CheckName(t *testing.T) {
	if got := (xssConfirmer{}).CheckName(); got != "xss-reflected" {
		t.Errorf("CheckName() = %q, want xss-reflected", got)
	}
}

// reflectingServer echoes the `q` query parameter directly into an HTML
// page with no escaping — a textbook reflected-XSS sink.
func reflectingServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html><body>You searched for: %s</body></html>", r.URL.Query().Get("q"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestXSSConfirmer_ConfirmsUnescapedReflection(t *testing.T) {
	srv := reflectingServer(t)
	f := xssFinding(srv, "q", "test")

	got, err := (xssConfirmer{}).Confirm(t.Context(), f, http.DefaultClient)
	if err != nil {
		t.Fatalf("Confirm() error = %v", err)
	}
	if !got.Confirmed {
		t.Fatalf("Confirmed = false, want true; evidence: %s", got.Evidence.ResponseSnippet)
	}
	if !strings.Contains(got.Evidence.ResponseSnippet, "unescaped") {
		t.Errorf("Evidence = %q, want it to say unescaped", got.Evidence.ResponseSnippet)
	}
	if got.Request.Payload == f.Request.Payload {
		t.Error("Request.Payload was not replaced with the fresh marker")
	}
	if !strings.Contains(got.Request.Payload, "<xsscanary-") {
		t.Errorf("Request.Payload = %q, want the fresh marker shape", got.Request.Payload)
	}
}

func TestXSSConfirmer_UsesAFreshMarkerNotTheOriginalPayload(t *testing.T) {
	var lastQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastQuery = r.URL.Query().Get("q")
		fmt.Fprintf(w, "echo: %s", lastQuery)
	}))
	t.Cleanup(srv.Close)

	f := xssFinding(srv, "q", "<script>alert(1)</script>")
	if _, err := (xssConfirmer{}).Confirm(t.Context(), f, http.DefaultClient); err != nil {
		t.Fatalf("Confirm() error = %v", err)
	}
	if strings.Contains(lastQuery, "alert(1)") {
		t.Errorf("server received the original scan-time payload %q, want a fresh marker instead", lastQuery)
	}
	if !strings.Contains(lastQuery, "xsscanary-") {
		t.Errorf("server received %q, want the fresh marker shape", lastQuery)
	}
}

// escapingServer HTML-escapes the parameter before echoing it — not
// exploitable, and the Confirmer must say so rather than reporting either
// "confirmed" or a bare "not found".
func escapingServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		escaped := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&#34;", "'", "&#39;").Replace(q)
		fmt.Fprintf(w, "<html><body>You searched for: %s</body></html>", escaped)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestXSSConfirmer_EscapedReflectionIsNotConfirmed(t *testing.T) {
	srv := escapingServer(t)
	f := xssFinding(srv, "q", "test")

	got, err := (xssConfirmer{}).Confirm(t.Context(), f, http.DefaultClient)
	if err != nil {
		t.Fatalf("Confirm() error = %v", err)
	}
	if got.Confirmed {
		t.Error("Confirmed = true, want false — an HTML-escaped reflection is not exploitable")
	}
	if !strings.Contains(got.Evidence.ResponseSnippet, "escaped") {
		t.Errorf("Evidence = %q, want it to say the marker was escaped", got.Evidence.ResponseSnippet)
	}
}

func TestXSSConfirmer_NoReflectionAtAllIsNotConfirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><body>nothing to see here</body></html>")
	}))
	t.Cleanup(srv.Close)

	f := xssFinding(srv, "q", "test")
	got, err := (xssConfirmer{}).Confirm(t.Context(), f, http.DefaultClient)
	if err != nil {
		t.Fatalf("Confirm() error = %v", err)
	}
	if got.Confirmed {
		t.Error("Confirmed = true, want false")
	}
	if !strings.Contains(got.Evidence.ResponseSnippet, "did not reproduce") {
		t.Errorf("Evidence = %q, want it to say so", got.Evidence.ResponseSnippet)
	}
}

func TestXSSConfirmer_PathParameterInjection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/users/")
		fmt.Fprintf(w, "<html><body>Profile: %s</body></html>", name)
	}))
	t.Cleanup(srv.Close)

	f := model.Finding{
		CheckName: "xss-reflected",
		Endpoint:  model.Endpoint{Method: "GET", Path: "/users/{name}"},
		Request: model.CapturedRequest{
			Method:        "GET",
			URL:           srv.URL + "/users/test",
			InjectedParam: "name",
			Payload:       "test",
		},
	}

	got, err := (xssConfirmer{}).Confirm(t.Context(), f, http.DefaultClient)
	if err != nil {
		t.Fatalf("Confirm() error = %v", err)
	}
	if !got.Confirmed {
		t.Fatalf("Confirmed = false, want true; evidence: %s", got.Evidence.ResponseSnippet)
	}
}

func TestXSSConfirmer_UnreachableTargetIsAnError(t *testing.T) {
	f := model.Finding{
		CheckName: "xss-reflected",
		Request: model.CapturedRequest{
			Method:        "GET",
			URL:           "http://127.0.0.1:1/search?q=test",
			InjectedParam: "q",
			Payload:       "test",
		},
	}
	if _, err := (xssConfirmer{}).Confirm(t.Context(), f, http.DefaultClient); err == nil {
		t.Fatal("Confirm() error = nil, want an error for an unreachable target")
	}
}

func TestFreshMarker_IsUniqueEachCall(t *testing.T) {
	a, err := freshMarker()
	if err != nil {
		t.Fatalf("freshMarker() error = %v", err)
	}
	b, err := freshMarker()
	if err != nil {
		t.Fatalf("freshMarker() error = %v", err)
	}
	if a == b {
		t.Error("two calls to freshMarker() produced the same value")
	}
	if len(a) != 16 { // 8 bytes, hex-encoded
		t.Errorf("freshMarker() = %q, want 16 hex characters", a)
	}
}
