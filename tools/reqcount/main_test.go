package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestProxy_CountsWhatCrossedAndChangesNothing covers both halves of the
// tool's contract at once. The counts are the point; leaving the response
// untouched is what makes them mean anything, since a proxy that altered
// what the scanner saw would be measuring its own interference.
func TestProxy_CountsWhatCrossedAndChangesNothing(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.Header().Set("X-Lab", "kept")
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, `{"ok":true}`)
		default:
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"error":"nope"}`)
		}
	}))
	t.Cleanup(upstream.Close)

	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	c := &counter{byMethodStatus: map[string]int{}, byPath: map[string]int{}}
	front := httptest.NewServer(newProxy(target, c))
	t.Cleanup(front.Close)

	for range 2 {
		resp, err := http.Get(front.URL + "/ok")
		if err != nil {
			t.Fatalf("Get() error = %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if got, want := string(body), `{"ok":true}`; got != want {
			t.Errorf("body through the proxy = %q, want %q unchanged", got, want)
		}
		if got := resp.Header.Get("X-Lab"); got != "kept" {
			t.Errorf("X-Lab = %q, want it forwarded untouched", got)
		}
	}

	resp, err := http.Get(front.URL + "/missing")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want the upstream's %d", resp.StatusCode, http.StatusNotFound)
	}

	if c.total != 3 {
		t.Errorf("total = %d, want 3", c.total)
	}
	if got := c.byMethodStatus["GET -> 200"]; got != 2 {
		t.Errorf("GET -> 200 = %d, want 2", got)
	}
	if got := c.byMethodStatus["GET -> 404"]; got != 1 {
		t.Errorf("GET -> 404 = %d, want 1", got)
	}
	if got := c.byPath["/ok"]; got != 2 {
		t.Errorf("/ok = %d, want 2", got)
	}
}

// TestProxy_CountsAHopThatFailed guards the honesty of the total: a request
// the upstream never answered was still spent, and dropping it would make
// the tool flatter the scanner it exists to measure.
func TestProxy_CountsAHopThatFailed(t *testing.T) {
	// A port nothing is listening on.
	target, err := url.Parse("http://127.0.0.1:1")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	c := &counter{byMethodStatus: map[string]int{}, byPath: map[string]int{}}
	front := httptest.NewServer(newProxy(target, c))
	t.Cleanup(front.Close)

	resp, err := http.Get(front.URL + "/unreachable")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	resp.Body.Close()

	if c.total != 1 {
		t.Fatalf("total = %d, want the failed hop counted", c.total)
	}
	if got := c.byMethodStatus["GET -> 599"]; got != 1 {
		t.Errorf("GET -> 599 = %d, want the failed hop under a distinguishable code", got)
	}
}

// TestCounter_WriteIsStable pins the property the summary is compared on:
// two runs that saw the same traffic must produce the same bytes, or the
// measurement cannot be diffed against a recorded baseline.
func TestCounter_WriteIsStable(t *testing.T) {
	build := func() *counter {
		c := &counter{byMethodStatus: map[string]int{}, byPath: map[string]int{}}
		for _, p := range []string{"/b", "/a", "/c", "/a"} {
			c.record(http.MethodGet, p, http.StatusOK)
		}
		return c
	}

	dir := t.TempDir()
	first, second := filepath.Join(dir, "1.json"), filepath.Join(dir, "2.json")
	if err := build().write(first); err != nil {
		t.Fatalf("write() error = %v", err)
	}
	if err := build().write(second); err != nil {
		t.Fatalf("write() error = %v", err)
	}

	a, b := readFile(t, first), readFile(t, second)
	if a != b {
		t.Errorf("two identical measurements differ:\n%s\n---\n%s", a, b)
	}

	var s summary
	if err := json.Unmarshal([]byte(a), &s); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if s.Total != 4 || s.ByPath["/a"] != 2 {
		t.Errorf("summary = %+v, want 4 requests with /a twice", s)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	return string(data)
}

// TestCounter_WriteKeepsTheArrowReadable guards a small thing that makes
// the output usable: encoding/json escapes > by default, which turns the
// "GET -> 200" keys into "GET -> 200" and makes the summary neither
// readable nor greppable.
func TestCounter_WriteKeepsTheArrowReadable(t *testing.T) {
	c := &counter{byMethodStatus: map[string]int{}, byPath: map[string]int{}}
	c.record(http.MethodGet, "/x", http.StatusOK)

	path := filepath.Join(t.TempDir(), "s.json")
	if err := c.write(path); err != nil {
		t.Fatalf("write() error = %v", err)
	}

	got := readFile(t, path)
	if !strings.Contains(got, "GET -> 200") {
		t.Errorf("summary = %s\nwant a literal \"GET -> 200\" key", got)
	}
	if strings.Contains(got, `\u003e`) {
		t.Error("summary escaped > as \\u003e; SetEscapeHTML(false) is what keeps it readable")
	}
}
