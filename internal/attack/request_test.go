package attack

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWithInjectedValue_QueryParameter(t *testing.T) {
	got, err := withInjectedValue("http://lab.invalid/items?id=old&other=1", "id", "old", "new")
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if got != "http://lab.invalid/items?id=new&other=1" {
		t.Errorf("got %q", got)
	}
}

func TestWithInjectedValue_ParamNotFoundAnywhere(t *testing.T) {
	_, err := withInjectedValue("http://lab.invalid/items?other=1", "id", "old", "new")
	if err == nil {
		t.Fatal("error = nil, want an error when the parameter is not in the query or the path")
	}
}

func TestWithInjectedValue_UnparseableURL(t *testing.T) {
	_, err := withInjectedValue("http://[::1]:namedport/x", "id", "old", "new")
	if err == nil {
		t.Fatal("error = nil, want a parse error")
	}
}

func TestGet_BuildRequestError(t *testing.T) {
	_, err := get(context.Background(), http.DefaultClient, "BAD METHOD", "http://lab.invalid/x")
	if err == nil {
		t.Fatal("error = nil, want an error for an invalid method")
	}
}

func TestGet_TransportError(t *testing.T) {
	_, err := get(context.Background(), http.DefaultClient, "GET", "http://127.0.0.1:1/x")
	if err == nil {
		t.Fatal("error = nil, want a transport error for an unreachable host")
	}
}

// errBodyClient answers with a body that fails to read, exercising get()'s
// io.ReadAll error path — not reachable through a real httptest.Server,
// which always serves a well-formed body.
type errBodyClient struct{}

func (errBodyClient) Do(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       readErrCloser{},
		Request:    req,
	}, nil
}

type readErrCloser struct{}

func (readErrCloser) Read([]byte) (int, error) { return 0, errors.New("simulated read failure") }
func (readErrCloser) Close() error             { return nil }

func TestGet_ReadBodyError(t *testing.T) {
	_, err := get(context.Background(), errBodyClient{}, "GET", "http://lab.invalid/x")
	if err == nil {
		t.Fatal("error = nil, want an error when the body cannot be read")
	}
}

func TestSnippetOf(t *testing.T) {
	if got := snippetOf(nil, 100); got != "<empty body>" {
		t.Errorf("snippetOf(nil) = %q", got)
	}
	if got := snippetOf([]byte("  a   b  "), 100); got != "a b" {
		t.Errorf("collapsed whitespace = %q, want %q", got, "a b")
	}
	long := strings.Repeat("x", 150)
	got := snippetOf([]byte(long), 100)
	if !strings.HasSuffix(got, "…") {
		t.Error("snippetOf() did not truncate a long body")
	}
	if r := []rune(got); len(r) != 101 {
		t.Errorf("truncated length = %d, want 101 (100 + ellipsis)", len(r))
	}
}

func TestAbsInt(t *testing.T) {
	tests := []struct{ in, want int }{{5, 5}, {-5, 5}, {0, 0}}
	for _, tt := range tests {
		if got := absInt(tt.in); got != tt.want {
			t.Errorf("absInt(%d) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

// A live server is used here (rather than a fake) so get() is also proven
// against a real response, not just the two synthetic failure doubles
// above.
func TestGet_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		w.Write([]byte("hello"))
	}))
	t.Cleanup(srv.Close)

	res, err := get(context.Background(), http.DefaultClient, "GET", srv.URL)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if res.status != http.StatusTeapot {
		t.Errorf("status = %d, want %d", res.status, http.StatusTeapot)
	}
	if string(res.body) != "hello" {
		t.Errorf("body = %q", res.body)
	}
}
