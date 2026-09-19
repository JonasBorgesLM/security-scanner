package attack

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
)

func verboseFinding(url string) model.Finding {
	return model.Finding{
		CheckName: "verbose-errors",
		Endpoint:  model.Endpoint{Method: http.MethodGet, Path: "/x"},
		Request:   model.CapturedRequest{Method: http.MethodGet, URL: url, InjectedParam: "q", Payload: `']["`},
	}
}

// TestVerboseConfirmer_ReproducesWhenMalformedLeaksAndBenignDoesNot is the
// reproduction the plan asks for: not just that the malformed request leaks,
// but that a benign one at the same parameter does not — so the leak is the
// malformed input's doing.
func TestVerboseConfirmer_ReproducesWhenMalformedLeaksAndBenignDoesNot(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("q") == "1" {
			fmt.Fprint(w, `{"ok":true}`)
			return
		}
		fmt.Fprint(w, "goroutine 1 [running]:\nmain.h()\n\t/app/h.go:9 +0x1")
	}))
	t.Cleanup(srv.Close)

	got, err := verboseConfirmer{}.Confirm(t.Context(), verboseFinding(srv.URL+"/x?q=%27%5D%5B"),
		model.Clients{Default: http.DefaultClient})
	if err != nil {
		t.Fatalf("Confirm() error = %v", err)
	}
	if !got.Confirmed {
		t.Error("Confirmed = false, want the leak reproduced")
	}
}

// TestVerboseConfirmer_BenignLeaksTooDoesNotConfirm is the discriminator:
// when the endpoint returns internal detail regardless of input, the
// malformed value is not the cause and it must not confirm.
func TestVerboseConfirmer_BenignLeaksTooDoesNotConfirm(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Traceback (most recent call last):\n  File \"a.py\", line 1")
	}))
	t.Cleanup(srv.Close)

	got, err := verboseConfirmer{}.Confirm(t.Context(), verboseFinding(srv.URL+"/x?q=%27%5D%5B"),
		model.Clients{Default: http.DefaultClient})
	if err != nil {
		t.Fatalf("Confirm() error = %v", err)
	}
	if got.Confirmed {
		t.Error("Confirmed = true where a benign value leaks too")
	}
	if !strings.Contains(got.Evidence.ResponseSnippet, "benign value") {
		t.Errorf("evidence = %q, want it to explain why it did not confirm", got.Evidence.ResponseSnippet)
	}
}
