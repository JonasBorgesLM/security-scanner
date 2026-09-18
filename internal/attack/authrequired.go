package attack

import (
	"context"
	"fmt"
	"net/http"

	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
)

func init() {
	Register(authRequiredConfirmer{})
}

// authSnippetLimit bounds how much of the reproduced response is kept.
const authSnippetLimit = 300

// authRequiredConfirmer reproduces the simplest proof of concept in the
// project: send the same request with no credentials and see whether the
// target answers again.
//
// It is also the one that needed the second identity most. A Confirmer
// holding only the authenticated client could replay the URL and get a 200
// every time — proving nothing except that the credentials work.
//
// Like the check, it sends no body. Reproduction must not depend on
// creating anything, and a finding that only reproduces when something is
// written is not one this project is willing to confirm.
type authRequiredConfirmer struct{}

var _ Confirmer = authRequiredConfirmer{}

func (authRequiredConfirmer) CheckName() string { return "auth-required" }

func (authRequiredConfirmer) Confirm(ctx context.Context, f model.Finding, clients model.Clients) (model.Finding, error) {
	res, err := get(ctx, clients.Anonymous, f.Request.Method, f.Request.URL)
	if err != nil {
		return f, fmt.Errorf("replaying the request without credentials: %w", err)
	}

	if !statusIsSuccess(res.status) {
		f.Evidence.StatusCode = res.status
		f.Evidence.ResponseSnippet = fmt.Sprintf(
			"did not reproduce: the same request without credentials answered %d this time, so the route is not open now — "+
				"either the finding was wrong or the control was added since the scan",
			res.status)
		return f, nil
	}

	f.Confirmed = true
	f.Evidence.StatusCode = res.status
	f.Evidence.ResponseSnippet = fmt.Sprintf(
		"reproduced: %s %s answered %d with no credentials at all; response: %s",
		f.Endpoint.Method, f.Endpoint.Path, res.status, snippetOf(res.body, authSnippetLimit))
	return f, nil
}

// statusIsSuccess is kept explicit rather than inlined twice, since "what
// counts as the target having answered" is the entire judgement here.
func statusIsSuccess(code int) bool {
	return code >= http.StatusOK && code < http.StatusMultipleChoices
}
