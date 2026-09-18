package engine

import (
	"context"
	"net/http"
	"testing"

	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
	"github.com/JonasBorgesLM/security-scanner/internal/ports"
)

func targetWith(ep model.Endpoint, status int, probedMethod string) model.Target {
	return model.Target{
		Endpoint: ep,
		Baseline: &model.Response{
			URL:          testBaseURL + ep.Path,
			StatusCode:   status,
			ProbedMethod: probedMethod,
			Headers:      http.Header{},
		},
	}
}

// TestAbsentFromTarget_OnlyTheUnambiguous404Counts is the whole rule, and
// the three false cases matter more than the true one: 404 is ambiguous,
// and acting on the wrong reading of it would skip routes that are really
// there.
func TestAbsentFromTarget_OnlyTheUnambiguous404Counts(t *testing.T) {
	get := func(path string) model.Endpoint {
		return model.Endpoint{Method: http.MethodGet, Path: path}
	}

	tests := []struct {
		name   string
		target model.Target
		want   bool
		why    string
	}{
		{
			name:   "404 on its own method, no path parameter",
			target: targetWith(get("/links"), http.StatusNotFound, http.MethodGet),
			want:   true,
			why:    "nothing else can explain this 404",
		},
		{
			name:   "404 but the path has a parameter",
			target: targetWith(get("/items/{id}"), http.StatusNotFound, http.MethodGet),
			want:   false,
			why:    "collection substituted a placeholder id; the resource may simply not exist",
		},
		{
			name:   "404 but the method was substituted",
			target: targetWith(model.Endpoint{Method: http.MethodPost, Path: "/links"}, http.StatusNotFound, http.MethodGet),
			want:   false,
			why:    "a POST route can answer 404 to GET for having no GET handler",
		},
		{
			name:   "a 405 is not a 404",
			target: targetWith(get("/links"), http.StatusMethodNotAllowed, http.MethodGet),
			want:   false,
			why:    "405 means the path exists",
		},
		{
			name:   "a route that answered",
			target: targetWith(get("/links"), http.StatusOK, http.MethodGet),
			want:   false,
		},
		{
			name:   "no baseline at all",
			target: model.Target{Endpoint: get("/links")},
			want:   false,
			why:    "collection failed; that is a different gap, with its own reason",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AbsentFromTarget(tt.target); got != tt.want {
				t.Errorf("AbsentFromTarget() = %v, want %v — %s", got, tt.want, tt.why)
			}
		})
	}
}

// TestBuildJobs_SchedulesNothingForAnAbsentRoute is the saving. Every job
// built for a route that is not there is traffic spent on nothing, and the
// live run that motivated this found 109 of 278 requests going to 404s.
func TestBuildJobs_SchedulesNothingForAnAbsentRoute(t *testing.T) {
	check := &stubCheck{
		meta: model.CheckMetadata{Name: "any", Kind: model.KindPassive},
		run: func(context.Context, model.Target, ports.HTTPClient) ([]model.Finding, error) {
			return nil, nil
		},
	}

	absent := targetWith(model.Endpoint{Method: http.MethodGet, Path: "/gone"}, http.StatusNotFound, http.MethodGet)
	present := targetWith(model.Endpoint{Method: http.MethodGet, Path: "/here"}, http.StatusOK, http.MethodGet)

	jobs := newEngine(t, false).BuildJobs([]model.Target{absent, present}, []model.Check{check})

	if len(jobs) != 1 {
		t.Fatalf("got %d jobs, want 1 — only the route that exists should be scheduled", len(jobs))
	}
	if got := jobs[0].Target.Endpoint.Path; got != "/here" {
		t.Errorf("scheduled %q, want the present route", got)
	}
}

// TestBuildJobs_StillSchedulesAnAmbiguous404 is the control. Erring towards
// "absent" would be a silent loss of coverage on every parameterised route
// whose placeholder id happens not to exist, which is most of them.
func TestBuildJobs_StillSchedulesAnAmbiguous404(t *testing.T) {
	check := &stubCheck{
		meta: model.CheckMetadata{Name: "any", Kind: model.KindPassive},
		run: func(context.Context, model.Target, ports.HTTPClient) ([]model.Finding, error) {
			return nil, nil
		},
	}

	ambiguous := targetWith(model.Endpoint{Method: http.MethodGet, Path: "/items/{id}"}, http.StatusNotFound, http.MethodGet)

	if jobs := newEngine(t, false).BuildJobs([]model.Target{ambiguous}, []model.Check{check}); len(jobs) != 1 {
		t.Errorf("got %d jobs, want 1 — a 404 on a placeholder id does not prove the route is gone", len(jobs))
	}
}
