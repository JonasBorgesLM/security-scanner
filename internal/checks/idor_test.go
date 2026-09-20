package checks

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
)

// userClient tags every request with a user, the way two Authenticators
// holding different credentials do.
type userClient struct{ user string }

func (c userClient) Do(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header.Set("X-User", c.user)
	return http.DefaultTransport.RoundTrip(clone)
}

// newTasksServer serves /tasks scoped to the caller and /tasks/{id} either
// scoped or not, depending on enforced.
func newTasksServer(t *testing.T, enforced bool) *httptest.Server {
	t.Helper()
	owner := map[string]string{"1": "alice", "2": "alice", "9": "bob"}

	mux := http.NewServeMux()
	mux.HandleFunc("/tasks", func(w http.ResponseWriter, r *http.Request) {
		user := r.Header.Get("X-User")
		var ids []string
		for _, id := range []string{"1", "2", "9"} {
			if owner[id] == user {
				ids = append(ids, id)
			}
		}
		parts := make([]string, len(ids))
		for i, id := range ids {
			parts[i] = fmt.Sprintf(`{"id":%s,"title":"t"}`, id)
		}
		fmt.Fprintf(w, `{"data":[%s]}`, strings.Join(parts, ","))
	})
	mux.HandleFunc("/tasks/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/tasks/")
		if enforced && owner[id] != r.Header.Get("X-User") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		fmt.Fprintf(w, `{"id":%s,"title":"secret of %s"}`, id, owner[id])
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func idorTarget(srv *httptest.Server) model.Target {
	return model.Target{
		Endpoint: model.Endpoint{Method: http.MethodGet, Path: "/tasks/{id}", RequiresAuth: true},
		Baseline: &model.Response{URL: srv.URL + "/tasks/1", StatusCode: 200, ProbedMethod: http.MethodGet},
	}
}

func idorClients(secondary bool) model.Clients {
	c := model.Clients{Default: userClient{"alice"}, Anonymous: http.DefaultClient}
	if secondary {
		c.Secondary = userClient{"bob"}
	}
	return c
}

// TestIDOR_FindsACrossAccountRead is the finding: bob reads a task that is
// listed for alice and not for bob.
func TestIDOR_FindsACrossAccountRead(t *testing.T) {
	srv := newTasksServer(t, false)

	findings, err := (&idor{}).Run(t.Context(), idorTarget(srv), idorClients(true))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if !strings.Contains(findings[0].Evidence.ResponseSnippet, "secret of alice") {
		t.Errorf("evidence = %q, want the other user's data it actually read", findings[0].Evidence.ResponseSnippet)
	}
}

// TestIDOR_EnforcedIsClean is the control: the same server checking
// ownership produces no finding and no gap.
func TestIDOR_EnforcedIsClean(t *testing.T) {
	srv := newTasksServer(t, true)

	findings, err := (&idor{}).Run(t.Context(), idorTarget(srv), idorClients(true))
	if err != nil {
		t.Fatalf("Run() error = %v, want a clean verdict", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings against a server that enforces ownership, want 0", len(findings))
	}
}

// TestIDOR_SharedResourcesProveNothing is the discrimination the check
// turns on, and the reason reading one collection is not enough.
//
// When both accounts list the same resources, a successful read by the
// second is the API working as designed. A check that tried the first id it
// saw would report every shared-data endpoint as broken.
func TestIDOR_SharedResourcesProveNothing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/tasks" {
			fmt.Fprint(w, `{"data":[{"id":1},{"id":2}]}`)
			return
		}
		fmt.Fprint(w, `{"id":1,"title":"shared"}`)
	}))
	t.Cleanup(srv.Close)

	findings, err := (&idor{}).Run(t.Context(), idorTarget(srv), idorClients(true))

	if len(findings) != 0 {
		t.Errorf("got %d findings where both accounts see the same resources, want 0", len(findings))
	}
	if !errors.Is(err, model.ErrSkipped) {
		t.Fatalf("err = %v, want a skip — nothing here belongs to one account and not the other", err)
	}
	if !strings.Contains(err.Error(), "would prove nothing") {
		t.Errorf("reason = %q, want it to explain why it stopped", err)
	}
}

// TestIDOR_NoSecondAccountIsASkipNamingTheSetting keeps the check from
// comparing a user with itself, and says which line is missing.
func TestIDOR_NoSecondAccountIsASkipNamingTheSetting(t *testing.T) {
	srv := newTasksServer(t, false)

	_, err := (&idor{}).Run(t.Context(), idorTarget(srv), idorClients(false))
	if !errors.Is(err, model.ErrSkipped) {
		t.Fatalf("err = %v, want a skip", err)
	}
	if !strings.Contains(err.Error(), "auth.secondary_credentials") {
		t.Errorf("reason = %q, want it to name the setting that is missing", err)
	}
}

// TestIDOR_PicksTheSameResourceEveryRun pins determinism. findings.json is
// compared between runs, so choosing whichever id the target happened to
// list first would make an unchanged target produce a different finding
// every scan.
func TestIDOR_PicksTheSameResourceEveryRun(t *testing.T) {
	first := onlyInFirst([]string{"9", "2", "1"}, []string{"9"})
	second := onlyInFirst([]string{"2", "1", "9"}, []string{"9"})

	if first != second {
		t.Errorf("two orderings of the same sets chose %q and %q", first, second)
	}
	if first != "1" {
		t.Errorf("chose %q, want the smallest candidate", first)
	}
}

// TestIDOR_AppliesOnlyToSafeDetailRoutes pins what it will ever be pointed
// at: a GET whose last path segment is a parameter. Writing to someone
// else's resource to prove the point is the thing this project refuses.
func TestIDOR_AppliesOnlyToSafeDetailRoutes(t *testing.T) {
	applies := (&idor{}).Metadata().AppliesTo

	tests := []struct {
		method, path string
		want         bool
	}{
		{"GET", "/tasks/{id}", true},
		{"GET", "/v1/tasks/{id}", true},
		// A nested detail route has no single concrete collection to list —
		// the collection path still holds {uid} — so it is left alone
		// rather than probed on a literal "{uid}" path.
		{"GET", "/v1/users/{uid}/posts/{pid}", false},
		// A root-level detail route has no collection prefix at all — found
		// live against the task-api's short-link resolver (GET /{code}),
		// which the check tried to "list" at the bare origin and produced
		// a confusing "could not list  as the first account" skip.
		{"GET", "/{code}", false},
		{"GET", "/tasks", false},
		{"GET", "/tasks/{id}/attachments", false},
		{"DELETE", "/tasks/{id}", false},
		{"POST", "/tasks/{id}", false},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			if got := applies(model.Endpoint{Method: tt.method, Path: tt.path}); got != tt.want {
				t.Errorf("AppliesTo = %v, want %v", got, tt.want)
			}
		})
	}
}
