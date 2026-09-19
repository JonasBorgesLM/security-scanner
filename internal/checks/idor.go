package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
	"github.com/JonasBorgesLM/security-scanner/internal/ports"
)

func init() {
	RegisterCheck(&idor{})
}

// trailingPathParam matches a path whose LAST segment is a template
// parameter, which is what a detail route looks like: /v1/tasks/{id}.
var trailingPathParam = regexp.MustCompile(`^(.*)/\{[^/{}]+\}$`)

// idCandidateLimit bounds how many identifiers are pulled out of a
// collection response. One is enough to prove the point; the rest exist so
// the check can find one that belongs to A and not to B.
const idCandidateLimit = 50

// idor asks whether one user's resource can be read with another user's
// session — OWASP's Broken Object Level Authorization, and the single most
// common real failure in APIs that are otherwise well built.
//
// # Why it needed a second identity, and why that was the hard part
//
// The evolution plan filed this as the hardest item on the roadmap and
// blamed the two-user config. That was wrong. The obstacle was that a check
// was handed exactly one client and the Authenticator injected the token
// into everything, so "ask as somebody else" was not a question a check
// could pose at all. Once Clients carried a second account, the config was
// four lines.
//
// # How it finds a resource that belongs to A
//
// This is the actual work, and it is where a black-box check has to be
// careful. Reading A's collection and trying one of its identifiers as B
// proves nothing on its own: the two users may legitimately see the same
// resources, and a 200 would then be the API working.
//
// So both collections are read, and the check only proceeds with an
// identifier present in A's and ABSENT from B's. A 200 on that is not
// ambiguous — B fetched something B cannot otherwise see.
//
// The smallest such identifier is chosen rather than the first, so two
// scans of an unchanged target pick the same one and produce the same
// finding ID.
type idor struct{}

var _ model.Check = (*idor)(nil)

func (c *idor) Metadata() model.CheckMetadata {
	return model.CheckMetadata{
		Name:          "idor",
		OWASPCategory: "A01:2021-Broken Access Control",
		Severity:      "high",
		Kind:          model.KindActive,
		RequiresAuth:  true,
		AppliesTo: func(ep model.Endpoint) bool {
			// Only a safe method: reading someone else's resource is the
			// whole proof, and writing to it would be the thing this
			// project refuses to do.
			return ep.Method == http.MethodGet && trailingPathParam.MatchString(ep.Path)
		},
	}
}

func (c *idor) Run(ctx context.Context, t model.Target, clients model.Clients) ([]model.Finding, error) {
	if clients.Secondary == nil {
		return nil, model.Skippedf(
			"%s %s needs a second account to compare against, and config.yaml sets no auth.secondary_credentials",
			t.Endpoint.Method, t.Endpoint.Path)
	}
	if t.Baseline == nil {
		return nil, model.Skippedf("no baseline response for %s %s, so the target's origin is unknown: %v",
			t.Endpoint.Method, t.Endpoint.Path, t.BaselineErr)
	}
	base, err := url.Parse(t.Baseline.URL)
	if err != nil {
		return nil, model.Skippedf("baseline URL %q is not parseable: %v", t.Baseline.URL, err)
	}
	origin := &url.URL{Scheme: base.Scheme, Host: base.Host}

	collectionPath := trailingPathParam.FindStringSubmatch(t.Endpoint.Path)[1]
	collectionURL := origin.String() + collectionPath

	mine, err := identifiersAt(ctx, clients.Default, collectionURL)
	if err != nil {
		return nil, model.Skippedf("could not list %s as the first account, so no resource is known to belong to it: %v",
			collectionPath, err)
	}
	theirs, err := identifiersAt(ctx, clients.Secondary, collectionURL)
	if err != nil {
		return nil, model.Skippedf("could not list %s as the second account: %v", collectionPath, err)
	}

	target := onlyInFirst(mine, theirs)
	if target == "" {
		return nil, model.Skippedf(
			"no resource under %s belongs to the first account and not the second, so a successful read by the second would prove nothing",
			collectionPath)
	}

	detailURL := origin.String() + strings.Replace(t.Endpoint.Path,
		t.Endpoint.Path[len(collectionPath):], "/"+url.PathEscape(target), 1)

	res, err := fetch(ctx, clients.Secondary, detailURL)
	if err != nil {
		return nil, fmt.Errorf("checks: idor: reading %s as the second account: %w", detailURL, err)
	}

	switch {
	case res.status >= 200 && res.status < 300:
		return []model.Finding{{
			ID: "cross-account-read",
			Request: model.CapturedRequest{
				Method: http.MethodGet,
				URL:    detailURL,
			},
			Evidence: model.Evidence{
				StatusCode: res.status,
				ResponseSnippet: fmt.Sprintf(
					"resource %q is listed under %s for the first account and not for the second, yet the second account read it "+
						"directly and got %d. Object-level authorization is not being checked here. Response: %s",
					target, collectionPath, res.status, snippetOfN(res.body, sqliSnippetLimit)),
			},
		}}, nil

	case res.status == http.StatusUnauthorized || res.status == http.StatusForbidden || res.status == http.StatusNotFound:
		// Refused, which is the answer everyone wants. 404 counts: hiding
		// the existence of another user's resource is a legitimate way to
		// enforce this.
		return nil, nil

	default:
		return nil, model.Skippedf(
			"the second account got %d reading %s, which is neither a successful read nor a refusal",
			res.status, detailURL)
	}
}

// onlyInFirst returns the smallest identifier present in mine and absent
// from theirs, or "" when there is none.
//
// Smallest rather than first, because findings.json is compared between
// runs: picking whichever identifier the target happened to list first
// would make an unchanged target produce a different finding every scan.
func onlyInFirst(mine, theirs []string) string {
	excluded := make(map[string]bool, len(theirs))
	for _, id := range theirs {
		excluded[id] = true
	}

	var candidates []string
	for _, id := range mine {
		if !excluded[id] {
			candidates = append(candidates, id)
		}
	}
	if len(candidates) == 0 {
		return ""
	}
	slices.Sort(candidates)
	return candidates[0]
}

// identifiersAt reads a collection and pulls out the identifiers of the
// resources it lists.
//
// It is a heuristic, and a deliberately small one: the first JSON array it
// can find, and the "id" of each object in it. A richer extractor would
// guess more and be wrong in more ways; when this one finds nothing, the
// check says so and stops rather than inventing a resource to try.
func identifiersAt(ctx context.Context, client ports.HTTPClient, rawURL string) ([]string, error) {
	res, err := fetch(ctx, client, rawURL)
	if err != nil {
		return nil, err
	}
	if res.status < 200 || res.status >= 300 {
		return nil, fmt.Errorf("listing %s answered %d", rawURL, res.status)
	}

	var body any
	if err := json.Unmarshal(res.body, &body); err != nil {
		return nil, fmt.Errorf("listing %s is not JSON: %w", rawURL, err)
	}

	items := firstArray(body)
	if items == nil {
		return nil, fmt.Errorf("listing %s contains no array of resources", rawURL)
	}

	var out []string
	for _, item := range items {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if id := identifierOf(obj); id != "" {
			out = append(out, id)
		}
		if len(out) >= idCandidateLimit {
			break
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("listing %s has no recognisable identifiers", rawURL)
	}
	return out, nil
}

// firstArray finds the array of resources in a listing response, whether it
// is the whole body or wrapped in an envelope.
func firstArray(body any) []any {
	switch v := body.(type) {
	case []any:
		return v
	case map[string]any:
		// Sorted, so an envelope with several arrays yields the same one on
		// every run rather than whichever Go's map iteration hands over.
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, key := range keys {
			if arr, ok := v[key].([]any); ok {
				return arr
			}
		}
	}
	return nil
}

// identifierOf pulls the identifier out of one listed resource. Only "id",
// because guessing at "uuid", "slug", "code" and friends would mean trying
// a value that is not what the detail route takes.
func identifierOf(obj map[string]any) string {
	switch id := obj["id"].(type) {
	case string:
		return id
	case float64:
		// JSON numbers land as float64; an integer id must not come back
		// as "1e+06".
		return fmt.Sprintf("%.0f", id)
	}
	return ""
}

func fetch(ctx context.Context, client ports.HTTPClient, rawURL string) (*probeResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProbeBodyBytes))
	if err != nil {
		return nil, err
	}
	return &probeResult{url: rawURL, status: resp.StatusCode, body: body}, nil
}
