package openapi

import (
	"reflect"
	"regexp"
	"testing"

	"github.com/JonasBorgesLM/warden/internal/core/model"
)

var uuidShape = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func endpoint(t *testing.T, endpoints []model.Endpoint, method, path string) model.Endpoint {
	t.Helper()
	for _, ep := range endpoints {
		if ep.Method == method && ep.Path == path {
			return ep
		}
	}
	t.Fatalf("endpoint %s %s not found", method, path)
	return model.Endpoint{}
}

func param(t *testing.T, ep model.Endpoint, in, name string) model.Parameter {
	t.Helper()
	for _, p := range ep.Parameters {
		if p.In == in && p.Name == name {
			return p
		}
	}
	t.Fatalf("parameter %s:%s not found on %s %s", in, name, ep.Method, ep.Path)
	return model.Parameter{}
}

func TestLoad(t *testing.T) {
	endpoints, err := Load(t.Context(), "testdata/lab-api.yaml")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	const wantCount = 6
	if len(endpoints) != wantCount {
		t.Fatalf("got %d endpoints, want %d", len(endpoints), wantCount)
	}

	t.Run("public endpoint overrides top-level security", func(t *testing.T) {
		ep := endpoint(t, endpoints, "GET", "/health")
		if ep.RequiresAuth {
			t.Errorf("RequiresAuth = true, want false (operation-level security: [] overrides doc default)")
		}
		if ep.SecurityScheme != "" {
			t.Errorf("SecurityScheme = %q, want empty", ep.SecurityScheme)
		}
		if ep.Destructive {
			t.Errorf("Destructive = true, want false")
		}
	})

	t.Run("query parameter and inherited top-level security", func(t *testing.T) {
		ep := endpoint(t, endpoints, "GET", "/items")
		if !ep.RequiresAuth {
			t.Errorf("RequiresAuth = false, want true (inherited from doc-level security)")
		}
		if ep.SecurityScheme != "bearerAuth" {
			t.Errorf("SecurityScheme = %q, want bearerAuth", ep.SecurityScheme)
		}

		q := param(t, ep, "query", "q")
		if q.Type != "string" || q.Required {
			t.Errorf("param q = %+v, want type=string required=false", q)
		}
	})

	t.Run("request body flattened into body parameters", func(t *testing.T) {
		ep := endpoint(t, endpoints, "POST", "/items")
		if !ep.RequiresAuth || ep.SecurityScheme != "bearerAuth" {
			t.Errorf("POST /items auth = (%v, %q), want (true, bearerAuth)", ep.RequiresAuth, ep.SecurityScheme)
		}

		name := param(t, ep, "body", "name")
		if name.Type != "string" || !name.Required {
			t.Errorf("param name = %+v, want type=string required=true", name)
		}

		price := param(t, ep, "body", "price")
		if price.Type != "number" || price.Required {
			t.Errorf("param price = %+v, want type=number required=false", price)
		}
	})

	t.Run("path-level parameter inherited by operation", func(t *testing.T) {
		ep := endpoint(t, endpoints, "GET", "/items/{id}")
		id := param(t, ep, "path", "id")
		if id.Type != "string" || !id.Required {
			t.Errorf("param id = %+v, want type=string required=true", id)
		}
	})

	t.Run("PUT and DELETE are marked destructive", func(t *testing.T) {
		for _, method := range []string{"PUT", "DELETE"} {
			ep := endpoint(t, endpoints, method, "/items/{id}")
			if !ep.Destructive {
				t.Errorf("%s /items/{id}: Destructive = false, want true", method)
			}
			if !ep.RequiresAuth || ep.SecurityScheme != "bearerAuth" {
				t.Errorf("%s /items/{id}: auth = (%v, %q), want (true, bearerAuth)", method, ep.RequiresAuth, ep.SecurityScheme)
			}
			// Path parameter must still be present even though it's declared
			// at the path-item level, not repeated per-operation.
			id := param(t, ep, "path", "id")
			if !id.Required {
				t.Errorf("%s /items/{id}: param id.Required = false, want true", method)
			}
		}
	})

	t.Run("GET /items is never destructive", func(t *testing.T) {
		ep := endpoint(t, endpoints, "GET", "/items")
		if ep.Destructive {
			t.Errorf("GET /items: Destructive = true, want false")
		}
	})
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(t.Context(), "testdata/does-not-exist.yaml"); err == nil {
		t.Fatal("Load with missing file: got nil error, want non-nil")
	}
}

func TestLoadInvalidSpec(t *testing.T) {
	if _, err := Load(t.Context(), "testdata/invalid.yaml"); err == nil {
		t.Fatal("Load with invalid spec: got nil error, want non-nil")
	}
}

func TestLoad_SecurityVariants(t *testing.T) {
	endpoints, err := Load(t.Context(), "testdata/security-variants.yaml")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	t.Run("AND-combined schemes pick the first alphabetically", func(t *testing.T) {
		ep := endpoint(t, endpoints, "GET", "/combined")
		if !ep.RequiresAuth {
			t.Errorf("RequiresAuth = false, want true")
		}
		if ep.SecurityScheme != "apiKeyAuth" {
			t.Errorf("SecurityScheme = %q, want apiKeyAuth (lowest of the three names)", ep.SecurityScheme)
		}
	})

	t.Run("OR alternatives use the first listed requirement", func(t *testing.T) {
		ep := endpoint(t, endpoints, "GET", "/alternatives")
		if !ep.RequiresAuth {
			t.Errorf("RequiresAuth = false, want true")
		}
		if ep.SecurityScheme != "bearerAuth" {
			t.Errorf("SecurityScheme = %q, want bearerAuth (first entry in the list)", ep.SecurityScheme)
		}
	})

	t.Run("an empty requirement makes the route public", func(t *testing.T) {
		// The empty alternative must win from either position in the list.
		for _, path := range []string{"/optional-auth", "/optional-auth-last"} {
			ep := endpoint(t, endpoints, "GET", path)
			if ep.RequiresAuth {
				t.Errorf("%s: RequiresAuth = true, want false — an empty `security` entry means auth is optional", path)
			}
			if ep.SecurityScheme != "" {
				t.Errorf("%s: SecurityScheme = %q, want empty", path, ep.SecurityScheme)
			}
		}
	})
}

// Parsing the same spec repeatedly must produce byte-identical results.
// findings.json is committed and reviewed by hand, so any instability here
// would surface as phantom diffs between two scans of an unchanged spec.
func TestLoad_IsDeterministic(t *testing.T) {
	first, err := Load(t.Context(), "testdata/security-variants.yaml")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	// Enough repetitions that randomized map iteration would almost surely
	// have produced a different scheme name at least once.
	for i := range 50 {
		got, err := Load(t.Context(), "testdata/security-variants.yaml")
		if err != nil {
			t.Fatalf("Load returned error on run %d: %v", i, err)
		}
		if !reflect.DeepEqual(first, got) {
			t.Fatalf("run %d differs from the first run:\nfirst = %+v\ngot   = %+v", i, first, got)
		}
	}
}

func TestLoad_EndpointOrderIsStable(t *testing.T) {
	endpoints, err := Load(t.Context(), "testdata/lab-api.yaml")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	// Paths sorted lexicographically, methods in the fixed httpMethods order.
	want := []string{
		"GET /health",
		"GET /items",
		"POST /items",
		"GET /items/{id}",
		"PUT /items/{id}",
		"DELETE /items/{id}",
	}
	if len(endpoints) != len(want) {
		t.Fatalf("got %d endpoints, want %d", len(endpoints), len(want))
	}
	for i, w := range want {
		got := endpoints[i].Method + " " + endpoints[i].Path
		if got != w {
			t.Errorf("endpoints[%d] = %q, want %q", i, got, w)
		}
	}
}

// TestLoad_ParameterSample is the extraction half of the fix found running
// the scanner against the task-api: a strictly-typed parameter (an enum,
// a uuid path segment) rejects a generic filler exactly as it rejects an
// injection payload, so an active check never got past validation to test
// anything. Parameter.Sample is what lets a check reach past that — but
// only when the spec itself justifies a value; it must never invent one.
func TestLoad_ParameterSample(t *testing.T) {
	endpoints, err := Load(t.Context(), "testdata/sample-values.yaml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	t.Run("parameter-level example wins", func(t *testing.T) {
		ep := endpoint(t, endpoints, "GET", "/widgets/{id}")
		got := param(t, ep, "path", "id").Sample
		want := "f47ac10b-58cc-4372-a567-0e02b2c3d479"
		if got != want {
			t.Errorf("Sample = %q, want %q", got, want)
		}
	})

	t.Run("falls through to the schema's own example", func(t *testing.T) {
		ep := endpoint(t, endpoints, "GET", "/gadgets/{key}")
		got := param(t, ep, "path", "key").Sample
		if got != "on-the-schema" {
			t.Errorf("Sample = %q, want %q", got, "on-the-schema")
		}
	})

	ep := endpoint(t, endpoints, "GET", "/search")

	t.Run("plain enum: first declared member", func(t *testing.T) {
		got := param(t, ep, "query", "sort").Sample
		if got != "relevance" {
			t.Errorf("Sample = %q, want the first enum member %q", got, "relevance")
		}
	})

	t.Run("array of enum: resolved via Items", func(t *testing.T) {
		got := param(t, ep, "query", "status").Sample
		if got != "pending" {
			t.Errorf("Sample = %q, want the first member of the item schema's enum %q", got, "pending")
		}
	})

	t.Run("format uuid with nothing else: synthetic placeholder", func(t *testing.T) {
		got := param(t, ep, "query", "token").Sample
		if got == "" {
			t.Fatal("Sample is empty for a format: uuid parameter")
		}
		if !uuidShape.MatchString(got) {
			t.Errorf("Sample = %q is not shaped like a UUID", got)
		}
	})

	t.Run("nothing the spec can offer: Sample stays empty", func(t *testing.T) {
		got := param(t, ep, "query", "q").Sample
		if got != "" {
			t.Errorf("Sample = %q, want empty — nothing in the spec justifies a value, and a caller must fall back to its own filler",
				got)
		}
	})

	t.Run("body property enum", func(t *testing.T) {
		op := endpoint(t, endpoints, "POST", "/reports")
		got := param(t, op, "body", "format").Sample
		if got != "pdf" {
			t.Errorf("Sample = %q, want the first enum member %q", got, "pdf")
		}
	})
}
