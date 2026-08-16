// Package openapi parses an OpenAPI 3 spec file into the []model.Endpoint
// slice the rest of the pipeline consumes.
package openapi

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"slices"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
)

// httpMethods lists the operations PathItem exposes, in a fixed order, so
// Load produces deterministic output regardless of map iteration order.
var httpMethods = []string{
	http.MethodGet,
	http.MethodPost,
	http.MethodPut,
	http.MethodPatch,
	http.MethodDelete,
	http.MethodHead,
	http.MethodOptions,
	http.MethodTrace,
	http.MethodConnect,
}

// destructiveMethods are skipped by the engine unless explicitly opted in
// (see model.Endpoint.Destructive and CLAUDE.md invariant #2).
var destructiveMethods = map[string]bool{
	http.MethodDelete: true,
	http.MethodPut:    true,
	http.MethodPatch:  true,
}

// Load reads and validates an OpenAPI 3 spec file at path and converts every
// operation into a model.Endpoint.
//
// ctx is threaded into the loader and the validation pass so this stage
// participates in the scan's global deadline like every other stage. Note
// that parsing a local spec with external refs disabled is CPU-bound and
// kin-openapi does not poll for cancellation along that path, so in practice
// Load returns before a deadline would ever fire; the parameter is what
// keeps the contract uniform, not a promise of preemption.
func Load(ctx context.Context, path string) ([]model.Endpoint, error) {
	loader := openapi3.NewLoader()
	loader.Context = ctx
	loader.IsExternalRefsAllowed = false

	doc, err := loader.LoadFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("openapi: load %s: %w", path, err)
	}

	if err := doc.Validate(ctx); err != nil {
		return nil, fmt.Errorf("openapi: validate %s: %w", path, err)
	}

	var endpoints []model.Endpoint
	for _, p := range sortedPaths(doc) {
		item := doc.Paths.Value(p)
		ops := item.Operations()
		for _, method := range httpMethods {
			op, ok := ops[method]
			if !ok {
				continue
			}
			endpoints = append(endpoints, toEndpoint(doc, method, p, item, op))
		}
	}

	return endpoints, nil
}

func sortedPaths(doc *openapi3.T) []string {
	return slices.Sorted(maps.Keys(doc.Paths.Map()))
}

func toEndpoint(doc *openapi3.T, method, path string, item *openapi3.PathItem, op *openapi3.Operation) model.Endpoint {
	params := extractParameters(item.Parameters, op.Parameters)
	params = append(params, extractBodyParameters(op.RequestBody)...)

	requiresAuth, scheme := resolveSecurity(doc, op)

	return model.Endpoint{
		Method:         method,
		Path:           path,
		Parameters:     params,
		RequiresAuth:   requiresAuth,
		SecurityScheme: scheme,
		Destructive:    destructiveMethods[method],
	}
}

// extractParameters converts path-level and operation-level parameters
// (query, path, header) into model.Parameter, with operation-level entries
// taking precedence as OpenAPI dictates.
func extractParameters(pathLevel, opLevel openapi3.Parameters) []model.Parameter {
	seen := make(map[string]bool)
	var out []model.Parameter

	add := func(params openapi3.Parameters) {
		for _, ref := range params {
			if ref == nil || ref.Value == nil {
				continue
			}
			p := ref.Value
			key := p.In + ":" + p.Name
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, model.Parameter{
				Name:     p.Name,
				In:       p.In,
				Type:     schemaType(p.Schema),
				Required: p.Required,
			})
		}
	}

	// Operation-level first so it wins the seen-dedup against path-level.
	add(opLevel)
	add(pathLevel)

	return out
}

// extractBodyParameters flattens the top-level properties of a JSON request
// body schema into model.Parameter entries with In: "body".
func extractBodyParameters(body *openapi3.RequestBodyRef) []model.Parameter {
	if body == nil || body.Value == nil {
		return nil
	}

	media := body.Value.Content.Get("application/json")
	if media == nil || media.Schema == nil || media.Schema.Value == nil {
		return nil
	}
	schema := media.Schema.Value

	required := make(map[string]bool, len(schema.Required))
	for _, name := range schema.Required {
		required[name] = true
	}

	names := slices.Sorted(maps.Keys(schema.Properties))

	out := make([]model.Parameter, 0, len(names))
	for _, name := range names {
		out = append(out, model.Parameter{
			Name:     name,
			In:       "body",
			Type:     schemaType(schema.Properties[name]),
			Required: required[name],
		})
	}
	return out
}

func schemaType(ref *openapi3.SchemaRef) string {
	if ref == nil || ref.Value == nil || ref.Value.Type == nil {
		return ""
	}
	types := ref.Value.Type.Slice()
	if len(types) == 0 {
		return ""
	}
	return types[0]
}

// resolveSecurity determines whether an operation requires auth and, if so,
// which security scheme it uses. An operation-level `security` overrides the
// document's top-level `security` per the OpenAPI spec, including an empty
// list explicitly meaning "no auth required".
//
// The result must be identical across runs: findings.json is a git-diffable
// artifact, so a scheme name that changed between two scans of the same spec
// would show up as spurious churn in review.
func resolveSecurity(doc *openapi3.T, op *openapi3.Operation) (requiresAuth bool, scheme string) {
	reqs := doc.Security
	if op.Security != nil {
		reqs = *op.Security
	}

	if len(reqs) == 0 {
		return false, ""
	}

	// The entries combine with OR. An empty requirement object anywhere in
	// the list means the operation may be called with no credentials at
	// all, so the scanner can reach it unauthenticated and treats it as
	// public regardless of which other alternatives exist.
	for _, req := range reqs {
		if len(req) == 0 {
			return false, ""
		}
	}

	// Otherwise the first alternative decides; slice order is already
	// stable. A single requirement listing several schemes combines them
	// with AND, and model.Endpoint records only one name — so pick the
	// lexicographically smallest rather than whatever Go's randomized map
	// iteration happens to yield this run.
	return true, slices.Min(slices.Collect(maps.Keys(reqs[0])))
}
