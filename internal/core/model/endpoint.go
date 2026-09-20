package model

// Parameter describes a single input to an Endpoint, as discovered from the
// OpenAPI spec — the injection point checks target with payloads.
type Parameter struct {
	Name     string `json:"name"`
	In       string `json:"in"` // "query" | "path" | "header" | "body"
	Type     string `json:"type"`
	Required bool   `json:"required"`
	// Sample is a real, valid value for this parameter drawn from the spec
	// itself — a parameter- or schema-level example, an enum member, or a
	// format-based synthetic value (a UUID for format: uuid) — in that
	// priority order. Empty when the spec gives no such value.
	//
	// It exists because a generic filler value is type-blind: measured
	// against a real API, a strictly-typed parameter (an enum, a uuid path
	// segment) rejects a generic filler exactly as it rejects an injection
	// payload, so an active check never gets past validation to test
	// anything and reports the parameter as unexercisable rather than
	// clean. A check should prefer Sample over its own generic filler when
	// present.
	Sample string `json:"sample,omitempty"`
}

// Endpoint is a single route imported from the OpenAPI spec.
type Endpoint struct {
	Method         string      `json:"method"`
	Path           string      `json:"path"`
	Parameters     []Parameter `json:"parameters,omitempty"`
	RequiresAuth   bool        `json:"requires_auth"`
	SecurityScheme string      `json:"security_scheme,omitempty"`
	// Destructive is true for DELETE/PUT/PATCH. Such endpoints are skipped
	// by the engine unless the config opts in explicitly.
	Destructive bool `json:"destructive"`
}
