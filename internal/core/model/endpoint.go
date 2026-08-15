package model

// Parameter describes a single input to an Endpoint, as discovered from the
// OpenAPI spec — the injection point checks target with payloads.
type Parameter struct {
	Name     string `json:"name"`
	In       string `json:"in"` // "query" | "path" | "header" | "body"
	Type     string `json:"type"`
	Required bool   `json:"required"`
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
