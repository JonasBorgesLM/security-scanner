package model

import (
	"context"

	"github.com/JonasBorgesLM/security-scanner/internal/ports"
)

// CheckMetadata describes a check for registry lookup and engine
// scheduling — never serialized, so it carries no JSON tags.
type CheckMetadata struct {
	Name          string
	OWASPCategory string
	Severity      string
	Kind          string // "passive" | "active"
	RequiresAuth  bool
	AppliesTo     func(Endpoint) bool
}

// Check is implemented by every vulnerability check, self-registered into
// the checks registry via init().
type Check interface {
	Metadata() CheckMetadata
	Run(ctx context.Context, ep Endpoint, c ports.HTTPClient) ([]Finding, error)
}
