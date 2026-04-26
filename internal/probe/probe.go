package probe

import (
	"context"

	"iscan/internal/model"
)

// Probe is the unified interface for all protocol probes.
type Probe interface {
	Run(ctx context.Context, target model.Target) model.ProbeResult
}

// ProbeFunc adapts a function to the Probe interface.
type ProbeFunc func(context.Context, model.Target) model.ProbeResult

func (f ProbeFunc) Run(ctx context.Context, target model.Target) model.ProbeResult {
	return f(ctx, target)
}

// Registry is the global probe registry populated via init().
var Registry = map[model.Layer]Probe{}

// NewResult creates a ProbeResult with the given layer and data.
func NewResult(layer model.Layer, data any) model.ProbeResult {
	return model.ProbeResult{Layer: layer, Data: data}
}
