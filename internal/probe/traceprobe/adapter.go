package traceprobe

import (
	"context"

	"iscan/internal/model"
	"iscan/internal/probe"
)

// TraceOpts holds configuration for the trace probe adapter.
type TraceOpts struct{}

// Adapter wraps the trace probe into the unified Probe interface.
type Adapter struct {
	Opts TraceOpts
}

// Run performs a single traceroute and returns a ProbeResult.
func (a *Adapter) Run(ctx context.Context, target model.Target) model.ProbeResult {
	obs := Probe(ctx, target.Domain, target.AddressFamily, 0)
	return probe.NewResult(model.LayerTrace, obs)
}

func init() {
	probe.Registry[model.LayerTrace] = &Adapter{}
}
