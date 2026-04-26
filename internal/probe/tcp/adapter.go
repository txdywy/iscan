package tcp

import (
	"context"

	"iscan/internal/model"
	"iscan/internal/probe"
)

// TCPOpts holds configuration for the TCP probe adapter.
type TCPOpts struct {
	Port int
}

// Adapter wraps the TCP probe into the unified Probe interface.
type Adapter struct {
	Opts TCPOpts
}

// Run performs a single TCP dial and returns a ProbeResult.
func (a *Adapter) Run(ctx context.Context, target model.Target) model.ProbeResult {
	obs := Probe(ctx, target.Domain, a.Opts.Port, 0)
	return probe.NewResult(model.LayerTCP, obs)
}

func init() {
	probe.Registry[model.LayerTCP] = &Adapter{
		Opts: TCPOpts{Port: 443},
	}
}
