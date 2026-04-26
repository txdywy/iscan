package icmpping

import (
	"context"
	"time"

	"iscan/internal/model"
	"iscan/internal/probe"
)

// PingOpts holds configuration for the ping probe adapter.
type PingOpts struct {
	Timeout time.Duration
}

// Adapter wraps the ping probe into the unified Probe interface.
type Adapter struct {
	Opts PingOpts
}

// Run performs a single ICMP echo request and returns a ProbeResult.
func (a *Adapter) Run(ctx context.Context, target model.Target) model.ProbeResult {
	obs := Probe(ctx, target.Domain, a.Opts.Timeout)
	return probe.NewResult(model.LayerPing, obs)
}

func init() {
	probe.Registry[model.LayerPing] = &Adapter{
		Opts: PingOpts{Timeout: 5 * time.Second},
	}
}
