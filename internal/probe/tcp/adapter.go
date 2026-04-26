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
// AddressFamily controls which network to use (tcp4, tcp6, or dual-stack tcp).
func (a *Adapter) Run(ctx context.Context, target model.Target) model.ProbeResult {
	network := "tcp"
	if target.AddressFamily == "ipv6" {
		network = "tcp6"
	} else if target.AddressFamily == "ipv4" {
		network = "tcp4"
	}
	obs := ProbeNetwork(ctx, target.Domain, a.Opts.Port, network, 0)
	return probe.NewResult(model.LayerTCP, obs)
}

func init() {
	probe.Registry[model.LayerTCP] = &Adapter{
		Opts: TCPOpts{Port: 443},
	}
}
