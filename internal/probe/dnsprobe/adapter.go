package dnsprobe

import (
	"context"

	mdns "github.com/miekg/dns"

	"iscan/internal/model"
	"iscan/internal/probe"
)

// DNSOpts holds configuration for the DNS probe adapter.
type DNSOpts struct {
	Resolver model.Resolver
	QType    uint16
}

// Adapter wraps the dns probe into the unified Probe interface.
type Adapter struct {
	Opts DNSOpts
}

// Run performs a single DNS lookup and returns a ProbeResult.
func (a *Adapter) Run(ctx context.Context, target model.Target) model.ProbeResult {
	obs := Probe(ctx, a.Opts.Resolver, target.Domain, a.Opts.QType, 0)
	return probe.NewResult(model.LayerDNS, obs)
}

func init() {
	probe.Registry[model.LayerDNS] = &Adapter{
		Opts: DNSOpts{
			Resolver: model.Resolver{Name: "system", System: true},
			QType:    mdns.TypeA,
		},
	}
}
