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
// Dual-stack: queries AAAA when target.AddressFamily allows IPv6.
func (a *Adapter) Run(ctx context.Context, target model.Target) model.ProbeResult {
	obs := Probe(ctx, a.Opts.Resolver, target.Domain, a.Opts.QType, 0)

	// Dual-stack: query AAAA when target allows IPv6.
	if target.AddressFamily == "" || target.AddressFamily == "ipv6" {
		obs6 := Probe(ctx, a.Opts.Resolver, target.Domain, mdns.TypeAAAA, 0)
		if obs6.Success {
			obs.Answers = append(obs.Answers, obs6.Answers...)
		}
		// If the A query failed but AAAA succeeded, use AAAA success status.
		if !obs.Success && obs6.Success {
			obs.Success = true
			obs.RCode = obs6.RCode
			obs.Error = ""
		}
		// If both failed, append AAAA error context.
		if !obs.Success && !obs6.Success && obs6.Error != "" {
			obs.Error = obs.Error + "; AAAA: " + obs6.Error
		}
	}

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
