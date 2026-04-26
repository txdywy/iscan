package dnsprobe

import (
	"context"

	mdns "github.com/miekg/dns"

	"iscan/internal/model"
	"iscan/internal/probe"
	"iscan/internal/targets"
)

// Adapter wraps the dns probe into the unified Probe interface.
type Adapter struct{}

// Run performs DNS lookups against all configured resolvers with per-resolver
// rate limiting, and returns aggregated observations as ProbeResult.Data.
// Dual-stack: queries AAAA when target.AddressFamily allows IPv6.
func (a *Adapter) Run(ctx context.Context, target model.Target) model.ProbeResult {
	resolvers := targets.BuiltinResolvers()
	var observations []model.DNSObservation

	for _, resolver := range resolvers {
		// Per-resolver rate limiting before each Probe() call.
		if err := waitLimiter(ctx, resolver.Name); err != nil {
			// Context cancelled — stop probing.
			break
		}

		qtype := mdns.TypeA
		obs := Probe(ctx, resolver, target.Domain, qtype, 0)
		observations = append(observations, obs)

		// Dual-stack: query AAAA when target allows IPv6.
		if target.AddressFamily == "" || target.AddressFamily == "ipv6" {
			// Rate limit for AAAA query too (same resolver).
			if err := waitLimiter(ctx, resolver.Name); err != nil {
				break
			}
			obs6 := Probe(ctx, resolver, target.Domain, mdns.TypeAAAA, 0)
			observations = append(observations, obs6)
		}
	}

	// Probe whoami.akamai.net for transparent proxy detection (per D-10)
	for _, resolver := range resolvers {
		if resolver.System {
			continue // D-11: whoami only for resolvers with known server addresses
		}
		if err := waitLimiter(ctx, resolver.Name); err != nil {
			break
		}
		whoamiObs := Probe(ctx, resolver, targets.WhoamiDomain, mdns.TypeA, 0)
		observations = append(observations, whoamiObs)
	}

	return probe.NewResult(model.LayerDNS, observations)
}

func init() {
	probe.Registry[model.LayerDNS] = &Adapter{}
}
