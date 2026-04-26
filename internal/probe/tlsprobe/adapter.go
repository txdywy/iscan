package tlsprobe

import (
	"context"
	"net"

	"iscan/internal/model"
	"iscan/internal/probe"
)

// TLSOpts holds configuration for the TLS probe adapter.
type TLSOpts struct {
	Port               int
	SNI                string
	NextProtos         []string
	InsecureSkipVerify bool
}

// Adapter wraps the TLS probe into the unified Probe interface.
type Adapter struct {
	Opts TLSOpts
}

// Run performs a single TLS handshake and returns a ProbeResult.
// When AddressFamily is set, pre-resolves the target to restrict address family
// while preserving the original domain as SNI.
func (a *Adapter) Run(ctx context.Context, target model.Target) model.ProbeResult {
	sni := a.Opts.SNI
	if sni == "" {
		sni = target.Domain
	}
	host := target.Domain
	if target.AddressFamily == "ipv6" || target.AddressFamily == "ipv4" {
		ips, err := net.LookupIP(target.Domain)
		if err == nil {
			for _, ip := range ips {
				if (target.AddressFamily == "ipv6" && ip.To4() == nil) ||
					(target.AddressFamily == "ipv4" && ip.To4() != nil) {
					host = ip.String()
					break
				}
			}
		}
		// If resolution fails, fall back to hostname (Probe will handle the error).
	}
	obs := Probe(ctx, host, a.Opts.Port, sni, a.Opts.NextProtos, 0, a.Opts.InsecureSkipVerify)
	return probe.NewResult(model.LayerTLS, obs)
}

func init() {
	probe.Registry[model.LayerTLS] = &Adapter{
		Opts: TLSOpts{
			Port:               443,
			NextProtos:         []string{"h2", "http/1.1"},
			InsecureSkipVerify: true,
		},
	}
}
