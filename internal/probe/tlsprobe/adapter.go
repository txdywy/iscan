package tlsprobe

import (
	"context"

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
func (a *Adapter) Run(ctx context.Context, target model.Target) model.ProbeResult {
	sni := a.Opts.SNI
	if sni == "" {
		sni = target.Domain
	}
	obs := Probe(ctx, target.Domain, a.Opts.Port, sni, a.Opts.NextProtos, 0, a.Opts.InsecureSkipVerify)
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
