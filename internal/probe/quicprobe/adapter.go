package quicprobe

import (
	"context"

	"iscan/internal/model"
	"iscan/internal/probe"
)

// QUICOpts holds configuration for the QUIC probe adapter.
type QUICOpts struct {
	Port int
	SNI  string
	ALPN []string
}

// Adapter wraps the QUIC probe into the unified Probe interface.
type Adapter struct {
	Opts QUICOpts
}

// Run performs a single QUIC handshake and returns a ProbeResult.
func (a *Adapter) Run(ctx context.Context, target model.Target) model.ProbeResult {
	sni := a.Opts.SNI
	if sni == "" {
		sni = target.Domain
	}
	obs := Probe(ctx, target.Domain, a.Opts.Port, sni, a.Opts.ALPN, 0)
	return probe.NewResult(model.LayerQUIC, obs)
}

func init() {
	probe.Registry[model.LayerQUIC] = &Adapter{
		Opts: QUICOpts{
			Port: 443,
			ALPN: []string{"h3"},
		},
	}
}
