package httpprobe

import (
	"context"
	"fmt"

	"iscan/internal/model"
	probeapi "iscan/internal/probe"
)

// HTTPOpts holds configuration for the HTTP probe adapter.
type HTTPOpts struct {
	Port        int
	Path        string
	DialAddress string
}

// Adapter wraps the HTTP probe into the unified Probe interface.
type Adapter struct {
	Opts HTTPOpts
}

// Run performs a single HTTP request and returns a ProbeResult.
func (a *Adapter) Run(ctx context.Context, target model.Target) model.ProbeResult {
	path := a.Opts.Path
	if path == "" {
		path = target.HTTPPath
	}
	if path == "" {
		path = "/"
	}
	url := fmt.Sprintf("%s://%s:%d%s", target.Scheme, target.Domain, a.Opts.Port, path)
	var obs model.HTTPObservation
	if a.Opts.DialAddress != "" {
		obs = ProbeWithAddress(ctx, url, a.Opts.DialAddress, 0)
	} else {
		obs = Probe(ctx, url, 0)
	}
	return probeapi.NewResult(model.LayerHTTP, obs)
}

func init() {
	probeapi.Registry[model.LayerHTTP] = &Adapter{
		Opts: HTTPOpts{Port: 443, Path: "/"},
	}
}
