package middleware

import "iscan/internal/probe"

type Middleware func(probe.Probe) probe.Probe

func Chain(p probe.Probe, mws ...Middleware) probe.Probe {
	for i := len(mws) - 1; i >= 0; i-- {
		p = mws[i](p)
	}
	return p
}
