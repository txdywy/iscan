package dnsprobe

import (
	"context"
	"sync"

	"golang.org/x/time/rate"
)

var (
	resolverLimiters sync.Map       // map[string]*rate.Limiter, keyed by resolver name
	defaultQPS       rate.Limit = 20
	defaultBurst     int        = 5
)

// getLimiter returns the rate limiter for the given resolver name.
// Creates a new limiter with defaultQPS and defaultBurst if one doesn't exist.
func getLimiter(name string) *rate.Limiter {
	actual, _ := resolverLimiters.LoadOrStore(name, rate.NewLimiter(defaultQPS, defaultBurst))
	return actual.(*rate.Limiter)
}

// SetRateLimit overrides the default QPS for new rate limiters.
// If qps <= 0, the rate limit is set to unlimited (rate.Inf).
func SetRateLimit(qps int) {
	if qps <= 0 {
		defaultQPS = rate.Inf // unlimited
		defaultBurst = 1
	} else {
		defaultQPS = rate.Limit(qps)
		// burst remains 5
	}
}

// waitLimiter blocks until a token is available for the given resolver name,
// or until the context is cancelled.
func waitLimiter(ctx context.Context, name string) error {
	if defaultQPS == rate.Inf {
		return nil
	}
	limiter := getLimiter(name)
	return limiter.Wait(ctx)
}
