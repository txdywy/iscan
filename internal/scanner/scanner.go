package scanner

import (
	"context"
	"net/url"
	"sort"
	"time"

	"golang.org/x/sync/errgroup"

	"iscan/internal/probe/dnsprobe"
	_ "iscan/internal/probe/httpprobe"
	_ "iscan/internal/probe/quicprobe"
	_ "iscan/internal/probe/tcp"
	_ "iscan/internal/probe/tlsprobe"
	_ "iscan/internal/probe/icmpping"
	_ "iscan/internal/probe/traceprobe"

	"iscan/internal/classifier"
	"iscan/internal/model"
	"iscan/internal/probe"
	"iscan/internal/probe/middleware"
	"iscan/internal/targets"
)

func Run(ctx context.Context, options model.ScanOptions) model.ScanReport {
	if options.Timeout <= 0 {
		options.Timeout = 5 * time.Second
	}
	if options.Retries <= 0 {
		options.Retries = 3
	}
	if options.Parallelism <= 0 {
		options.Parallelism = 4
	}

	// Configure DNS rate limiter, defaulting to 20 qps
	rateLimit := options.DNSRateLimit
	if rateLimit == 0 {
		rateLimit = 20
	}
	dnsprobe.SetRateLimit(rateLimit)

	start := time.Now()
	report := model.ScanReport{
		StartedAt: start,
		Options:   options,
	}
	resolvers := targets.BuiltinResolvers()
	source := targets.SelectSource(options.TargetSet)
	targetList, err := source.Load()
	if err != nil {
		report.Warnings = append(report.Warnings, "targets: "+err.Error())
		report.Duration = time.Since(start)
		return report
	}
	results := make([]model.TargetResult, len(targetList))

	probes := buildProbes(options)

	var group errgroup.Group
	group.SetLimit(options.Parallelism)
	for i, target := range targetList {
		i, target := i, target
		group.Go(func() error {
			targetCtx, targetCancel := context.WithCancel(ctx)
			defer targetCancel()
			result := scanTarget(targetCtx, target, resolvers, options, probes)
			result.Findings = classifier.Classify(result)
			results[i] = result
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		report.Warnings = append(report.Warnings, "scanner: "+err.Error())
	}
	for i, result := range results {
		if result.Target.Name == "" {
			continue
		}
		if result.Error != "" {
			report.Warnings = append(report.Warnings, targetList[i].Domain+": "+result.Error)
		}
		for _, pr := range result.Results {
			if pr.Layer == model.LayerTrace {
				if obs, ok := pr.Data.(model.TraceObservation); ok && !obs.Success {
					if model.IsLocalPermissionError(obs.Error) {
						report.Warnings = append(report.Warnings, targetList[i].Domain+": trace unavailable: "+obs.Error)
					}
				}
			}
			if pr.Layer == model.LayerPing {
				if obs, ok := pr.Data.(model.PingObservation); ok && !obs.Success {
					if model.IsLocalPermissionError(obs.Error) {
						report.Warnings = append(report.Warnings, targetList[i].Domain+": ping unavailable: "+obs.Error)
					}
				}
			}
		}
		report.Findings = append(report.Findings, result.Findings...)
		report.Targets = append(report.Targets, result)
	}
	report.Duration = time.Since(start)
	return report
}

func buildProbes(options model.ScanOptions) []probe.Probe {
	var probes []probe.Probe
	timeout := options.Timeout

	add := func(layer model.Layer) {
		p, ok := probe.Registry[layer]
		if !ok {
			return
		}
		p = middleware.Chain(p,
			middleware.Timeout(timeout),
			middleware.Retry(options.Retries, 500*time.Millisecond),
			middleware.Logging(nil),
		)
		probes = append(probes, p)
	}

	add(model.LayerDNS)
	add(model.LayerTCP)
	add(model.LayerTLS)
	if options.ICMPPing {
		add(model.LayerPing)
	}
	add(model.LayerHTTP)
	if options.QUIC {
		add(model.LayerQUIC)
	}
	if options.Trace {
		add(model.LayerTrace)
	}
	return probes
}

func scanTarget(ctx context.Context, target model.Target, resolvers []model.Resolver, options model.ScanOptions, probes []probe.Probe) model.TargetResult {
	result := model.TargetResult{
		Target:  target,
		Results: make([]model.ProbeResult, 0, len(probes)),
	}

	for _, p := range probes {
		pr := p.Run(ctx, target)
		result.Results = append(result.Results, pr)
	}

	return result
}

// probeContext derives a child context with a per-probe timeout.
// If the parent context has a deadline, the per-probe timeout is
// capped to the remaining time before that deadline so that a single
// probe cannot exhaust the entire window.
func probeContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining < timeout {
			timeout = remaining
		}
		if timeout <= 0 {
			timeout = time.Nanosecond
		}
	}
	return context.WithTimeout(ctx, timeout)
}

func UniqueAnswers(observations []model.DNSObservation) []string {
	seen := map[string]struct{}{}
	var answers []string
	for _, observation := range observations {
		for _, answer := range observation.Answers {
			if _, ok := seen[answer]; ok {
				continue
			}
			seen[answer] = struct{}{}
			answers = append(answers, answer)
		}
	}
	sort.Strings(answers)
	return answers
}

func HasSuccessfulTLSForSNI(observations []model.TLSObservation, sni string) bool {
	for _, observation := range observations {
		if observation.Success && observation.SNI == sni {
			return true
		}
	}
	return false
}

func TargetURL(target model.Target) string {
	path := target.HTTPPath
	if path == "" {
		path = "/"
	}
	return (&url.URL{Scheme: target.Scheme, Host: target.Domain, Path: path}).String()
}

// retryWithBackoff calls probe up to maxAttempts times with exponential backoff.
// Returns immediately on success or context cancellation.
func retryWithBackoff[T any](ctx context.Context, maxAttempts int, baseDelay time.Duration, probe func() (T, bool)) T {
	var zero T
	var last T
	var hasLast bool
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if ctx.Err() != nil {
			if hasLast {
				return last
			}
			return zero
		}
		result, ok := probe()
		last = result
		hasLast = true
		if ok {
			return result
		}
		if attempt < maxAttempts-1 {
			delay := baseDelay * (1 << attempt)
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				if hasLast {
					return last
				}
				return zero
			case <-timer.C:
			}
		}
	}
	if hasLast {
		return last
	}
	return zero
}
