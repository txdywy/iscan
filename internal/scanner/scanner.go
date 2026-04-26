package scanner

import (
	"context"
	"net"
	"net/url"
	"sort"
	"time"

	mdns "github.com/miekg/dns"
	"golang.org/x/sync/errgroup"

	"iscan/internal/classifier"
	"iscan/internal/model"
	"iscan/internal/probe/dnsprobe"
	"iscan/internal/probe/httpprobe"
	"iscan/internal/probe/quicprobe"
	"iscan/internal/probe/tcp"
	"iscan/internal/probe/tlsprobe"
	"iscan/internal/probe/traceprobe"
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

	start := time.Now()
	report := model.ScanReport{
		StartedAt: start,
		Options:   options,
	}
	resolvers := targets.BuiltinResolvers()
	targetList := targets.BuiltinTargets()
	for _, target := range targetList {
		if err := target.Validate(); err != nil {
			report.Warnings = append(report.Warnings, err.Error())
		}
	}
	results := make([]model.TargetResult, len(targetList))

	group, gCtx := errgroup.WithContext(ctx)
	group.SetLimit(options.Parallelism)
	for i, target := range targetList {
		i, target := i, target
		group.Go(func() error {
			select {
			case <-gCtx.Done():
				return gCtx.Err()
			default:
			}
			result := scanTarget(gCtx, target, resolvers, options)
			result.Findings = classifier.Classify(result)
			results[i] = result
			return nil
		})
	}
	if err := group.Wait(); err != nil && err != context.Canceled {
		report.Warnings = append(report.Warnings, err.Error())
	}
	for i, result := range results {
		if result.Target.Name == "" {
			continue // target was cancelled before scan started
		}
		if result.Trace != nil && result.Trace.Error != "" && model.IsLocalPermissionError(result.Trace.Error) {
			report.Warnings = append(report.Warnings, targetList[i].Domain+": trace unavailable: "+result.Trace.Error)
		}
		report.Findings = append(report.Findings, result.Findings...)
		report.Targets = append(report.Targets, result)
	}
	report.Duration = time.Since(start)
	return report
}

func scanTarget(ctx context.Context, target model.Target, resolvers []model.Resolver, options model.ScanOptions) model.TargetResult {
	result := model.TargetResult{Target: target}
	for _, resolver := range resolvers {
		if ctx.Err() != nil {
			return result
		}
		result.DNS = append(result.DNS, probeDNS(ctx, resolver, target.Domain, mdns.TypeA, options.Timeout))
		result.DNS = append(result.DNS, probeDNS(ctx, resolver, target.Domain, mdns.TypeAAAA, options.Timeout))
	}

	addresses := UniqueAnswers(result.DNS)
	if len(addresses) == 0 {
		addresses = []string{target.Domain}
	}
	for _, port := range target.Ports {
		for _, address := range addresses {
			obs := retryWithBackoff(ctx, options.Retries, 50*time.Millisecond,
				func() (model.TCPObservation, bool) {
					o := tcp.Probe(ctx, address, port, options.Timeout)
					return o, o.Success
				})
			result.TCP = append(result.TCP, obs)
		}
	}

	for _, observation := range result.TCP {
		if !observation.Success {
			continue
		}
		probeTLSWithRetries(ctx, &result, observation.Host, observation.Port, target.Domain, options)
		for _, compareSNI := range target.CompareSNI {
			probeTLSWithRetries(ctx, &result, observation.Host, observation.Port, compareSNI, options)
		}
	}

	if target.Scheme == "http" || HasSuccessfulTLSForSNI(result.TLS, target.Domain) {
		dialAddress := firstHTTPDialAddress(result, target)
		obs := retryWithBackoff(ctx, options.Retries, 50*time.Millisecond,
			func() (model.HTTPObservation, bool) {
				o := httpprobe.ProbeWithAddress(ctx, TargetURL(target), dialAddress, options.Timeout)
				return o, o.Success
			})
		result.HTTP = append(result.HTTP, obs)
	}
	if options.QUIC && target.QUICPort > 0 {
		quicPort := target.QUICPort
		for _, address := range addresses {
			if ctx.Err() != nil {
				break
			}
			obs := retryWithBackoff(ctx, options.Retries, 50*time.Millisecond,
				func() (model.QUICObservation, bool) {
					o := quicprobe.Probe(ctx, address, quicPort, target.Domain, []string{"h3"}, options.Timeout)
					return o, o.Success
				})
			result.QUIC = append(result.QUIC, obs)
			for _, compareSNI := range target.CompareSNI {
				if ctx.Err() != nil {
					break
				}
				obs := retryWithBackoff(ctx, options.Retries, 50*time.Millisecond,
					func() (model.QUICObservation, bool) {
						o := quicprobe.Probe(ctx, address, quicPort, compareSNI, []string{"h3"}, options.Timeout)
						return o, o.Success
					})
				result.QUIC = append(result.QUIC, obs)
			}
		}
	}
	if options.Trace {
		trace := traceprobe.Probe(ctx, target.Domain, options.Timeout)
		result.Trace = &trace
	}
	return result
}

func probeTLSWithRetries(ctx context.Context, result *model.TargetResult, host string, port int, sni string, options model.ScanOptions) {
	obs := retryWithBackoff(ctx, options.Retries, 50*time.Millisecond,
		func() (model.TLSObservation, bool) {
			o := tlsprobe.Probe(ctx, host, port, sni, []string{"h2", "http/1.1"}, options.Timeout, true)
			return o, o.Success
		})
	result.TLS = append(result.TLS, obs)
}

func probeDNS(ctx context.Context, resolver model.Resolver, domain string, qtype uint16, timeout time.Duration) model.DNSObservation {
	if !resolver.System {
		return dnsprobe.Probe(ctx, resolver, domain, qtype, timeout)
	}
	start := time.Now()
	observation := model.DNSObservation{
		Resolver: resolver.Name,
		Query:    domain,
		Type:     mdns.TypeToString[qtype],
	}
	network := "ip4"
	if qtype == mdns.TypeAAAA {
		network = "ip6"
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, network, domain)
	observation.Latency = time.Since(start)
	if err != nil {
		observation.Error = err.Error()
		return observation
	}
	for _, ip := range ips {
		if qtype == mdns.TypeA && ip.To4() != nil {
			observation.Answers = append(observation.Answers, ip.String())
		}
		if qtype == mdns.TypeAAAA && ip.To4() == nil {
			observation.Answers = append(observation.Answers, ip.String())
		}
	}
	observation.Success = true
	observation.RCode = "NOERROR"
	return observation
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

func firstHTTPDialAddress(result model.TargetResult, target model.Target) string {
	if target.Scheme == "https" {
		for _, observation := range result.TLS {
			if observation.Success && observation.SNI == target.Domain {
				return observation.Address
			}
		}
	}
	for _, observation := range result.TCP {
		if observation.Success {
			return observation.Address
		}
	}
	return ""
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
