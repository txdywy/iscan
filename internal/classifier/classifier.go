package classifier

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"iscan/internal/model"
)

func Classify(result model.TargetResult) []model.Finding {
	now := time.Now()
	var findings []model.Finding

	dnsObs := collectAllDNSObservations(result.Results)
	tcpObs := collectObservations[model.TCPObservation](result.Results, model.LayerTCP)
	tlsObs := collectObservations[model.TLSObservation](result.Results, model.LayerTLS)
	httpObs := collectObservations[model.HTTPObservation](result.Results, model.LayerHTTP)
	quicObs := collectObservations[model.QUICObservation](result.Results, model.LayerQUIC)
	traceObs := collectObservation[model.TraceObservation](result.Results, model.LayerTrace)

	if dnsInconsistent(dnsObs) {
		findings = append(findings, model.Finding{
			Type:       model.FindingDNSInconsistent,
			Layer:      model.LayerDNS,
			Confidence: model.ConfidenceLow,
			Evidence:   []string{"resolver answer sets differ"},
			ObservedAt: now,
		})
	}
	if evidence := suspiciousDNS(dnsObs); len(evidence) > 0 {
		findings = append(findings, model.Finding{
			Type:       model.FindingDNSSuspiciousAnswer,
			Layer:      model.LayerDNS,
			Confidence: CalibrateConfidence(ConfidenceSignals{Base: model.ConfidenceMedium, EvidenceCount: len(evidence)}),
			Evidence:   evidence,
			ObservedAt: now,
		})
	}
	if f := tlsQuicDivergence(result, tlsObs, quicObs, now); len(f) > 0 {
		findings = append(findings, f...)
	}
	if f := dnsRcodeFindings(dnsObs, now); len(f) > 0 {
		findings = append(findings, f...)
	}
	if f := detectTransparentDNSProxy(dnsObs, now); len(f) > 0 {
		findings = append(findings, f...)
	}
	if evidence := aggregateFailures(tcpObs,
		func(o model.TCPObservation) string { return fmt.Sprintf("%s:%d", o.Host, o.Port) },
		func(o model.TCPObservation) bool { return o.Success },
		func(o model.TCPObservation) string {
			return fmt.Sprintf("%s:%d failed: %s", o.Host, o.Port, o.ErrorKind)
		},
	); len(evidence) > 0 {
		findings = append(findings, model.Finding{
			Type:       model.FindingTCPConnectFailure,
			Layer:      model.LayerTCP,
			Confidence: model.ConfidenceLow,
			Evidence:   evidence,
			ObservedAt: now,
		})
	}
	if evidence := aggregateFailures(tlsObs,
		func(o model.TLSObservation) string { return o.Address + "|" + o.SNI },
		func(o model.TLSObservation) bool { return o.Success },
		func(o model.TLSObservation) string { return fmt.Sprintf("%s failed: %s", o.SNI, o.Error) },
	); len(evidence) > 0 {
		findings = append(findings, model.Finding{
			Type:       model.FindingTLSHandshakeFailure,
			Layer:      model.LayerTLS,
			Confidence: model.ConfidenceLow,
			Evidence:   evidence,
			ObservedAt: now,
		})
	}
	if evidence := sniCorrelatedFailures(tlsObs); len(evidence) > 0 {
		findings = append(findings, model.Finding{
			Type:       model.FindingSNICorrelated,
			Layer:      model.LayerTLS,
			Confidence: model.ConfidenceMedium,
			Evidence:   evidence,
			ObservedAt: now,
		})
	}
	if evidence := aggregateFailures(httpObs,
		func(o model.HTTPObservation) string { return o.URL },
		func(o model.HTTPObservation) bool { return o.Success },
		func(o model.HTTPObservation) string {
			if o.Error != "" {
				return fmt.Sprintf("%s failed: %s", o.URL, o.Error)
			}
			return fmt.Sprintf("%s returned status %d", o.URL, o.StatusCode)
		},
	); len(evidence) > 0 {
		findings = append(findings, model.Finding{
			Type:       model.FindingHTTPFailure,
			Layer:      model.LayerHTTP,
			Confidence: model.ConfidenceLow,
			Evidence:   evidence,
			ObservedAt: now,
		})
	}
	if evidence := aggregateFailures(quicObs,
		func(o model.QUICObservation) string { return o.Address + "|" + o.SNI },
		func(o model.QUICObservation) bool { return o.Success },
		func(o model.QUICObservation) string { return fmt.Sprintf("%s failed: %s", o.SNI, o.Error) },
	); len(evidence) > 0 {
		findings = append(findings, model.Finding{
			Type:       model.FindingQUICFailure,
			Layer:      model.LayerQUIC,
			Confidence: model.ConfidenceLow,
			Evidence:   evidence,
			ObservedAt: now,
		})
	}
	if traceObs != nil && !traceObs.Success && !model.IsLocalPermissionError(traceObs.Error) {
		findings = append(findings, model.Finding{
			Type:       model.FindingPathQuality,
			Layer:      model.LayerTrace,
			Confidence: model.ConfidenceLow,
			Evidence:   []string{traceObs.Error},
			ObservedAt: now,
		})
	}
	return findings
}

func aggregateFailures[T any](observations []T, keyFn func(T) string, successFn func(T) bool, msgFn func(T) string) []string {
	type state struct {
		success bool
		last    T
	}
	byKey := map[string]state{}
	for _, observation := range observations {
		key := keyFn(observation)
		current := byKey[key]
		if successFn(observation) {
			current.success = true
		}
		current.last = observation
		byKey[key] = current
	}
	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var evidence []string
	for _, key := range keys {
		current := byKey[key]
		if !current.success {
			evidence = append(evidence, msgFn(current.last))
		}
	}
	return evidence
}

func dnsInconsistent(observations []model.DNSObservation) bool {
	setsByType := map[string]map[string]struct{}{}
	for _, observation := range observations {
		if !dnsHasUsableAnswers(observation) {
			continue
		}
		answers := append([]string(nil), observation.Answers...)
		sort.Strings(answers)
		qtype := observation.Type
		if qtype == "" {
			qtype = "unknown"
		}
		if setsByType[qtype] == nil {
			setsByType[qtype] = map[string]struct{}{}
		}
		setsByType[qtype][strings.Join(answers, ",")] = struct{}{}
	}
	for _, sets := range setsByType {
		if len(sets) <= 1 {
			continue
		}
		// Multiple answer sets for the same query type.
		// Only flag as inconsistent if the sets have no overlap
		// (i.e. no resolver returned any IP that another resolver
		// also returned). This avoids false positives for GeoDNS.
		if !setsHaveIntersection(sets) {
			return true
		}
	}
	return false
}

func setsHaveIntersection(sets map[string]struct{}) bool {
	if len(sets) <= 1 {
		return true
	}
	// Build a global set of all IPs seen.
	global := map[string]int{}
	for joined := range sets {
		for _, ip := range strings.Split(joined, ",") {
			global[ip]++
		}
	}
	// If any IP appears in more than one set, there is overlap.
	for _, count := range global {
		if count > 1 {
			return true
		}
	}
	return false
}

func dnsHasUsableAnswers(observation model.DNSObservation) bool {
	return len(observation.Answers) > 0 && observation.Error == ""
}

func suspiciousDNS(observations []model.DNSObservation) []string {
	var evidence []string
	for _, observation := range observations {
		for _, answer := range observation.Answers {
			ip := net.ParseIP(answer)
			if ip == nil {
				continue
			}
			if isSuspiciousIP(ip) {
				evidence = append(evidence, fmt.Sprintf("%s returned suspicious address %s", observation.Resolver, answer))
			}
		}
	}
	return evidence
}

func sniCorrelatedFailures(observations []model.TLSObservation) []string {
	type state struct {
		success []string
		failed  []string
	}
	byAddress := map[string]*state{}
	for _, observation := range observations {
		if observation.Address == "" || observation.SNI == "" {
			continue
		}
		current := byAddress[observation.Address]
		if current == nil {
			current = &state{}
			byAddress[observation.Address] = current
		}
		if observation.Success {
			current.success = append(current.success, observation.SNI)
		} else {
			current.failed = append(current.failed, observation.SNI)
		}
	}
	addresses := make([]string, 0, len(byAddress))
	for addr := range byAddress {
		addresses = append(addresses, addr)
	}
	sort.Strings(addresses)
	var evidence []string
	for _, address := range addresses {
		current := byAddress[address]
		if len(current.success) > 0 && len(current.failed) > 0 {
			evidence = append(evidence, fmt.Sprintf("%s succeeded for SNI %s but failed for SNI %s", address, strings.Join(current.success, ","), strings.Join(current.failed, ",")))
		}
	}
	return evidence
}

func isSuspiciousIP(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

// collectObservations extracts all observations of type T for the given layer.
func collectObservations[T any](results []model.ProbeResult, layer model.Layer) []T {
	var out []T
	for _, r := range results {
		if r.Layer == layer {
			if obs, ok := r.Data.(T); ok {
				out = append(out, obs)
			}
		}
	}
	return out
}

// collectObservation extracts the first observation of type T for the given layer, or nil.
func collectObservation[T any](results []model.ProbeResult, layer model.Layer) *T {
	for _, r := range results {
		if r.Layer == layer {
			if obs, ok := r.Data.(T); ok {
				return &obs
			}
		}
	}
	return nil
}

// collectAllDNSObservations extracts DNS observations from ProbeResult data, handling both
// single DNSObservation (backward compatible) and []DNSObservation (multi-resolver adapter).
func collectAllDNSObservations(results []model.ProbeResult) []model.DNSObservation {
	var out []model.DNSObservation
	for _, r := range results {
		if r.Layer != model.LayerDNS {
			continue
		}
		// New format: []DNSObservation from multi-resolver adapter
		if obsSlice, ok := r.Data.([]model.DNSObservation); ok {
			out = append(out, obsSlice...)
			continue
		}
		// Old format: single DNSObservation (backward compatible)
		if obs, ok := r.Data.(model.DNSObservation); ok {
			out = append(out, obs)
		}
	}
	return out
}

// dnsRcodeFindings generates findings for non-NOERROR DNS response codes.
func dnsRcodeFindings(observations []model.DNSObservation, now time.Time) []model.Finding {
	var findings []model.Finding
	for _, obs := range observations {
		if obs.RCode == "" || obs.RCode == "NOERROR" {
			continue
		}
		findings = append(findings, model.Finding{
			Type:       rcodeFindingType(obs.RCode),
			Layer:      model.LayerDNS,
			Confidence: rcodeConfidence(obs.RCode),
			Evidence:   []string{fmt.Sprintf("%s returned %s for %s", obs.Resolver, obs.RCode, obs.Query)},
			ObservedAt: now,
		})
	}
	return findings
}

func rcodeFindingType(rcode string) model.FindingType {
	switch rcode {
	case "NXDOMAIN":
		return model.FindingDNSNXDOMAIN
	case "SERVFAIL":
		return model.FindingDNSSERVFAIL
	case "REFUSED":
		return model.FindingDNSREFUSED
	default:
		return model.FindingDNSOtherRCODE
	}
}

func rcodeConfidence(rcode string) model.Confidence {
	switch rcode {
	case "NXDOMAIN":
		return model.ConfidenceHigh
	case "SERVFAIL":
		return model.ConfidenceMedium
	case "REFUSED":
		return model.ConfidenceHigh
	default:
		return model.ConfidenceLow
	}
}

func tlsQuicDivergence(result model.TargetResult, tlsObs []model.TLSObservation, quicObs []model.QUICObservation, now time.Time) []model.Finding {
	if result.Target.QUICPort == 0 || len(quicObs) == 0 {
		return nil
	}
	if !hasUsableTLS(tlsObs) || !hasFailedQUIC(quicObs) {
		return nil
	}
	if !hasComparableTransportFamily(result.Target, tlsObs, quicObs) {
		return nil
	}

	evidence := []string{
		fmt.Sprintf("%s has successful TLS observations for SNI %s", targetLabel(result.Target), strings.Join(successfulSNIs(tlsObs), ", ")),
		fmt.Sprintf("%s has failed QUIC observations for SNI %s", targetLabel(result.Target), strings.Join(failedQUICSNIs(quicObs), ", ")),
	}
	return []model.Finding{{
		Type:       model.FindingTLSQUICDivergence,
		Layer:      model.LayerQUIC,
		Confidence: CalibrateConfidence(ConfidenceSignals{Base: model.ConfidenceLow, EvidenceCount: len(evidence), CrossLayerAgreement: true}),
		Evidence:   evidence,
		ObservedAt: now,
	}}
}

func hasUsableTLS(observations []model.TLSObservation) bool {
	for _, obs := range observations {
		if obs.Success {
			return true
		}
	}
	return false
}

func hasFailedQUIC(observations []model.QUICObservation) bool {
	for _, obs := range observations {
		if !obs.Success && !isIgnoredQUICFailure(obs.Error) {
			return true
		}
	}
	return false
}

func hasComparableTransportFamily(target model.Target, tlsObs []model.TLSObservation, quicObs []model.QUICObservation) bool {
	if len(target.CompareSNI) == 0 {
		return true
	}
	allowed := map[string]struct{}{}
	for _, sni := range target.CompareSNI {
		allowed[sni] = struct{}{}
	}
	for _, obs := range tlsObs {
		if obs.Success {
			if _, ok := allowed[obs.SNI]; ok {
				return true
			}
		}
	}
	for _, obs := range quicObs {
		if !obs.Success && !isIgnoredQUICFailure(obs.Error) {
			if _, ok := allowed[obs.SNI]; ok {
				return true
			}
		}
	}
	return false
}

func successfulSNIs(observations []model.TLSObservation) []string {
	seen := map[string]struct{}{}
	for _, obs := range observations {
		if obs.Success && obs.SNI != "" {
			seen[obs.SNI] = struct{}{}
		}
	}
	var snis []string
	for sni := range seen {
		snis = append(snis, sni)
	}
	sort.Strings(snis)
	return snis
}

func failedQUICSNIs(observations []model.QUICObservation) []string {
	seen := map[string]struct{}{}
	for _, obs := range observations {
		if !obs.Success && !isIgnoredQUICFailure(obs.Error) && obs.SNI != "" {
			seen[obs.SNI] = struct{}{}
		}
	}
	var snis []string
	for sni := range seen {
		snis = append(snis, sni)
	}
	sort.Strings(snis)
	return snis
}

func isIgnoredQUICFailure(err string) bool {
	lower := strings.ToLower(err)
	switch {
	case lower == "":
		return true
	case strings.Contains(lower, "unsupported"), strings.Contains(lower, "not supported"):
		return true
	case strings.Contains(lower, "permission denied"), strings.Contains(lower, "operation not permitted"):
		return true
	default:
		return false
	}
}

func targetLabel(target model.Target) string {
	if target.Name != "" {
		return target.Name
	}
	if target.Domain != "" {
		return target.Domain
	}
	return "unknown-target"
}

// detectTransparentDNSProxy checks whoami query responses against known resolver IPs.
// If a whoami.akamai.net query returns an IP different from known resolver IPs,
// a transparent DNS proxy finding is generated.
func detectTransparentDNSProxy(observations []model.DNSObservation, now time.Time) []model.Finding {
	var findings []model.Finding
	for _, obs := range observations {
		// Only check observations that successfully resolved whoami domains
		if !obs.Success || len(obs.Answers) == 0 {
			continue
		}
		// Check if this was a whoami query (query contains whoami.)
		if !strings.Contains(obs.Query, "whoami.") {
			continue
		}
		// Compare resolved IP against known resolver server addresses
		resolvedIP := obs.Answers[0]
		if isKnownResolverIP(resolvedIP) {
			continue // This is expected — whoami returns the resolver's own IP
		}
		// The resolved IP differs from expected — transparent proxy detected
		findings = append(findings, model.Finding{
			Type:       model.FindingDNSTransparentProxy,
			Layer:      model.LayerDNS,
			Confidence: model.ConfidenceHigh,
			Evidence:   []string{fmt.Sprintf("whoami query via %s resolved to %s (expected resolver's own IP)", obs.Resolver, resolvedIP)},
			ObservedAt: now,
		})
	}
	return findings
}

func isKnownResolverIP(ip string) bool {
	// Known public resolver IPs that whoami should return
	known := map[string]bool{
		"1.1.1.1": true, "1.0.0.1": true,                         // Cloudflare
		"8.8.8.8": true, "8.8.4.4": true,                         // Google
		"9.9.9.9": true, "149.112.112.112": true,                 // Quad9
		"2606:4700:4700::1111": true, "2606:4700:4700::1001": true, // Cloudflare IPv6
		"2001:4860:4860::8888": true, "2001:4860:4860::8844": true, // Google IPv6
		"2620:fe::fe": true, "2620:fe::9": true,                  // Quad9 IPv6
	}
	return known[ip]
}
