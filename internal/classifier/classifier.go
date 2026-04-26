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

	dnsObs := collectObservations[model.DNSObservation](result.Results, model.LayerDNS)
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
			Confidence: model.ConfidenceMedium,
			Evidence:   evidence,
			ObservedAt: now,
		})
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
