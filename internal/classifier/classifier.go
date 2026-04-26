package classifier

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"iscan/internal/model"
)

func Classify(result model.TargetResult) []model.Finding {
	var findings []model.Finding
	if dnsInconsistent(result.DNS) {
		findings = append(findings, model.Finding{
			Type:       model.FindingDNSInconsistent,
			Layer:      model.LayerDNS,
			Confidence: model.ConfidenceLow,
			Evidence:   []string{"resolver answer sets differ"},
		})
	}
	if evidence := suspiciousDNS(result.DNS); len(evidence) > 0 {
		findings = append(findings, model.Finding{
			Type:       model.FindingDNSSuspiciousAnswer,
			Layer:      model.LayerDNS,
			Confidence: model.ConfidenceMedium,
			Evidence:   evidence,
		})
	}
	if evidence := tcpFailures(result.TCP); len(evidence) > 0 {
		findings = append(findings, model.Finding{
			Type:       model.FindingTCPConnectFailure,
			Layer:      model.LayerTCP,
			Confidence: model.ConfidenceLow,
			Evidence:   evidence,
		})
	}
	if evidence := tlsFailures(result.TLS); len(evidence) > 0 {
		findings = append(findings, model.Finding{
			Type:       model.FindingTLSHandshakeFailure,
			Layer:      model.LayerTLS,
			Confidence: model.ConfidenceLow,
			Evidence:   evidence,
		})
	}
	if evidence := sniCorrelatedFailures(result.TLS); len(evidence) > 0 {
		findings = append(findings, model.Finding{
			Type:       model.FindingSNICorrelated,
			Layer:      model.LayerTLS,
			Confidence: model.ConfidenceMedium,
			Evidence:   evidence,
		})
	}
	if evidence := httpFailures(result.HTTP); len(evidence) > 0 {
		findings = append(findings, model.Finding{
			Type:       model.FindingHTTPFailure,
			Layer:      model.LayerHTTP,
			Confidence: model.ConfidenceLow,
			Evidence:   evidence,
		})
	}
	if result.Trace != nil && !result.Trace.Success && !isLocalTraceError(result.Trace.Error) {
		findings = append(findings, model.Finding{
			Type:       model.FindingPathQuality,
			Layer:      model.LayerTrace,
			Confidence: model.ConfidenceLow,
			Evidence:   []string{result.Trace.Error},
		})
	}
	return findings
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
		if len(sets) > 1 {
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

func tcpFailures(observations []model.TCPObservation) []string {
	type state struct {
		success bool
		last    model.TCPObservation
	}
	byEndpoint := map[string]state{}
	for _, observation := range observations {
		key := fmt.Sprintf("%s:%d", observation.Host, observation.Port)
		current := byEndpoint[key]
		if observation.Success {
			current.success = true
		}
		current.last = observation
		byEndpoint[key] = current
	}
	var evidence []string
	for key, current := range byEndpoint {
		if !current.success {
			evidence = append(evidence, fmt.Sprintf("%s failed: %s", key, current.last.ErrorKind))
		}
	}
	return evidence
}

func tlsFailures(observations []model.TLSObservation) []string {
	type state struct {
		success bool
		last    model.TLSObservation
	}
	byEndpoint := map[string]state{}
	for _, observation := range observations {
		key := observation.Address + "|" + observation.SNI
		current := byEndpoint[key]
		if observation.Success {
			current.success = true
		}
		current.last = observation
		byEndpoint[key] = current
	}
	var evidence []string
	for _, current := range byEndpoint {
		if !current.success {
			evidence = append(evidence, fmt.Sprintf("%s failed: %s", current.last.SNI, current.last.Error))
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
	var evidence []string
	for address, current := range byAddress {
		if len(current.success) > 0 && len(current.failed) > 0 {
			evidence = append(evidence, fmt.Sprintf("%s succeeded for SNI %s but failed for SNI %s", address, strings.Join(current.success, ","), strings.Join(current.failed, ",")))
		}
	}
	return evidence
}

func httpFailures(observations []model.HTTPObservation) []string {
	type state struct {
		success bool
		last    model.HTTPObservation
	}
	byURL := map[string]state{}
	for _, observation := range observations {
		current := byURL[observation.URL]
		if observation.Success {
			current.success = true
		}
		current.last = observation
		byURL[observation.URL] = current
	}
	var evidence []string
	for url, current := range byURL {
		if current.success {
			continue
		}
		if current.last.Error != "" {
			evidence = append(evidence, fmt.Sprintf("%s failed: %s", url, current.last.Error))
			continue
		}
		evidence = append(evidence, fmt.Sprintf("%s returned status %d", url, current.last.StatusCode))
	}
	return evidence
}

func isSuspiciousIP(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

func isLocalTraceError(message string) bool {
	lower := strings.ToLower(message)
	return strings.Contains(lower, "operation not permitted") || strings.Contains(lower, "permission denied")
}
