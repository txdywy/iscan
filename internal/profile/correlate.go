package profile

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"iscan/internal/classifier"
	"iscan/internal/model"
)

func Correlate(report model.ScanReport) []model.Finding {
	controlTargets, diagnosticTargets := splitTargets(report)
	if len(controlTargets) == 0 || len(diagnosticTargets) == 0 {
		return nil
	}

	now := time.Now()
	var findings []model.Finding
	for _, layer := range []model.Layer{model.LayerDNS, model.LayerTCP, model.LayerTLS, model.LayerQUIC, model.LayerTrace, model.LayerHTTP} {
		controlSuccesses := layerTargetsWithSuccess(controlTargets, layer)
		diagnosticFailures := layerTargetsWithFailure(diagnosticTargets, layer)
		if len(controlSuccesses) == 0 || len(diagnosticFailures) == 0 {
			continue
		}
		findings = append(findings, model.Finding{
			Type:       model.FindingControlDiagnosticDivergence,
			Layer:      layer,
			Confidence: classifier.CalibrateConfidence(classifier.ConfidenceSignals{Base: model.ConfidenceMedium, EvidenceCount: len(controlSuccesses) + len(diagnosticFailures), ControlCorroborated: true}),
			Evidence: []string{
				fmt.Sprintf("controls succeeded on %s: %s", layer, strings.Join(controlSuccesses, ", ")),
				fmt.Sprintf("diagnostics failed on %s: %s", layer, strings.Join(diagnosticFailures, ", ")),
			},
			ObservedAt: now,
		})
	}
	return findings
}

func splitTargets(report model.ScanReport) (controlTargets, diagnosticTargets []model.TargetResult) {
	for _, target := range report.Targets {
		if target.Target.Control {
			controlTargets = append(controlTargets, target)
			continue
		}
		diagnosticTargets = append(diagnosticTargets, target)
	}
	return controlTargets, diagnosticTargets
}

func countFindingsInTargets(targets []model.TargetResult, typ model.FindingType) int {
	n := 0
	for _, target := range targets {
		for _, finding := range target.Findings {
			if finding.Type == typ {
				n++
			}
		}
	}
	return n
}

func hasFindingInTargets(targets []model.TargetResult, typ model.FindingType) bool {
	return countFindingsInTargets(targets, typ) > 0
}

func layerTargetsWithSuccess(targets []model.TargetResult, layer model.Layer) []string {
	var names []string
	for _, target := range targets {
		if layerTargetStatus(target, layer) == targetSuccess {
			names = append(names, targetLabel(target.Target))
		}
	}
	sort.Strings(names)
	return names
}

func layerTargetsWithFailure(targets []model.TargetResult, layer model.Layer) []string {
	var names []string
	for _, target := range targets {
		if layerTargetStatus(target, layer) == targetFailure {
			names = append(names, targetLabel(target.Target))
		}
	}
	sort.Strings(names)
	return names
}

type targetLayerStatus int

const (
	targetUnknown targetLayerStatus = iota
	targetSuccess
	targetFailure
)

func layerTargetStatus(target model.TargetResult, layer model.Layer) targetLayerStatus {
	var success bool
	var failure bool

	for _, finding := range target.Findings {
		if finding.Layer == layer {
			failure = true
			break
		}
	}

	switch layer {
	case model.LayerDNS:
		dnsObs := collectObservations[model.DNSObservation](target.Results, model.LayerDNS)
		for _, obs := range dnsObs {
			if obs.Success && obs.RCode != "" && obs.RCode != "NOERROR" {
				failure = true
			}
			if obs.Success && obs.RCode == "NOERROR" {
				success = true
			}
			if !obs.Success {
				failure = true
			}
		}
	case model.LayerTCP:
		tcpObs := collectObservations[model.TCPObservation](target.Results, model.LayerTCP)
		for _, obs := range tcpObs {
			if obs.Success {
				success = true
			} else {
				failure = true
			}
		}
	case model.LayerTLS:
		tlsObs := collectObservations[model.TLSObservation](target.Results, model.LayerTLS)
		for _, obs := range tlsObs {
			if obs.Success {
				success = true
			} else {
				failure = true
			}
		}
	case model.LayerQUIC:
		quicObs := collectObservations[model.QUICObservation](target.Results, model.LayerQUIC)
		for _, obs := range quicObs {
			if obs.Success {
				success = true
			} else {
				failure = true
			}
		}
	case model.LayerTrace:
		traceObs := collectObservation[model.TraceObservation](target.Results, model.LayerTrace)
		if traceObs != nil {
			if traceObs.Success {
				success = true
			} else if !model.IsLocalPermissionError(traceObs.Error) {
				failure = true
			}
		}
	case model.LayerHTTP:
		httpObs := collectObservations[model.HTTPObservation](target.Results, model.LayerHTTP)
		for _, obs := range httpObs {
			if obs.Success {
				success = true
			} else {
				failure = true
			}
		}
	default:
		return targetUnknown
	}

	if failure {
		return targetFailure
	}
	if success {
		return targetSuccess
	}
	return targetUnknown
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
