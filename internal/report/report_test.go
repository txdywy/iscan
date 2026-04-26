package report_test

import (
	"strings"
	"testing"

	"iscan/internal/model"
	"iscan/internal/report"
)

func TestSummaryIncludesTargetAndFinding(t *testing.T) {
	scan := model.ScanReport{
		Targets: []model.TargetResult{
			{
				Target: model.Target{Name: "example", Domain: "example.com"},
				Results: []model.ProbeResult{
					{Layer: model.LayerDNS, Data: model.DNSObservation{Success: true}},
					{Layer: model.LayerTCP, Data: model.TCPObservation{Success: true}},
					{Layer: model.LayerTLS, Data: model.TLSObservation{Success: true}},
					{Layer: model.LayerHTTP, Data: model.HTTPObservation{Success: true, StatusCode: 204}},
				},
				Findings: []model.Finding{{
					Type:       model.FindingDNSInconsistent,
					Layer:      model.LayerDNS,
					Confidence: model.ConfidenceLow,
					Evidence:   []string{"resolver answer sets differ"},
				}},
			},
		},
	}

	summary := report.Summary(scan)
	if !strings.Contains(summary, "example.com") {
		t.Fatalf("expected domain in summary, got %q", summary)
	}
	if !strings.Contains(summary, "dns_inconsistent") {
		t.Fatalf("expected finding in summary, got %q", summary)
	}
}
