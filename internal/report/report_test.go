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
				DNS:    []model.DNSObservation{{Success: true}},
				TCP:    []model.TCPObservation{{Success: true}},
				TLS:    []model.TLSObservation{{Success: true}},
				HTTP:   []model.HTTPObservation{{Success: true, StatusCode: 204}},
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
