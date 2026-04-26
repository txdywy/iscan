package profile_test

import (
	"testing"
	"time"

	"iscan/internal/model"
	"iscan/internal/profile"
)

func TestBuildProfileComputesTiers(t *testing.T) {
	report := model.ScanReport{
		Targets: []model.TargetResult{
			{
				Target: model.Target{Domain: "example.com"},
				DNS: []model.DNSObservation{
					{Resolver: "system", Answers: []string{"93.184.216.34"}, Success: true, Latency: 30 * time.Millisecond},
					{Resolver: "cloudflare", Answers: []string{"93.184.216.34"}, Success: true, Latency: 25 * time.Millisecond},
				},
				TCP: []model.TCPObservation{
					{Success: true, Host: "93.184.216.34", Port: 443, Latency: 50 * time.Millisecond},
				},
				TLS: []model.TLSObservation{
					{Success: true, SNI: "example.com", Version: "TLS1.3", Address: "93.184.216.34:443"},
				},
			},
		},
	}

	prof := profile.BuildProfile(report)

	if prof.TCPHealth.SuccessRate != 1.0 {
		t.Fatalf("expected TCP success rate 1.0, got %.2f", prof.TCPHealth.SuccessRate)
	}
	if prof.TCPHealth.Tier != profile.QualityExcellent {
		t.Fatalf("expected TCP tier excellent, got %q", prof.TCPHealth.Tier)
	}
	if prof.TLSHealth.Tier != profile.QualityExcellent {
		t.Fatalf("expected TLS tier excellent, got %q", prof.TLSHealth.Tier)
	}
	if prof.DNSHealth.Tier != profile.QualityExcellent {
		t.Fatalf("expected DNS tier excellent, got %q", prof.DNSHealth.Tier)
	}
	if !prof.DNSHealth.Agreement {
		t.Fatal("expected DNS agreement for matching answer sets")
	}
	if prof.OverallStability < 0.8 {
		t.Fatalf("expected high overall stability, got %.2f", prof.OverallStability)
	}
}

func TestBuildProfileDetectsSNIFiltering(t *testing.T) {
	report := model.ScanReport{
		Targets: []model.TargetResult{
			{
				Target: model.Target{Domain: "blocked.example"},
				TLS: []model.TLSObservation{
					{Address: "1.2.3.4:443", SNI: "blocked.example", Success: false, Error: "reset"},
					{Address: "1.2.3.4:443", SNI: "example.com", Success: true},
				},
			},
		},
		Findings: []model.Finding{
			{Type: model.FindingSNICorrelated, Layer: model.LayerTLS, Confidence: model.ConfidenceMedium},
		},
	}

	prof := profile.BuildProfile(report)

	if !prof.TLSHealth.HasSNIFiltering {
		t.Fatal("expected SNI filtering flag set")
	}
}

func TestBuildProfileDegradesOnErrors(t *testing.T) {
	report := model.ScanReport{
		Targets: []model.TargetResult{
			{
				Target: model.Target{Domain: "broken.example"},
				TCP: []model.TCPObservation{
					{Success: false, ErrorKind: "refused", Host: "broken.example", Port: 443},
				},
				TLS: []model.TLSObservation{},
			},
		},
	}

	prof := profile.BuildProfile(report)

	if prof.TCPHealth.SuccessRate != 0 {
		t.Fatalf("expected TCP success rate 0, got %.2f", prof.TCPHealth.SuccessRate)
	}
	if prof.TCPHealth.Tier != profile.QualityPoor {
		t.Fatalf("expected TCP tier poor, got %q", prof.TCPHealth.Tier)
	}
	if prof.OverallStability > 0.55 {
		t.Fatalf("expected low overall stability, got %.2f", prof.OverallStability)
	}
}
