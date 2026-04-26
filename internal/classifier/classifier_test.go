package classifier_test

import (
	"testing"

	"iscan/internal/classifier"
	"iscan/internal/model"
)

func TestClassifyReportsDNSInconsistencyWithoutPoisoning(t *testing.T) {
	result := model.TargetResult{
		Target: model.Target{Name: "example", Domain: "example.com"},
		Results: []model.ProbeResult{
			{Layer: model.LayerDNS, Data: model.DNSObservation{Resolver: "system", Answers: []string{"93.184.216.34"}}},
			{Layer: model.LayerDNS, Data: model.DNSObservation{Resolver: "public", Answers: []string{"93.184.216.35"}}},
		},
	}

	findings := classifier.Classify(result)

	if !hasFinding(findings, model.FindingDNSInconsistent) {
		t.Fatalf("expected dns_inconsistent finding, got %#v", findings)
	}
	if hasFinding(findings, model.FindingDNSSuspiciousAnswer) {
		t.Fatalf("did not expect suspicious DNS finding for ordinary resolver disagreement: %#v", findings)
	}
}

func TestClassifyDoesNotCompareAAndAAAAAsInconsistent(t *testing.T) {
	result := model.TargetResult{
		Target: model.Target{Name: "dualstack", Domain: "example.com"},
		Results: []model.ProbeResult{
			{Layer: model.LayerDNS, Data: model.DNSObservation{Resolver: "system", Type: "A", Answers: []string{"93.184.216.34"}}},
			{Layer: model.LayerDNS, Data: model.DNSObservation{Resolver: "system", Type: "AAAA", Answers: []string{"2606:2800:220:1:248:1893:25c8:1946"}}},
			{Layer: model.LayerDNS, Data: model.DNSObservation{Resolver: "public", Type: "A", Answers: []string{"93.184.216.34"}}},
			{Layer: model.LayerDNS, Data: model.DNSObservation{Resolver: "public", Type: "AAAA", Answers: []string{"2606:2800:220:1:248:1893:25c8:1946"}}},
		},
	}

	findings := classifier.Classify(result)

	if hasFinding(findings, model.FindingDNSInconsistent) {
		t.Fatalf("did not expect A and AAAA to be compared as inconsistent: %#v", findings)
	}
}

func TestClassifyReportsSuspiciousDNSForPrivateAnswer(t *testing.T) {
	result := model.TargetResult{
		Target: model.Target{Name: "blocked", Domain: "blocked.example"},
		Results: []model.ProbeResult{
			{Layer: model.LayerDNS, Data: model.DNSObservation{Resolver: "system", Answers: []string{"10.0.0.1"}}},
			{Layer: model.LayerDNS, Data: model.DNSObservation{Resolver: "public", Answers: []string{"93.184.216.34"}}},
		},
	}

	findings := classifier.Classify(result)

	if !hasFinding(findings, model.FindingDNSSuspiciousAnswer) {
		t.Fatalf("expected dns_suspicious_answer finding, got %#v", findings)
	}
}

func TestClassifyKeepsSingleTLSFailureLowConfidence(t *testing.T) {
	result := model.TargetResult{
		Target: model.Target{Name: "tls", Domain: "tls.example"},
		Results: []model.ProbeResult{
			{Layer: model.LayerTLS, Data: model.TLSObservation{SNI: "tls.example", Success: false, Error: "remote error: tls: handshake failure"}},
		},
	}

	findings := classifier.Classify(result)

	finding, ok := getFinding(findings, model.FindingTLSHandshakeFailure)
	if !ok {
		t.Fatalf("expected tls_handshake_failure finding, got %#v", findings)
	}
	if finding.Confidence != model.ConfidenceLow {
		t.Fatalf("expected low confidence for single TLS failure, got %q", finding.Confidence)
	}
}

func TestClassifyReportsSNICorrelatedFailureWhenSameAddressDiffersBySNI(t *testing.T) {
	result := model.TargetResult{
		Target: model.Target{Name: "sni", Domain: "sni.example"},
		Results: []model.ProbeResult{
			{Layer: model.LayerTLS, Data: model.TLSObservation{Address: "203.0.113.10:443", SNI: "sni.example", Success: false, Error: "connection reset"}},
			{Layer: model.LayerTLS, Data: model.TLSObservation{Address: "203.0.113.10:443", SNI: "example.com", Success: true}},
		},
	}

	findings := classifier.Classify(result)

	if !hasFinding(findings, model.FindingSNICorrelated) {
		t.Fatalf("expected sni_correlated_failure finding, got %#v", findings)
	}
}

func TestClassifyReportsHTTPApplicationFailure(t *testing.T) {
	result := model.TargetResult{
		Target: model.Target{Name: "http", Domain: "http.example"},
		Results: []model.ProbeResult{
			{Layer: model.LayerHTTP, Data: model.HTTPObservation{URL: "https://http.example/", StatusCode: 503, Success: false, Error: "status 503"}},
		},
	}

	findings := classifier.Classify(result)

	if !hasFinding(findings, model.FindingHTTPFailure) {
		t.Fatalf("expected http_application_failure finding, got %#v", findings)
	}
}

func TestClassifyReportsQUICHandshakeFailure(t *testing.T) {
	result := model.TargetResult{
		Target: model.Target{Name: "quic", Domain: "quic.example"},
		Results: []model.ProbeResult{
			{Layer: model.LayerQUIC, Data: model.QUICObservation{SNI: "quic.example", Success: false, Error: "timeout: no recent network activity"}},
		},
	}

	findings := classifier.Classify(result)

	if !hasFinding(findings, model.FindingQUICFailure) {
		t.Fatalf("expected quic_handshake_failure finding, got %#v", findings)
	}
}

func TestClassifyDoesNotTreatTracePermissionErrorAsPathQuality(t *testing.T) {
	result := model.TargetResult{
		Target: model.Target{Name: "trace", Domain: "trace.example"},
		Results: []model.ProbeResult{
			{Layer: model.LayerTrace, Data: model.TraceObservation{Success: false, Error: "listen ip4:icmp 0.0.0.0: socket: operation not permitted"}},
		},
	}

	findings := classifier.Classify(result)

	if hasFinding(findings, model.FindingPathQuality) {
		t.Fatalf("did not expect path quality finding for local permission error: %#v", findings)
	}
}

func TestClassifyReportsRCODE_NXDOMAIN(t *testing.T) {
	result := model.TargetResult{
		Target: model.Target{Name: "nxdomain", Domain: "nonexistent.example"},
		Results: []model.ProbeResult{
			{Layer: model.LayerDNS, Data: model.DNSObservation{Resolver: "system", Query: "nonexistent.example.", RCode: "NXDOMAIN", Success: false}},
		},
	}

	findings := classifier.Classify(result)

	finding, ok := getFinding(findings, model.FindingDNSNXDOMAIN)
	if !ok {
		t.Fatalf("expected dns_nxdomain finding, got %#v", findings)
	}
	if finding.Confidence != model.ConfidenceHigh {
		t.Fatalf("expected high confidence for NXDOMAIN, got %q", finding.Confidence)
	}
}

func TestClassifyReportsRCODE_SERVFAIL(t *testing.T) {
	result := model.TargetResult{
		Target: model.Target{Name: "servfail", Domain: "broken.example"},
		Results: []model.ProbeResult{
			{Layer: model.LayerDNS, Data: model.DNSObservation{Resolver: "system", Query: "broken.example.", RCode: "SERVFAIL", Success: false}},
		},
	}

	findings := classifier.Classify(result)

	finding, ok := getFinding(findings, model.FindingDNSSERVFAIL)
	if !ok {
		t.Fatalf("expected dns_servfail finding, got %#v", findings)
	}
	if finding.Confidence != model.ConfidenceMedium {
		t.Fatalf("expected medium confidence for SERVFAIL, got %q", finding.Confidence)
	}
}

func TestClassifyReportsRCODE_REFUSED(t *testing.T) {
	result := model.TargetResult{
		Target: model.Target{Name: "refused", Domain: "blocked.example"},
		Results: []model.ProbeResult{
			{Layer: model.LayerDNS, Data: model.DNSObservation{Resolver: "public", Query: "blocked.example.", RCode: "REFUSED", Success: false}},
		},
	}

	findings := classifier.Classify(result)

	finding, ok := getFinding(findings, model.FindingDNSREFUSED)
	if !ok {
		t.Fatalf("expected dns_refused finding, got %#v", findings)
	}
	if finding.Confidence != model.ConfidenceHigh {
		t.Fatalf("expected high confidence for REFUSED, got %q", finding.Confidence)
	}
}

func TestClassifyReportsRCODE_Other(t *testing.T) {
	result := model.TargetResult{
		Target: model.Target{Name: "other", Domain: "error.example"},
		Results: []model.ProbeResult{
			{Layer: model.LayerDNS, Data: model.DNSObservation{Resolver: "system", Query: "error.example.", RCode: "FORMERR", Success: false}},
		},
	}

	findings := classifier.Classify(result)

	finding, ok := getFinding(findings, model.FindingDNSOtherRCODE)
	if !ok {
		t.Fatalf("expected dns_other_rcode finding, got %#v", findings)
	}
	if finding.Confidence != model.ConfidenceLow {
		t.Fatalf("expected low confidence for other RCODE, got %q", finding.Confidence)
	}
}

func TestClassifyNoRCODEFindingForNOERROR(t *testing.T) {
	result := model.TargetResult{
		Target: model.Target{Name: "ok", Domain: "example.com"},
		Results: []model.ProbeResult{
			{Layer: model.LayerDNS, Data: model.DNSObservation{Resolver: "system", Query: "example.com.", RCode: "NOERROR", Success: true, Answers: []string{"93.184.216.34"}}},
		},
	}

	findings := classifier.Classify(result)

	for _, typ := range []model.FindingType{model.FindingDNSNXDOMAIN, model.FindingDNSSERVFAIL, model.FindingDNSREFUSED, model.FindingDNSOtherRCODE} {
		if hasFinding(findings, typ) {
			t.Fatalf("did not expect %s finding for NOERROR response", typ)
		}
	}
}

func TestClassifyCollectsDNSObservationsFromSliceData(t *testing.T) {
	result := model.TargetResult{
		Target: model.Target{Name: "slice", Domain: "example.com"},
		Results: []model.ProbeResult{
			{Layer: model.LayerDNS, Data: []model.DNSObservation{
				{Resolver: "cloudflare-doh", Query: "example.com.", RCode: "NXDOMAIN", Success: false, Type: "A"},
			}},
		},
	}

	findings := classifier.Classify(result)

	if !hasFinding(findings, model.FindingDNSNXDOMAIN) {
		t.Fatalf("expected dns_nxdomain finding from slice data, got %#v", findings)
	}
}

func hasFinding(findings []model.Finding, typ model.FindingType) bool {
	_, ok := getFinding(findings, typ)
	return ok
}

func TestClassifyDetectsTransparentDNSProxy(t *testing.T) {
	result := model.TargetResult{
		Target: model.Target{Name: "proxy", Domain: "example.com"},
		Results: []model.ProbeResult{
			{Layer: model.LayerDNS, Data: model.DNSObservation{
				Resolver: "cloudflare",
				Query:    "whoami.akamai.net.",
				Answers:  []string{"10.0.0.1"},
				Success:  true,
			}},
		},
	}

	findings := classifier.Classify(result)

	finding, ok := getFinding(findings, model.FindingDNSTransparentProxy)
	if !ok {
		t.Fatalf("expected dns_transparent_proxy finding for unexpected whoami response, got %#v", findings)
	}
	if finding.Confidence != model.ConfidenceHigh {
		t.Fatalf("expected high confidence for transparent proxy detection, got %q", finding.Confidence)
	}
}

func TestClassifyNoTransparentProxyForKnownResolverIP(t *testing.T) {
	result := model.TargetResult{
		Target: model.Target{Name: "normal", Domain: "example.com"},
		Results: []model.ProbeResult{
			{Layer: model.LayerDNS, Data: model.DNSObservation{
				Resolver: "cloudflare",
				Query:    "whoami.akamai.net.",
				Answers:  []string{"1.1.1.1"},
				Success:  true,
			}},
		},
	}

	findings := classifier.Classify(result)

	if hasFinding(findings, model.FindingDNSTransparentProxy) {
		t.Fatalf("did not expect transparent proxy finding for known resolver IP, got %#v", findings)
	}
}

func TestClassifyNoTransparentProxyForNonWhoamiQuery(t *testing.T) {
	result := model.TargetResult{
		Target: model.Target{Name: "normal", Domain: "example.com"},
		Results: []model.ProbeResult{
			{Layer: model.LayerDNS, Data: model.DNSObservation{
				Resolver: "system",
				Query:    "example.com.",
				Answers:  []string{"93.184.216.34"},
				Success:  true,
			}},
		},
	}

	findings := classifier.Classify(result)

	if hasFinding(findings, model.FindingDNSTransparentProxy) {
		t.Fatalf("did not expect transparent proxy finding for non-whoami query, got %#v", findings)
	}
}

func getFinding(findings []model.Finding, typ model.FindingType) (model.Finding, bool) {
	for _, finding := range findings {
		if finding.Type == typ {
			return finding, true
		}
	}
	return model.Finding{}, false
}
