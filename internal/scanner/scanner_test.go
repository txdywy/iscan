package scanner_test

import (
	"testing"
	"time"

	"iscan/internal/model"
	"iscan/internal/scanner"
)

func TestUniqueAnswersSortedAndDeduplicated(t *testing.T) {
	obs := []model.DNSObservation{
		{Answers: []string{"1.1.1.1", "2.2.2.2"}},
		{Answers: []string{"2.2.2.2", "3.3.3.3"}},
	}
	got := scanner.UniqueAnswers(obs)
	want := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}
	if len(got) != len(want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expected %v, got %v", want, got)
		}
	}
}

func TestTargetURLHandlesEmptyPath(t *testing.T) {
	u := scanner.TargetURL(model.Target{Scheme: "https", Domain: "example.com"})
	if u != "https://example.com/" {
		t.Fatalf("expected https://example.com/, got %s", u)
	}
}

func TestTargetURLPreservesPath(t *testing.T) {
	u := scanner.TargetURL(model.Target{Scheme: "https", Domain: "example.com", HTTPPath: "/health"})
	if u != "https://example.com/health" {
		t.Fatalf("expected https://example.com/health, got %s", u)
	}
}

func TestHasSuccessfulTLSForSNIMatchesExactSNI(t *testing.T) {
	obs := []model.TLSObservation{
		{SNI: "example.com", Success: true},
		{SNI: "other.com", Success: false},
	}
	if !scanner.HasSuccessfulTLSForSNI(obs, "example.com") {
		t.Fatal("expected true for matching SNI")
	}
	if scanner.HasSuccessfulTLSForSNI(obs, "other.com") {
		t.Fatal("expected false for failed SNI")
	}
	if scanner.HasSuccessfulTLSForSNI(obs, "missing.com") {
		t.Fatal("expected false for missing SNI")
	}
}

func TestBuildScanReportSkipsCancelledTargets(t *testing.T) {
	// This is an integration-level smoke test: Run with a tiny timeout
	// against the builtin target set should return at least one target
	// without panicking.
	report := scanner.Run(t.Context(), model.ScanOptions{
		Timeout: 100 * time.Millisecond,
		Retries: 1,
		Trace:   false,
		QUIC:    false,
	})
	if len(report.Targets) == 0 {
		t.Fatal("expected at least one target result")
	}
	if report.Duration <= 0 {
		t.Fatal("expected positive duration")
	}
}

func TestTargetFailureDoesNotCancelOthers(t *testing.T) {
	report := scanner.Run(t.Context(), model.ScanOptions{
		Timeout: 500 * time.Millisecond,
		Retries: 1,
		Trace:   false,
		QUIC:    false,
	})
	if len(report.Targets) < 2 {
		t.Fatalf("expected at least 2 target results, got %d -- first failure may have cancelled others", len(report.Targets))
	}
	for i, result := range report.Targets {
		if result.Target.Name == "" {
			t.Errorf("target %d has empty name -- was cancelled before scan started", i)
		}
	}
	if report.Duration <= 0 {
		t.Fatal("expected positive duration")
	}
	t.Logf("scanned %d targets in %v", len(report.Targets), report.Duration)
}
