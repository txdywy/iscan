package icmpping

import (
	"context"
	"testing"
	"time"
)

func TestProbeReturnsObservation(t *testing.T) {
	ctx := context.Background()
	obs := Probe(ctx, "192.0.2.1", 1*time.Second)
	// Even on failure, Target must be set
	if obs.Target != "192.0.2.1" {
		t.Errorf("expected Target=192.0.2.1, got %q", obs.Target)
	}
	// Latency must be non-zero (defer captures time)
	if obs.Latency == 0 {
		t.Error("expected non-zero Latency")
	}
}

func TestProbeInvalidTarget(t *testing.T) {
	ctx := context.Background()
	obs := Probe(ctx, "invalid-.domain", 1*time.Second)
	if obs.Success {
		t.Error("expected failure for invalid target")
	}
	if obs.Error == "" {
		t.Error("expected error for invalid target")
	}
}
