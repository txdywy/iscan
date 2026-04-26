package dnsprobe

import (
	"context"
	"testing"

	"golang.org/x/time/rate"
)

// TestGetLimiterSameName verifies that getLimiter returns the same limiter
// for the same resolver name (shared across calls).
func TestGetLimiterSameName(t *testing.T) {
	l1 := getLimiter("test_resolver")
	l2 := getLimiter("test_resolver")
	if l1 != l2 {
		t.Fatal("expected same limiter pointer for same resolver name")
	}
}

// TestWaitLimiterRespectsContext verifies that waitLimiter returns an error
// when the context is already cancelled (token bucket has no tokens).
func TestWaitLimiterRespectsContext(t *testing.T) {
	SetRateLimit(1)

	// Manually store a limiter with 1 token that has been consumed.
	resolverLimiters.Store("ctx_test", rate.NewLimiter(1, 1))
	lim := getLimiter("ctx_test")
	if !lim.Allow() {
		t.Fatal("expected Allow to succeed (one token available)")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := waitLimiter(ctx, "ctx_test")
	if err == nil {
		t.Fatal("expected error from waitLimiter with cancelled context")
	}
	if err.Error() != "context canceled" {
		t.Fatalf("expected 'context canceled' error, got: %v", err)
	}
}

// TestSetRateLimitZeroMeansUnlimited verifies that setting QPS to 0 makes
// waitLimiter return immediately without blocking.
func TestSetRateLimitZeroMeansUnlimited(t *testing.T) {
	SetRateLimit(0)

	err := waitLimiter(context.Background(), "unlimited_test")
	if err != nil {
		t.Fatalf("expected no error for unlimited rate limit, got: %v", err)
	}

	// Restore default for other tests.
	SetRateLimit(20)
}
