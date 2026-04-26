package scanner

import (
	"context"
	"testing"
	"time"

	"iscan/internal/model"
)

func TestRetryWithBackoffReturnsLastFailedObservation(t *testing.T) {
	attempts := 0
	got := retryWithBackoff(context.Background(), 3, time.Nanosecond,
		func() (model.TCPObservation, bool) {
			attempts++
			o := model.TCPObservation{
				Host:      "203.0.113.10",
				Port:      443,
				Error:     "attempt failed",
				ErrorKind: "timeout",
			}
			if attempts == 3 {
				o.Error = "final timeout"
			}
			return o, false
		})

	if attempts != 3 {
		t.Fatalf("expected 3 attempts, got %d", attempts)
	}
	if got.Host != "203.0.113.10" || got.Port != 443 || got.Error != "final timeout" || got.ErrorKind != "timeout" {
		t.Fatalf("expected final failed observation, got %#v", got)
	}
}
