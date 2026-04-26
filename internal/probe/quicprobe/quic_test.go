package quicprobe_test

import (
	"context"
	"testing"
	"time"

	"iscan/internal/probe/quicprobe"
)

func TestProbeQUICRecordsFailureOnNonQUICEndpoint(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	observation := quicprobe.Probe(ctx, "127.0.0.1", 1, "localhost", []string{"h3"}, 2*time.Second)

	if observation.Success {
		t.Fatalf("expected QUIC failure on non-QUIC endpoint, got %#v", observation)
	}
	if observation.Error == "" {
		t.Fatal("expected error message")
	}
	if observation.SNI != "localhost" {
		t.Fatalf("expected SNI localhost, got %q", observation.SNI)
	}
}
