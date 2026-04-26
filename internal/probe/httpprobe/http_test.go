package httpprobe_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"iscan/internal/probe/httpprobe"
)

func TestProbeHTTPRecordsStatusAndFirstByte(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	observation := httpprobe.Probe(context.Background(), server.URL, 2*time.Second)
	if !observation.Success {
		t.Fatalf("expected HTTP success, got %#v", observation)
	}
	if observation.StatusCode != http.StatusAccepted {
		t.Fatalf("expected status 202, got %#v", observation)
	}
	if observation.FirstByteLatency <= 0 {
		t.Fatalf("expected first byte latency, got %#v", observation)
	}
}
