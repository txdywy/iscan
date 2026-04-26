package httpprobe_test

import (
	"context"
	"crypto/tls"
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

func TestProbeWithAddressUsesFixedDialAddressAndPreservesHostAndSNI(t *testing.T) {
	var gotHost string
	var gotSNI string
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			gotSNI = hello.ServerName
			return nil, nil
		},
	}
	server.StartTLS()
	defer server.Close()

	observation := httpprobe.ProbeWithAddress(context.Background(), "https://diagnostic.example/status", server.Listener.Addr().String(), 2*time.Second)

	if !observation.Success {
		t.Fatalf("expected HTTP success through fixed address, got %#v", observation)
	}
	if observation.DialAddress != server.Listener.Addr().String() {
		t.Fatalf("expected dial address %q, got %#v", server.Listener.Addr().String(), observation)
	}
	if gotHost != "diagnostic.example" {
		t.Fatalf("expected Host header to preserve URL host, got %q", gotHost)
	}
	if gotSNI != "diagnostic.example" {
		t.Fatalf("expected SNI diagnostic.example, got %q", gotSNI)
	}
}
