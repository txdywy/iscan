package tlsprobe_test

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"iscan/internal/probe/tlsprobe"
)

func TestProbeTLSSuccessRecordsVersionAndALPN(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	host, port := splitServerAddr(t, server.Listener.Addr().String())

	observation := tlsprobe.Probe(context.Background(), host, port, "example.com", []string{"h2", "http/1.1"}, 2*time.Second, true)
	if !observation.Success {
		t.Fatalf("expected TLS success, got %#v", observation)
	}
	if observation.Version == "" {
		t.Fatalf("expected TLS version, got %#v", observation)
	}
	if observation.CertSHA256 == "" {
		t.Fatalf("expected certificate digest, got %#v", observation)
	}
}

func TestProbeTLSHandshakeFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = listener.Close()
	}()

	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	host, port := splitServerAddr(t, listener.Addr().String())
	observation := tlsprobe.Probe(context.Background(), host, port, "example.com", nil, 2*time.Second, true)

	if observation.Success {
		t.Fatalf("expected TLS failure, got %#v", observation)
	}
	if observation.Error == "" {
		t.Fatalf("expected TLS error, got %#v", observation)
	}
}

func splitServerAddr(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portString, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := net.LookupPort("tcp", portString)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}

var _ = tls.VersionTLS13
