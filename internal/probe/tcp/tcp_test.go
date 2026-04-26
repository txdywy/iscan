package tcp_test

import (
	"context"
	"net"
	"testing"
	"time"

	"iscan/internal/probe/tcp"
)

func TestProbeConnectSuccess(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = listener.Close()
	}()

	done := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
		}
		close(done)
	}()

	host, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	observation := tcp.Probe(context.Background(), host, mustPort(t, port), 2*time.Second)
	if !observation.Success {
		t.Fatalf("expected TCP success, got %#v", observation)
	}
	if observation.Latency <= 0 {
		t.Fatalf("expected latency to be recorded, got %s", observation.Latency)
	}

	<-done
}

func TestClassifyConnectionRefused(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}

	observation := tcp.Probe(context.Background(), host, mustPort(t, port), 500*time.Millisecond)
	if observation.Success {
		t.Fatalf("expected TCP failure, got %#v", observation)
	}
	if observation.ErrorKind != "refused" {
		t.Fatalf("expected refused error kind, got %#v", observation)
	}
}

func mustPort(t *testing.T, value string) int {
	t.Helper()
	port, err := net.LookupPort("tcp", value)
	if err != nil {
		t.Fatal(err)
	}
	return port
}
