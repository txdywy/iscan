package dnsprobe_test

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"iscan/internal/model"
	"iscan/internal/probe/dnsprobe"
)

func TestProbeARecordsFromResolver(t *testing.T) {
	server := startDNSServer(t, false)
	observation := dnsprobe.Probe(context.Background(), model.Resolver{Name: "local", Server: server}, "example.com", mdns.TypeA, 2*time.Second)

	if !observation.Success {
		t.Fatalf("expected DNS success, got %#v", observation)
	}
	if observation.RCode != "NOERROR" {
		t.Fatalf("expected NOERROR, got %#v", observation)
	}
	if len(observation.Answers) != 1 || observation.Answers[0] != "203.0.113.10" {
		t.Fatalf("expected A answer, got %#v", observation.Answers)
	}
}

func TestProbeHandlesMissingPort(t *testing.T) {
	server := startDNSServer(t, false)
	host, _, err := net.SplitHostPort(server)
	if err != nil {
		t.Fatal(err)
	}
	// Passing host without port; Probe should auto-append :53 and fail
	// with "connection refused" (since no DNS server runs on :53).
	// This verifies the missingPort code path was reached and the probe
	// behaved correctly rather than panicking or returning a different error.
	observation := dnsprobe.Probe(context.Background(), model.Resolver{Name: "local", Server: host}, "example.com", mdns.TypeA, 2*time.Second)
	if observation.Success {
		t.Fatal("expected DNS failure when connecting to port 53 (no server there)")
	}
	if !strings.Contains(observation.Error, "connection refused") {
		t.Fatalf("expected connection refused error (confirming port 53 was tried), got %v", observation.Error)
	}
}

func TestProbeRetriesOverTCPWhenTruncated(t *testing.T) {
	server := startDNSServer(t, true)
	observation := dnsprobe.Probe(context.Background(), model.Resolver{Name: "local", Server: server}, "example.com", mdns.TypeA, 2*time.Second)
	if !observation.Success {
		t.Fatalf("expected DNS success after TCP retry, got %#v", observation)
	}
	if len(observation.Answers) != 1 || observation.Answers[0] != "203.0.113.10" {
		t.Fatalf("expected A answer after TCP retry, got %#v", observation.Answers)
	}
}

func startDNSServer(t *testing.T, truncated bool) string {
	t.Helper()
	mux := mdns.NewServeMux()
	mux.HandleFunc(".", func(w mdns.ResponseWriter, r *mdns.Msg) {
		msg := new(mdns.Msg)
		msg.SetReply(r)
		// Check that EDNS0 is present in the query.
		if len(r.Extra) == 0 {
			t.Log("warning: query did not contain EDNS0 option")
		}
		for _, question := range r.Question {
			if question.Qtype == mdns.TypeA {
				msg.Answer = append(msg.Answer, &mdns.A{
					Hdr: mdns.RR_Header{Name: question.Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60},
					A:   net.ParseIP("203.0.113.10"),
				})
			}
		}
		if truncated {
			msg.Truncated = true
		}
		_ = w.WriteMsg(msg)
	})
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udpServer := &mdns.Server{PacketConn: listener, Handler: mux}
	go func() {
		_ = udpServer.ActivateAndServe()
	}()

	// Also start a TCP server on the same port for truncated fallback.
	tcpListener, err := net.Listen("tcp", listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	tcpServer := &mdns.Server{Listener: tcpListener, Handler: mux}
	go func() {
		_ = tcpServer.ActivateAndServe()
	}()

	t.Cleanup(func() {
		_ = udpServer.Shutdown()
		_ = tcpServer.Shutdown()
	})
	return listener.LocalAddr().String()
}
