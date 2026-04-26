package dnsprobe_test

import (
	"net"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"iscan/internal/model"
	"iscan/internal/probe/dnsprobe"
)

func TestProbeARecordsFromResolver(t *testing.T) {
	server := startDNSServer(t)
	observation := dnsprobe.Probe(model.Resolver{Name: "local", Server: server}, "example.com", mdns.TypeA, 2*time.Second)

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

func startDNSServer(t *testing.T) string {
	t.Helper()
	mux := mdns.NewServeMux()
	mux.HandleFunc(".", func(w mdns.ResponseWriter, r *mdns.Msg) {
		msg := new(mdns.Msg)
		msg.SetReply(r)
		for _, question := range r.Question {
			if question.Qtype == mdns.TypeA {
				msg.Answer = append(msg.Answer, &mdns.A{
					Hdr: mdns.RR_Header{Name: question.Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60},
					A:   net.ParseIP("203.0.113.10"),
				})
			}
		}
		_ = w.WriteMsg(msg)
	})
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &mdns.Server{PacketConn: listener, Handler: mux}
	go func() {
		_ = server.ActivateAndServe()
	}()
	t.Cleanup(func() {
		_ = server.Shutdown()
	})
	return listener.LocalAddr().String()
}
