package dnsprobe_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"iscan/internal/model"
	"iscan/internal/probe/dnsprobe"
)

func TestProbeDoH(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("content-type") != "application/dns-message" {
			http.Error(w, "bad content type", http.StatusBadRequest)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		query := new(mdns.Msg)
		if err := query.Unpack(body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		reply := new(mdns.Msg)
		reply.SetReply(query)
		for _, question := range query.Question {
			if question.Qtype == mdns.TypeA {
				reply.Answer = append(reply.Answer, &mdns.A{
					Hdr: mdns.RR_Header{Name: question.Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60},
					A:   net.ParseIP("203.0.113.10"),
				})
			}
		}

		packed, err := reply.Pack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("content-type", "application/dns-message")
		_, _ = w.Write(packed)
	}))
	t.Cleanup(server.Close)

	// Extract host:port from the server URL (https://host:port)
	host := strings.TrimPrefix(server.URL, "https://")

	observation := dnsprobe.Probe(context.Background(), model.Resolver{Name: "local", Server: host, Transport: "https"}, "example.com", mdns.TypeA, 2*time.Second)

	if !observation.Success {
		t.Fatalf("expected DNS success via DoH, got %#v", observation)
	}
	if observation.RCode != "NOERROR" {
		t.Fatalf("expected NOERROR, got %#v", observation)
	}
	if len(observation.Answers) != 1 || observation.Answers[0] != "203.0.113.10" {
		t.Fatalf("expected A answer 203.0.113.10, got %#v", observation.Answers)
	}
}

func TestProbeDoHError(t *testing.T) {
	observation := dnsprobe.Probe(context.Background(), model.Resolver{Name: "bad", Server: "127.0.0.1:1", Transport: "https"}, "example.com", mdns.TypeA, 100*time.Millisecond)

	if observation.Success {
		t.Fatal("expected DNS failure via DoH, got success")
	}
	if observation.Error == "" || !strings.Contains(observation.Error, "doh:") {
		t.Fatalf("expected error with 'doh:' prefix, got %v", observation.Error)
	}
}
