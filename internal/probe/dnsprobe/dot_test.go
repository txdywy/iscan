package dnsprobe_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"iscan/internal/model"
	"iscan/internal/probe/dnsprobe"
)

// startDoTServer starts a DNS-over-TLS server on a random port and returns its address.
func startDoTServer(t *testing.T) string {
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

	// Generate a self-signed TLS certificate.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "dot-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		DNSNames:     []string{"localhost"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatal(err)
	}

	server := &mdns.Server{Listener: listener, Handler: mux}
	go func() {
		_ = server.ActivateAndServe()
	}()

	t.Cleanup(func() {
		_ = server.Shutdown()
	})

	return listener.Addr().String()
}

func TestProbeDoT(t *testing.T) {
	addr := startDoTServer(t)
	observation := dnsprobe.Probe(context.Background(), model.Resolver{Name: "local", Server: addr, Transport: "tcp-tls"}, "example.com", mdns.TypeA, 2*time.Second)

	if !observation.Success {
		t.Fatalf("expected DNS success via DoT, got %#v", observation)
	}
	if observation.RCode != "NOERROR" {
		t.Fatalf("expected NOERROR, got %#v", observation)
	}
	if len(observation.Answers) != 1 || observation.Answers[0] != "203.0.113.10" {
		t.Fatalf("expected A answer 203.0.113.10, got %#v", observation.Answers)
	}
}

func TestProbeDoTDefaultPort(t *testing.T) {
	// No port specified; dotQuery should append :853. Since nothing is
	// listening on port 853, this should fail with a connection error.
	observation := dnsprobe.Probe(context.Background(), model.Resolver{Name: "local", Server: "127.0.0.1", Transport: "tcp-tls"}, "example.com", mdns.TypeA, 2*time.Second)

	if observation.Success {
		t.Fatal("expected DNS failure via DoT to default port 853 (no server there)")
	}
	if !strings.Contains(observation.Error, "dot:") {
		t.Fatalf("expected error with 'dot:' prefix, got %v", observation.Error)
	}
}
