package dnsprobe

import (
	"context"
	"crypto/tls"
	"time"

	mdns "github.com/miekg/dns"

	"iscan/internal/model"
)

// dotQuery performs a DNS query over TLS (DoT) using miekg/dns Client
// configured with tcp-tls and InsecureSkipVerify. Defaults to port 853
// if no port is specified in resolver.Server.
func dotQuery(ctx context.Context, resolver model.Resolver, domain string, qtype uint16, timeout time.Duration) model.DNSObservation {
	obs := model.DNSObservation{
		Resolver: resolver.Name,
		Query:    mdns.Fqdn(domain),
		Type:     mdns.TypeToString[qtype],
	}

	msg := new(mdns.Msg)
	msg.SetQuestion(mdns.Fqdn(domain), qtype)
	msg.SetEdns0(1232, false)

	server := resolver.Server
	if server != "" && missingPort(server) {
		server = server + ":853"
	}

	client := &mdns.Client{
		Net:     "tcp-tls",
		Timeout: timeout,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	start := time.Now()
	resp, _, err := client.ExchangeContext(ctx, msg, server)
	obs.Latency = time.Since(start)
	if err != nil {
		obs.Error = "dot: " + err.Error()
		return obs
	}

	obs.RCode = mdns.RcodeToString[resp.Rcode]
	obs.Success = resp.Rcode == mdns.RcodeSuccess

	for _, answer := range resp.Answer {
		switch rr := answer.(type) {
		case *mdns.A:
			obs.Answers = append(obs.Answers, rr.A.String())
		case *mdns.AAAA:
			obs.Answers = append(obs.Answers, rr.AAAA.String())
		case *mdns.CNAME:
			obs.CNAMEs = append(obs.CNAMEs, rr.Target)
		}
	}

	// If truncated, retry with the same TCP-TLS client (TCP handles large responses).
	if resp.Truncated {
		tcpStart := time.Now()
		retryMsg := new(mdns.Msg)
		retryMsg.SetQuestion(mdns.Fqdn(domain), qtype)
		retryMsg.SetEdns0(1232, false)
		resp, _, err = client.ExchangeContext(ctx, retryMsg, server)
		obs.Latency = time.Since(tcpStart)
		if err == nil {
			obs.RCode = mdns.RcodeToString[resp.Rcode]
			obs.Success = resp.Rcode == mdns.RcodeSuccess
			obs.Answers = obs.Answers[:0]
			obs.CNAMEs = obs.CNAMEs[:0]
			for _, answer := range resp.Answer {
				switch rr := answer.(type) {
				case *mdns.A:
					obs.Answers = append(obs.Answers, rr.A.String())
				case *mdns.AAAA:
					obs.Answers = append(obs.Answers, rr.AAAA.String())
				case *mdns.CNAME:
					obs.CNAMEs = append(obs.CNAMEs, rr.Target)
				}
			}
		} else {
			obs.Error = "dot_truncated_retry_failed: " + err.Error()
		}
	}

	return obs
}
