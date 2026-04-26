package dnsprobe

import (
	"context"
	"errors"
	"net"
	"time"

	mdns "github.com/miekg/dns"

	"iscan/internal/model"
)

func Probe(ctx context.Context, resolver model.Resolver, domain string, qtype uint16, timeout time.Duration) model.DNSObservation {
	query := mdns.Fqdn(domain)
	observation := model.DNSObservation{
		Resolver: resolver.Name,
		Query:    query,
		Type:     mdns.TypeToString[qtype],
	}
	msg := new(mdns.Msg)
	msg.SetQuestion(query, qtype)
	msg.SetEdns0(1232, false)
	client := &mdns.Client{Net: "udp", Timeout: timeout}
	server := resolver.Server
	if server != "" && missingPort(server) {
		server = net.JoinHostPort(server, "53")
	}

	start := time.Now()
	resp, _, err := client.ExchangeContext(ctx, msg, server)
	observation.Latency = time.Since(start)
	if err != nil {
		observation.Error = err.Error()
		return observation
	}
	observation.RCode = mdns.RcodeToString[resp.Rcode]
	observation.Success = resp.Rcode == mdns.RcodeSuccess
	for _, answer := range resp.Answer {
		switch rr := answer.(type) {
		case *mdns.A:
			observation.Answers = append(observation.Answers, rr.A.String())
		case *mdns.AAAA:
			observation.Answers = append(observation.Answers, rr.AAAA.String())
		case *mdns.CNAME:
			observation.CNAMEs = append(observation.CNAMEs, rr.Target)
		}
	}
	// If truncated, retry over TCP.
	if resp.Truncated {
		tcpClient := &mdns.Client{Net: "tcp", Timeout: timeout}
		resp, _, err = tcpClient.ExchangeContext(ctx, msg, server)
		if err == nil {
			observation.RCode = mdns.RcodeToString[resp.Rcode]
			observation.Success = resp.Rcode == mdns.RcodeSuccess
			observation.Answers = observation.Answers[:0]
			observation.CNAMEs = observation.CNAMEs[:0]
			for _, answer := range resp.Answer {
				switch rr := answer.(type) {
				case *mdns.A:
					observation.Answers = append(observation.Answers, rr.A.String())
				case *mdns.AAAA:
					observation.Answers = append(observation.Answers, rr.AAAA.String())
				case *mdns.CNAME:
					observation.CNAMEs = append(observation.CNAMEs, rr.Target)
				}
			}
		}
	}
	return observation
}

func missingPort(server string) bool {
	_, _, err := net.SplitHostPort(server)
	if err == nil {
		return false
	}
	var addrErr *net.AddrError
	if errors.As(err, &addrErr) {
		return addrErr.Err == "missing port in address"
	}
	return false
}
