package dnsprobe

import (
	"context"
	"errors"
	"net"
	"time"

	mdns "github.com/miekg/dns"

	"iscan/internal/model"
)

// Probe dispatches a DNS query to the appropriate transport based on
// resolver.Transport. Default ("", "udp", "tcp") routes to udpQuery.
// "https" routes to dohQuery, "tcp-tls" routes to dotQuery, and
// "system" routes to systemResolverQuery.
func Probe(ctx context.Context, resolver model.Resolver, domain string, qtype uint16, timeout time.Duration) model.DNSObservation {
	switch resolver.Transport {
	case "https":
		return dohQuery(ctx, resolver, domain, qtype, timeout)
	case "tcp-tls":
		return dotQuery(ctx, resolver, domain, qtype, timeout)
	case "system":
		return systemResolverQuery(ctx, resolver, domain, qtype, timeout)
	default: // "", "udp", "tcp"
		return udpQuery(ctx, resolver, domain, qtype, timeout)
	}
}

// udpQuery performs a DNS query over UDP with TCP truncated fallback.
func udpQuery(ctx context.Context, resolver model.Resolver, domain string, qtype uint16, timeout time.Duration) model.DNSObservation {
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
	// If truncated, retry over TCP with updated latency.
	if resp.Truncated {
		tcpStart := time.Now()
		tcpMsg := new(mdns.Msg)
		tcpMsg.SetQuestion(query, qtype)
		tcpMsg.SetEdns0(1232, false)
		tcpClient := &mdns.Client{Net: "tcp", Timeout: timeout}
		resp, _, err = tcpClient.ExchangeContext(ctx, tcpMsg, server)
		observation.Latency = time.Since(tcpStart)
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
		} else {
			observation.Success = false
			observation.Error = "truncated+tcp_fallback_failed: " + err.Error()
		}
	}
	return observation
}

// systemResolverQuery performs a DNS lookup using Go's net.DefaultResolver.
// Maps net.DNSError types to DNS RCODEs for consistent error reporting.
func systemResolverQuery(ctx context.Context, resolver model.Resolver, domain string, qtype uint16, timeout time.Duration) model.DNSObservation {
	obs := model.DNSObservation{Resolver: resolver.Name, Query: domain, Type: mdns.TypeToString[qtype]}
	start := time.Now()
	addrs, err := net.DefaultResolver.LookupHost(ctx, domain)
	obs.Latency = time.Since(start)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) {
			if dnsErr.IsNotFound {
				obs.RCode = "NXDOMAIN"
			} else if dnsErr.IsTemporary {
				obs.RCode = "SERVFAIL"
			}
		}
		obs.Error = err.Error()
		return obs
	}
	obs.RCode = "NOERROR"
	obs.Success = true
	obs.Answers = addrs
	return obs
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
