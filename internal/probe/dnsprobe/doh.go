package dnsprobe

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"time"

	mdns "github.com/miekg/dns"

	"iscan/internal/model"
)

// dohQuery performs a DNS query over HTTPS (DoH) by sending DNS wire-format
// messages via HTTP POST to https://{resolver.Server}/dns-query.
func dohQuery(ctx context.Context, resolver model.Resolver, domain string, qtype uint16, timeout time.Duration) model.DNSObservation {
	obs := model.DNSObservation{
		Resolver: resolver.Name,
		Query:    mdns.Fqdn(domain),
		Type:     mdns.TypeToString[qtype],
	}

	msg := new(mdns.Msg)
	msg.SetQuestion(mdns.Fqdn(domain), qtype)
	msg.SetEdns0(1232, false)

	packed, err := msg.Pack()
	if err != nil {
		obs.Error = "doh: " + err.Error()
		return obs
	}

	dohURL := "https://" + resolver.Server + "/dns-query"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, dohURL, bytes.NewReader(packed))
	if err != nil {
		obs.Error = "doh: " + err.Error()
		return obs
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	start := time.Now()
	resp, err := client.Do(req)
	obs.Latency = time.Since(start)
	if err != nil {
		obs.Error = "doh: " + err.Error()
		return obs
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		obs.Error = "doh: " + err.Error()
		return obs
	}

	dnsResp := new(mdns.Msg)
	if err := dnsResp.Unpack(body); err != nil {
		obs.Error = "doh: " + err.Error()
		return obs
	}

	obs.RCode = mdns.RcodeToString[dnsResp.Rcode]
	obs.Success = dnsResp.Rcode == mdns.RcodeSuccess

	for _, answer := range dnsResp.Answer {
		switch rr := answer.(type) {
		case *mdns.A:
			obs.Answers = append(obs.Answers, rr.A.String())
		case *mdns.AAAA:
			obs.Answers = append(obs.Answers, rr.AAAA.String())
		case *mdns.CNAME:
			obs.CNAMEs = append(obs.CNAMEs, rr.Target)
		}
	}

	return obs
}
