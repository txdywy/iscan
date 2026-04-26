package httpprobe

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"time"

	"iscan/internal/model"
)

func Probe(ctx context.Context, url string, timeout time.Duration) model.HTTPObservation {
	return probe(ctx, url, "", timeout)
}

func ProbeWithAddress(ctx context.Context, url string, dialAddress string, timeout time.Duration) model.HTTPObservation {
	return probe(ctx, url, dialAddress, timeout)
}

func probe(ctx context.Context, url string, dialAddress string, timeout time.Duration) model.HTTPObservation {
	observation := model.HTTPObservation{URL: url, DialAddress: dialAddress}
	dialer := net.Dialer{Timeout: timeout}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	if dialAddress != "" {
		transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, dialAddress)
		}
	}
	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var dnsStart, connectStart, tlsStart, requestStart time.Time
	trace := &httptrace.ClientTrace{
		DNSStart: func(_ httptrace.DNSStartInfo) {
			dnsStart = time.Now()
		},
		DNSDone: func(_ httptrace.DNSDoneInfo) {
			if !dnsStart.IsZero() {
				observation.DNSStartLatency = time.Since(dnsStart)
			}
		},
		ConnectStart: func(_, _ string) {
			connectStart = time.Now()
		},
		ConnectDone: func(_, _ string, _ error) {
			if !connectStart.IsZero() {
				observation.ConnectLatency = time.Since(connectStart)
			}
		},
		TLSHandshakeStart: func() {
			tlsStart = time.Now()
		},
		TLSHandshakeDone: func(tls.ConnectionState, error) {
			if !tlsStart.IsZero() {
				observation.TLSHandshakeLatency = time.Since(tlsStart)
			}
		},
		GotFirstResponseByte: func() {
			observation.FirstByteLatency = time.Since(requestStart)
		},
	}

	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, url, nil)
	if err != nil {
		observation.Error = err.Error()
		return observation
	}
	requestStart = time.Now()
	resp, err := client.Do(req)
	observation.Latency = time.Since(requestStart)
	if err != nil {
		observation.Error = err.Error()
		return observation
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	observation.StatusCode = resp.StatusCode
	observation.Success = resp.StatusCode >= 200 && resp.StatusCode < 400
	return observation
}
