package httpprobe

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptrace"
	"time"

	"iscan/internal/model"
)

func Probe(url string, timeout time.Duration) model.HTTPObservation {
	observation := model.HTTPObservation{URL: url}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	var connectStart, tlsStart, requestStart time.Time
	trace := &httptrace.ClientTrace{
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

	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace), http.MethodGet, url, nil)
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
	defer resp.Body.Close()
	observation.StatusCode = resp.StatusCode
	observation.Success = resp.StatusCode >= 200 && resp.StatusCode < 500
	return observation
}
