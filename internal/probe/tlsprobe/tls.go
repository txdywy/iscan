package tlsprobe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net"
	"strconv"
	"time"

	"iscan/internal/model"
)

func Probe(ctx context.Context, host string, port int, sni string, nextProtos []string, timeout time.Duration, insecureSkipVerify bool) model.TLSObservation {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	start := time.Now()
	dialer := net.Dialer{Timeout: timeout}
	cfg := &tls.Config{
		ServerName:         sni,
		NextProtos:         nextProtos,
		InsecureSkipVerify: insecureSkipVerify,
	}
	tlsDialer := &tls.Dialer{NetDialer: &dialer, Config: cfg}
	conn, err := tlsDialer.DialContext(ctx, "tcp", address)
	latency := time.Since(start)
	if err != nil {
		return model.TLSObservation{
			Address: address,
			SNI:     sni,
			Latency: latency,
			Success: false,
			Error:   err.Error(),
		}
	}
	defer func() {
		_ = conn.Close()
	}()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return model.TLSObservation{
			Address: address,
			SNI:     sni,
			Latency: latency,
			Success: false,
			Error:   "connection is not a tls.Conn",
		}
	}
	state := tlsConn.ConnectionState()
	observation := model.TLSObservation{
		Address: address,
		SNI:     sni,
		Version: tlsVersion(state.Version),
		ALPN:    state.NegotiatedProtocol,
		Latency: latency,
		Success: true,
	}
	if len(state.PeerCertificates) > 0 {
		sum := sha256.Sum256(state.PeerCertificates[0].Raw)
		observation.CertSHA256 = hex.EncodeToString(sum[:])
	}
	return observation
}

func tlsVersion(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return "unknown"
	}
}
