package tlsprobe

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net"
	"strconv"
	"time"

	"iscan/internal/model"
)

func Probe(host string, port int, sni string, nextProtos []string, timeout time.Duration, insecureSkipVerify bool) model.TLSObservation {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	start := time.Now()
	dialer := net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(&dialer, "tcp", address, &tls.Config{
		ServerName:         sni,
		NextProtos:         nextProtos,
		InsecureSkipVerify: insecureSkipVerify,
	})
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
	defer conn.Close()

	state := conn.ConnectionState()
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
