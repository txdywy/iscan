package quicprobe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net"
	"strconv"
	"time"

	"github.com/quic-go/quic-go"

	"iscan/internal/model"
)

func Probe(ctx context.Context, host string, port int, sni string, alpn []string, timeout time.Duration) model.QUICObservation {
	if len(alpn) == 0 {
		alpn = []string{"h3"}
	}
	address := net.JoinHostPort(host, strconv.Itoa(port))
	start := time.Now()

	tlsConf := &tls.Config{
		ServerName:         sni,
		NextProtos:         alpn,
		InsecureSkipVerify: true,
	}
	quicConf := &quic.Config{
		MaxIdleTimeout:       timeout,
		HandshakeIdleTimeout: timeout,
	}

	conn, err := quic.DialAddr(ctx, address, tlsConf, quicConf)
	latency := time.Since(start)
	if err != nil {
		return model.QUICObservation{
			Address: address,
			SNI:     sni,
			Latency: latency,
			Success: false,
			Error:   err.Error(),
		}
	}
	defer conn.CloseWithError(0, "")

	state := conn.ConnectionState().TLS
	observation := model.QUICObservation{
		Address: address,
		SNI:     sni,
		Version: quicVersionName(conn.ConnectionState().Version),
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

func quicVersionName(v quic.Version) string {
	switch v {
	case quic.Version1:
		return "QUICv1"
	case quic.Version2:
		return "QUICv2"
	default:
		return v.String()
	}
}
