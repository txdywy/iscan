package tcp

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"iscan/internal/model"
)

// ProbeNetwork is like Probe but allows specifying the network ("tcp", "tcp4", "tcp6").
func ProbeNetwork(ctx context.Context, host string, port int, network string, timeout time.Duration) model.TCPObservation {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	start := time.Now()
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, network, address)
	latency := time.Since(start)
	if err != nil {
		return model.TCPObservation{
			Address:   address,
			Host:      host,
			Port:      port,
			Latency:   latency,
			Success:   false,
			Error:     err.Error(),
			ErrorKind: classifyError(err),
		}
	}
	_ = conn.Close()
	return model.TCPObservation{
		Address: address,
		Host:    host,
		Port:    port,
		Latency: latency,
		Success: true,
	}
}

func Probe(ctx context.Context, host string, port int, timeout time.Duration) model.TCPObservation {
	return ProbeNetwork(ctx, host, port, "tcp", timeout)
}

func classifyError(err error) string {
	if errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err) {
		return "timeout"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "refused"
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return "reset"
	}
	if errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) {
		return "unreachable"
	}
	lower := strings.ToLower(err.Error())
	switch {
	case strings.Contains(lower, "connection refused"):
		return "refused"
	case strings.Contains(lower, "reset"):
		return "reset"
	case strings.Contains(lower, "timeout"):
		return "timeout"
	case strings.Contains(lower, "no route"), strings.Contains(lower, "network is unreachable"):
		return "unreachable"
	default:
		return "other"
	}
}
