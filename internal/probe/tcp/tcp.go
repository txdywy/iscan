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

func Probe(host string, port int, timeout time.Duration) model.TCPObservation {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	start := time.Now()
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(context.Background(), "tcp", address)
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
