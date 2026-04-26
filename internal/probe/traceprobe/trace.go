package traceprobe

import (
	"context"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"iscan/internal/model"
)

func Probe(ctx context.Context, target string, timeout time.Duration) (observation model.TraceObservation) {
	start := time.Now()
	observation = model.TraceObservation{Target: target}
	defer func() {
		observation.Latency = time.Since(start)
	}()
	ips, err := net.LookupIP(target)
	if err != nil {
		observation.Error = err.Error()
		observation.Latency = time.Since(start)
		return observation
	}
	var ip net.IP
	for _, candidate := range ips {
		if candidate.To4() != nil {
			ip = candidate
			break
		}
	}
	if ip == nil {
		observation.Error = "no IPv4 address for trace"
		observation.Latency = time.Since(start)
		return observation
	}

	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		observation.Error = err.Error()
		observation.Latency = time.Since(start)
		return observation
	}
	defer conn.Close()
	packetConn := ipv4.NewPacketConn(conn)

	var consecutiveEmpty int
	for ttl := 1; ttl <= 30; ttl++ {
		select {
		case <-ctx.Done():
			observation.Error = ctx.Err().Error()
			return observation
		default:
		}
		if err := packetConn.SetTTL(ttl); err != nil {
			observation.Error = err.Error()
			observation.Latency = time.Since(start)
			return observation
		}
		hop, done := probeHop(conn, ip, ttl, timeout)
		observation.Hops = append(observation.Hops, hop)
		if !done && isReadTimeout(hop.Error) {
			consecutiveEmpty++
			if consecutiveEmpty >= 3 {
				break
			}
		} else {
			consecutiveEmpty = 0
		}
		if done {
			observation.Success = true
			break
		}
	}
	return observation
}

func isReadTimeout(errStr string) bool {
	return strings.Contains(strings.ToLower(errStr), "timeout")
}

func probeHop(conn *icmp.PacketConn, ip net.IP, ttl int, timeout time.Duration) (model.TraceHop, bool) {
	message := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  ttl,
			Data: []byte("iscan"),
		},
	}
	bytes, err := message.Marshal(nil)
	if err != nil {
		return model.TraceHop{TTL: ttl, Error: err.Error()}, false
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	sent := time.Now()
	if _, err := conn.WriteTo(bytes, &net.IPAddr{IP: ip}); err != nil {
		return model.TraceHop{TTL: ttl, Error: err.Error()}, false
	}
	reply := make([]byte, 1500)
	n, peer, err := conn.ReadFrom(reply)
	if err != nil {
		return model.TraceHop{TTL: ttl, Error: err.Error()}, false
	}
	parsed, err := icmp.ParseMessage(1, reply[:n])
	if err != nil {
		return model.TraceHop{TTL: ttl, Address: peer.String(), Error: err.Error()}, false
	}
	return model.TraceHop{
		TTL:     ttl,
		Address: peer.String(),
		RTT:     time.Since(sent),
	}, parsed.Type == ipv4.ICMPTypeEchoReply
}
