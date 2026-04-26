package icmpping

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"iscan/internal/model"
)

// Probe sends a single ICMP Echo request to target and returns a PingObservation.
// Permission errors are returned in observation.Error (never panics or crashes).
func Probe(ctx context.Context, target string, timeout time.Duration) (observation model.PingObservation) {
	start := time.Now()
	observation = model.PingObservation{Target: target}
	defer func() {
		observation.Latency = time.Since(start)
	}()

	// Resolve target to IPv4 address (ping requires raw IP; IPv6 handled separately in Phase 3 Plan 03)
	ips, err := net.LookupIP(target)
	if err != nil {
		observation.Error = err.Error()
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
		observation.Error = "no IPv4 address for ping"
		return observation
	}
	observation.Address = ip.String()

	// Open raw ICMP socket
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		observation.Error = err.Error()
		return observation
	}
	defer func() { _ = conn.Close() }()

	// Generate random probe ID (same pattern as traceroute)
	var idBytes [2]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		observation.Error = "icmp id generation failed: " + err.Error()
		return observation
	}
	probeID := int(binary.BigEndian.Uint16(idBytes[:]))

	// Build ICMP Echo request (TTL default 64, single shot)
	message := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   probeID,
			Seq:  1,
			Data: []byte("iscan"),
		},
	}
	bytes, err := message.Marshal(nil)
	if err != nil {
		observation.Error = err.Error()
		return observation
	}

	// Set deadline and send
	_ = conn.SetDeadline(time.Now().Add(timeout))
	sent := time.Now()
	if _, err := conn.WriteTo(bytes, &net.IPAddr{IP: ip}); err != nil {
		observation.Error = err.Error()
		return observation
	}

	// Read reply
	reply := make([]byte, 1500)
	n, peer, err := conn.ReadFrom(reply)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			observation.Error = "read timeout"
			return observation
		}
		observation.Error = err.Error()
		return observation
	}

	// Parse reply
	parsed, err := icmp.ParseMessage(1, reply[:n])
	if err != nil {
		observation.Address = peer.String()
		observation.Error = err.Error()
		return observation
	}

	// Extract TTL from IP header via ipv4.ParseHeader
	ttl := 0
	if header, err := ipv4.ParseHeader(reply[:n]); err == nil {
		ttl = header.TTL
	}

	switch body := parsed.Body.(type) {
	case *icmp.Echo:
		if body.ID == probeID {
			observation.Address = peer.String()
			observation.RTT = time.Since(sent)
			observation.TTL = ttl
			observation.Success = true
		}
	}
	return observation
}
