package traceprobe

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"strings"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"iscan/internal/model"
)

func Probe(ctx context.Context, target string, addressFamily string, timeout time.Duration) (observation model.TraceObservation) {
	start := time.Now()
	observation = model.TraceObservation{Target: target}
	defer func() {
		observation.Latency = time.Since(start)
	}()
	ips, err := net.LookupIP(target)
	if err != nil {
		observation.Error = err.Error()
		return observation
	}
	var ip net.IP
	// Select IP based on AddressFamily preference.
	for _, candidate := range ips {
		if addressFamily == "ipv6" && candidate.To4() == nil {
			ip = candidate
			break
		}
		if addressFamily == "ipv4" && candidate.To4() != nil {
			ip = candidate
			break
		}
	}
	if ip == nil {
		// Fallback for empty AddressFamily: prefer IPv4, then any.
		for _, candidate := range ips {
			if candidate.To4() != nil {
				ip = candidate
				break
			}
		}
		if ip == nil && len(ips) > 0 {
			ip = ips[0] // IPv6 fallback
		}
	}
	if ip == nil {
		observation.Error = "no IP address for trace"
		return observation
	}
	isIPv4 := ip.To4() != nil

	var conn *icmp.PacketConn
	if isIPv4 {
		conn, err = icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	} else {
		conn, err = icmp.ListenPacket("ip6:icmp", "::")
	}
	if err != nil {
		observation.Error = err.Error()
		return observation
	}
	defer func() {
		_ = conn.Close()
	}()
	var packetConn4 *ipv4.PacketConn
	var packetConn6 *ipv6.PacketConn
	if isIPv4 {
		packetConn4 = ipv4.NewPacketConn(conn)
	} else {
		packetConn6 = ipv6.NewPacketConn(conn)
	}

	var idBytes [2]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		observation.Error = "icmp id generation failed: " + err.Error()
		return observation
	}
	probeID := int(binary.BigEndian.Uint16(idBytes[:]))

	var consecutiveEmpty int
	for ttl := 1; ttl <= 30; ttl++ {
		select {
		case <-ctx.Done():
			observation.Error = ctx.Err().Error()
			return observation
		default:
		}
		var setErr error
		if isIPv4 {
			setErr = packetConn4.SetTTL(ttl)
		} else {
			setErr = packetConn6.SetHopLimit(ttl)
		}
		if setErr != nil {
			observation.Error = setErr.Error()
			return observation
		}
		hop, done := ProbeHop(ctx, conn, ip, ttl, timeout, probeID, isIPv4)
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

func ProbeHop(ctx context.Context, conn *icmp.PacketConn, ip net.IP, ttl int, timeout time.Duration, probeID int, isIPv4 bool) (model.TraceHop, bool) {
	select {
	case <-ctx.Done():
		return model.TraceHop{TTL: ttl, Error: ctx.Err().Error()}, false
	default:
	}
	// Cap per-hop timeout so a single stuck hop doesn't consume the whole budget.
	if timeout > 2*time.Second {
		timeout = 2 * time.Second
	}
	var msgType icmp.Type
	if isIPv4 {
		msgType = ipv4.ICMPTypeEcho
	} else {
		msgType = ipv6.ICMPTypeEchoRequest
	}
	message := icmp.Message{
		Type: msgType,
		Code: 0,
		Body: &icmp.Echo{
			ID:   probeID,
			Seq:  ttl,
			Data: []byte("iscan"),
		},
	}
	bytes, err := message.Marshal(nil)
	if err != nil {
		return model.TraceHop{TTL: ttl, Error: err.Error()}, false
	}
	// Independent per-hop deadline; each iteration starts a fresh timer.
	_ = conn.SetDeadline(time.Now().Add(timeout))
	sent := time.Now()
	if _, err := conn.WriteTo(bytes, &net.IPAddr{IP: ip}); err != nil {
		return model.TraceHop{TTL: ttl, Error: err.Error()}, false
	}
	reply := make([]byte, 1500)
	n, peer, err := conn.ReadFrom(reply)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return model.TraceHop{TTL: ttl, Error: "read timeout"}, false
		}
		return model.TraceHop{TTL: ttl, Error: err.Error()}, false
	}
	proto := 1 // ICMP for IPv4
	if !isIPv4 {
		proto = 58 // ICMPv6 for IPv6
	}
	parsed, err := icmp.ParseMessage(proto, reply[:n])
	if err != nil {
		return model.TraceHop{TTL: ttl, Address: peer.String(), Error: err.Error()}, false
	}
	// Validate ICMP body matches our Echo request (ID + Seq).
	switch body := parsed.Body.(type) {
	case *icmp.Echo:
		if body.ID != probeID || body.Seq != ttl {
			// Mismatch — likely from a concurrent probe or unrelated traffic.
			return model.TraceHop{TTL: ttl, Address: peer.String(), RTT: time.Since(sent)}, false
		}
	case *icmp.TimeExceeded:
		// Time Exceeded means we got a hop but haven't reached the target.
		// Validate the inner ICMP body to detect cross-contamination.
		hop := model.TraceHop{
			TTL:     ttl,
			Address: peer.String(),
			RTT:     time.Since(sent),
		}
		if body.Data != nil && len(body.Data) > 0 {
			// Inner packet: [inner IP header (20+ bytes)] + [inner ICMP message header (8 bytes)]
			innerIHL := int(body.Data[0]&0x0f) * 4
			if len(body.Data) >= innerIHL+8 {
				innerID := int(binary.BigEndian.Uint16(body.Data[innerIHL+4 : innerIHL+6]))
				innerSeq := int(binary.BigEndian.Uint16(body.Data[innerIHL+6 : innerIHL+8]))
				hop.Mismatch = (innerID != probeID || innerSeq != ttl)
			}
			// If truncated by router, skip validation — accept without Mismatch.
		}
		return hop, false
	}
	return model.TraceHop{
		TTL:     ttl,
		Address: peer.String(),
		RTT:     time.Since(sent),
	}, func() bool {
		if isIPv4 {
			return parsed.Type == ipv4.ICMPTypeEchoReply
		}
		return parsed.Type == ipv6.ICMPTypeEchoReply
	}()
}
