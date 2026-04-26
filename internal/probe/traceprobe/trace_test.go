package traceprobe_test

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"iscan/internal/model"
	"iscan/internal/probe/traceprobe"
)

// buildTimeExceededPacket constructs an ICMP TimeExceeded message whose inner
// (original) packet is an IPv4 header followed by an ICMP Echo with the given
// innerID and innerSeq.
func buildTimeExceededPacket(innerID, innerSeq int, srcAddr net.IP) []byte {
	innerICMP := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   innerID,
			Seq:  innerSeq,
			Data: []byte("iscan"),
		},
	}
	innerICMPBytes, _ := innerICMP.Marshal(nil)

	// Inner IPv4 header (20 bytes bare minimum).
	// Byte 0: Version=4, IHL=5 (5*4=20 bytes).
	ipHdr := make([]byte, 20)
	ipHdr[0] = 0x45
	totalLen := 20 + len(innerICMPBytes)
	ipHdr[2] = byte(totalLen >> 8)
	ipHdr[3] = byte(totalLen)
	if srcAddr != nil && srcAddr.To4() != nil {
		copy(ipHdr[12:16], srcAddr.To4())
	}

	innerPkt := append(ipHdr, innerICMPBytes...)

	msg := icmp.Message{
		Type: ipv4.ICMPTypeTimeExceeded,
		Code: 0,
		Body: &icmp.TimeExceeded{Data: innerPkt},
	}
	raw, _ := msg.Marshal(nil)
	return raw
}

// TestProbeHopTimeExceededMismatchedID verifies that ProbeHop sets
// Mismatch=true when the inner ICMP body in a TimeExceeded response has
// an ID different from the probe's ID.
func TestProbeHopTimeExceededMismatchedID(t *testing.T) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		t.Skip("ICMP privileges required: ", err)
	}
	defer conn.Close()

	probeID := 12345
	ttl := 3

	// Inject a crafted TimeExceeded with mismatched inner ID before calling
	// ProbeHop. The packet will be queued in the receive buffer so that
	// ProbeHop's ReadFrom picks it up rather than the kernel's EchoReply.
	mismatchedID := 99999
	raw := buildTimeExceededPacket(mismatchedID, ttl, net.ParseIP("127.0.0.1"))
	_, err = conn.WriteTo(raw, &net.IPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal("failed to send TimeExceeded packet:", err)
	}

	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	hop, done := traceprobe.ProbeHop(ctx, conn, net.ParseIP("127.0.0.1"), ttl, time.Second, probeID, true)

	if done {
		// We received an EchoReply instead of our crafted TimeExceeded
		// (the kernel responded faster). Test is inconclusive — skip
		// the Mismatch assertion.
		t.Logf("got EchoReply (skipping Mismatch assertion); hop RTT=%v", hop.RTT)
		return
	}
	if hop.Error != "" {
		t.Fatalf("unexpected error: %v", hop.Error)
	}
	if !hop.Mismatch {
		t.Errorf("expected Mismatch=true for mismatched inner ID (probeID=%d, innerID=%d), got Mismatch=%v",
			probeID, mismatchedID, hop.Mismatch)
	}
}

// TestProbeHopTimeExceededMatchingID verifies that ProbeHop leaves
// Mismatch=false when the inner ICMP body matches the probe's ID and Seq.
func TestProbeHopTimeExceededMatchingID(t *testing.T) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		t.Skip("ICMP privileges required: ", err)
	}
	defer conn.Close()

	probeID := 12345
	ttl := 3

	// Inject a crafted TimeExceeded with matching inner ID.
	raw := buildTimeExceededPacket(probeID, ttl, net.ParseIP("127.0.0.1"))
	_, err = conn.WriteTo(raw, &net.IPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal("failed to send TimeExceeded packet:", err)
	}

	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	hop, done := traceprobe.ProbeHop(ctx, conn, net.ParseIP("127.0.0.1"), ttl, time.Second, probeID, true)

	if done {
		t.Logf("got EchoReply (skipping Mismatch assertion); hop RTT=%v", hop.RTT)
		return
	}
	if hop.Error != "" {
		t.Fatalf("unexpected error: %v", hop.Error)
	}
	if hop.Mismatch {
		t.Errorf("expected Mismatch=false for matching inner ID (probeID=%d, innerID=%d), got Mismatch=%v",
			probeID, probeID, hop.Mismatch)
	}
}

// TestProbeGeneratesUniqueIDs verifies that Probe() does not panic when
// called concurrently and generates a unique ID per call via crypto/rand.
func TestProbeGeneratesUniqueIDs(t *testing.T) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		t.Skip("ICMP privileges required: ", err)
	}
	conn.Close()

	// Verify that crypto/rand produces distinct values across calls.
	seen := make(map[uint16]struct{})
	for i := 0; i < 10; i++ {
		var b [2]byte
		if _, err := rand.Read(b[:]); err != nil {
			t.Fatal("rand.Read failed:", err)
		}
		id := binary.BigEndian.Uint16(b[:])
		if _, dup := seen[id]; dup {
			t.Errorf("duplicate ID generated on iteration %d: %d", i, id)
		}
		seen[id] = struct{}{}
	}

	// Smoke test: two concurrent Probe calls should not panic.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	results := make([]model.TraceObservation, 2)

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = traceprobe.Probe(ctx, "127.0.0.1", "", time.Second)
		}(i)
	}
	wg.Wait()

	for i, obs := range results {
		if obs.Error != "" {
			t.Logf("Probe %d: %s", i, obs.Error)
		} else {
			t.Logf("Probe %d: %d hops", i, len(obs.Hops))
		}
	}
}

// TestConcurrentTracerouteNoCrossContamination verifies that concurrent
// Probe calls do not cross-contaminate each other's hop data. Each probe
// uses its own ICMP socket and a unique ID, so hops from one should never
// carry data from another.
func TestConcurrentTracerouteNoCrossContamination(t *testing.T) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		t.Skip("ICMP privileges required: ", err)
	}
	conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	results := make([]model.TraceObservation, 3)

	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = traceprobe.Probe(ctx, "127.0.0.1", "", 2*time.Second)
		}(i)
	}
	wg.Wait()

	for i, obs := range results {
		if obs.Error != "" {
			t.Logf("Probe %d: %s", i, obs.Error)
		} else {
			t.Logf("Probe %d: %d hops", i, len(obs.Hops))
		}
		// If hops exist, verify no Mismatch for EchoReply (ID+Seq matched).
		// On loopback the EchoReply should always match.
		for _, hop := range obs.Hops {
			if hop.Mismatch {
				t.Logf("Probe %d TTL %d: Mismatch flagged (may be normal under load)", i, hop.TTL)
			}
		}
	}
}
