---
phase: 03-missing-table-stakes
reviewed: 2026-04-26T16:00:00Z
depth: deep
files_reviewed: 23
files_reviewed_list:
  - cmd/iscan/main.go
  - internal/model/model.go
  - internal/model/errors.go
  - internal/model/errors_test.go
  - internal/probe/dnsprobe/dns.go
  - internal/probe/dnsprobe/dns_test.go
  - internal/probe/dnsprobe/adapter.go
  - internal/probe/httpprobe/http.go
  - internal/probe/httpprobe/adapter.go
  - internal/probe/icmpping/icmp.go
  - internal/probe/icmpping/adapter.go
  - internal/probe/icmpping/icmpping_test.go
  - internal/probe/quicprobe/quic.go
  - internal/probe/quicprobe/adapter.go
  - internal/probe/tcp/tcp.go
  - internal/probe/tcp/adapter.go
  - internal/probe/tlsprobe/tls.go
  - internal/probe/tlsprobe/adapter.go
  - internal/probe/traceprobe/trace.go
  - internal/probe/traceprobe/adapter.go
  - internal/probe/traceprobe/trace_test.go
  - internal/scanner/scanner.go
  - internal/scanner/scanner_test.go
  - internal/targets/targets.go
  - internal/targets/targets_test.go
  - internal/report/report.go
  - internal/classifier/classifier.go
  - internal/profile/profile.go
  - internal/recommend/recommend.go
findings:
  critical: 2
  warning: 5
  info: 4
  total: 11
status: issues_found
---

# Phase 3: Code Review Report (Missing Table Stakes)

**Reviewed:** 2026-04-26T16:00:00Z
**Depth:** Deep (cross-file call chains traced)
**Files Reviewed:** 23
**Status:** Issues Found

## Summary

This phase added three capabilities: an ICMP Ping probe (`internal/probe/icmpping/`), custom target sets with a `FileSource` JSON loader (`internal/targets/`), and IPv6 address-family support across all probes (DNS dual-stack, TCP/TLS/HTTP bracketing, ICMPv6 traceroute). The code is generally well-structured and the integration points are clean. However, there are two BLOCKER bugs that render specific features non-functional, along with several WARNING-level issues.

**BLOCKER (2):**
- The traceroute's per-hop socket deadline is always set to `time.Now()` because the adapter passes `timeout=0` to `Probe()`. Every per-hop ReadFrom immediately times out, producing 3 consecutive empty hops and stopping. The traceroute feature is effectively broken.
- The ICMPv6 TimeExceeded inner-body parsing always assumes an IPv4 header format (`body.Data[0]&0x0f * 4`). For IPv6, this computation gives offset 0, reading the IPv6 payload length as the inner ICMP Echo ID -- completely wrong. The Mismatch detection for ICMPv6 traceroute is incorrect.

**WARNING (5):**
- ICMP Ping probe ignores the `ctx` parameter entirely (no `select` on `ctx.Done()`). Context cancellation (e.g., Ctrl+C) does not interrupt an in-flight ping.
- ICMP Ping probe does not validate the ICMP message type matches EchoReply (only checks Echo body ID). An EchoRequest reflected back could match.
- DNS dual-stack AAAA query always uses `timeout=0` with no socket-level timeout on the DNS client.
- `FileSource.Load()` validation errors do not indicate which target index failed.
- `report.hasSuccess()` is missing a `PingObservation` case, creating a dormant bug that will activate if Ping is ever added to the summary.

---

## Critical Issues

### CR-01: Traceroute per-hop socket deadline is `time.Now()` (trace broken)

**File:** `internal/probe/traceprobe/adapter.go:20`
**Propagation:** `adapter.go:20` -> `trace.go:18` -> `trace.go:105` -> `trace.go:134,157`
**Issue:** The trace adapter calls `Probe(ctx, target.Domain, target.AddressFamily, 0)`, passing `timeout=0`. In `Probe()`, this 0 is forwarded to `ProbeHop()`, which sets the per-hop socket deadline:

```go
if timeout > 2*time.Second {
    timeout = 2 * time.Second  // 0 is NOT > 2s, so this is skipped
}
_ = conn.SetDeadline(time.Now().Add(timeout))  // timeout=0 -> deadline=now
```

Since `timeout` is 0, `SetDeadline` is called with `time.Now()`. By the time `ReadFrom` is reached (after `WriteTo`), the deadline is already in the past, so `ReadFrom` immediately returns a timeout error. The trace loop in `Probe()` then accumulates 3 consecutive empty hops and breaks, never reaching the target. The traceroute feature is non-functional.

**Note:** This bug pre-dates phase 3 (the original `Probe(ctx, target.Domain, 0)` also passed 0), but it directly prevents the IPv6 traceroute from working and should be fixed as part of this phase's integration.

**Fix:**
```go
// adapter.go line 20 - pass a sane timeout
obs := Probe(ctx, target.Domain, target.AddressFamily, 2*time.Second)
```

Also consider having `ProbeHop` derive a timeout from the context's deadline rather than relying on a fixed parameter:

```go
// trace.go in ProbeHop - derive deadline from context
if dl, ok := ctx.Deadline(); ok {
    remaining := time.Until(dl)
    if timeout == 0 || remaining < timeout {
        timeout = remaining
    }
}
if timeout <= 0 || timeout > 2*time.Second {
    timeout = 2 * time.Second
}
```

---

### CR-02: ICMPv6 TimeExceeded inner-body parsing uses IPv4 header format

**File:** `internal/probe/traceprobe/trace.go:193-198`
**Issue:** When the traceroute receives an ICMP TimeExceeded, the inner (original) packet header is parsed to extract the original ICMP Echo ID/Seq for Mismatch detection. The code unconditionally interprets the inner packet's first byte as an IPv4 header:

```go
innerIHL := int(body.Data[0]&0x0f) * 4
if len(body.Data) >= innerIHL+8 {
    innerID := int(binary.BigEndian.Uint16(body.Data[innerIHL+4 : innerIHL+6]))
    innerSeq := int(binary.BigEndian.Uint16(body.Data[innerIHL+6 : innerIHL+8]))
    hop.Mismatch = (innerID != probeID || innerSeq != ttl)
}
```

For ICMPv6 TimeExceeded, the inner packet is an IPv6 header (40 bytes fixed, no IHL field). `body.Data[0] & 0x0f` evaluates to `0x60 & 0x0f = 0x00`, so `innerIHL` = 0. The code then reads `body.Data[4:6]` (IPv6 Payload Length) as the "ID" and `body.Data[6:8]` (Next Header + Hop Limit) as the "Seq". This is always wrong for IPv6, causing:
- False Mismatch=true for most hops (payload length will rarely match the probe ID)
- False Mismatch=false when payload length coincidentally matches

**Fix:**
```go
// trace.go lines 193-201
if body.Data != nil && len(body.Data) > 0 {
    if isIPv4 {
        innerIHL := int(body.Data[0]&0x0f) * 4
        if len(body.Data) >= innerIHL+8 {
            innerID := int(binary.BigEndian.Uint16(body.Data[innerIHL+4 : innerIHL+6]))
            innerSeq := int(binary.BigEndian.Uint16(body.Data[innerIHL+6 : innerIHL+8]))
            hop.Mismatch = (innerID != probeID || innerSeq != ttl)
        }
    } else {
        // IPv6 header is fixed at 40 bytes
        if len(body.Data) >= 40+8 {
            innerID := int(binary.BigEndian.Uint16(body.Data[40+4 : 40+6]))
            innerSeq := int(binary.BigEndian.Uint16(body.Data[40+6 : 40+8]))
            hop.Mismatch = (innerID != probeID || innerSeq != ttl)
        }
    }
}
```

---

## Warnings

### WR-01: ICMP Ping probe ignores context cancellation

**File:** `internal/probe/icmpping/icmp.go:18`
**Issue:** The `Probe` function accepts a `ctx context.Context` parameter but never references it in the function body. There is no `select` on `ctx.Done()`, no `ctx.Deadline()` check, and no context-aware call. The `net.LookupIP(target)` call (line 26) does not support context-based cancellation, and `conn.ReadFrom(reply)` (line 86) only respects the socket deadline (set via `timeout`), not context cancellation.

If the user presses Ctrl+C during a ping:
1. The main context is cancelled
2. The probe does not notice -- `net.LookupIP` blocks until DNS returns or the DNS timeout fires
3. `conn.ReadFrom` blocks until the ICMP reply arrives or the socket deadline fires (up to `timeout`)
4. The probe only returns after timeout

**Fix:**
```go
// icmp.go - add context-aware cancellation
func Probe(ctx context.Context, target string, timeout time.Duration) (observation model.PingObservation) {
    start := time.Now()
    observation = model.PingObservation{Target: target}
    defer func() {
        observation.Latency = time.Since(start)
    }()

    // Use a resolver that respects context
    resolver := net.Resolver{}
    ips, err := resolver.LookupIPAddr(ctx, target)
    if err != nil {
        observation.Error = err.Error()
        return observation
    }
    // ... rest of the function
```

Alternatively, choose on `ctx.Done()` before each blocking operation, or use `conn.SetReadDeadline` + select on `ctx.Done()` in a goroutine.

---

### WR-02: ICMP Ping probe does not validate message type as EchoReply

**File:** `internal/probe/icmpping/icmp.go:110-117`
**Issue:** The probe only checks that the ICMP body has an `*icmp.Echo` type with matching `body.ID`:

```go
switch body := parsed.Body.(type) {
case *icmp.Echo:
    if body.ID == probeID {
        observation.Address = peer.String()
        observation.RTT = time.Since(sent)
        observation.TTL = ttl
        observation.Success = true
    }
}
```

While only Echo Reply messages normally carry an `*icmp.Echo` body, the parsed message type (`parsed.Type`) is never checked. If a router reflects back an Echo Request (type 8, which also has an `*icmp.Echo` body with matching ID/Seq), the probe would incorrectly treat it as a success with fake RTT.

**Likelihood:** Low under normal network conditions, but the fix is trivial.

**Fix:**
```go
case *icmp.Echo:
    if parsed.Type == ipv4.ICMPTypeEchoReply && body.ID == probeID {
        observation.Success = true
        // ...
    }
```

This matches the pattern already used in `trace.go:209-214` for `ProbeHop`.

---

### WR-03: DNS dual-stack AAAA query uses hardcoded timeout=0

**File:** `internal/probe/dnsprobe/adapter.go:30`
**Issue:** The dual-stack AAAA query calls `Probe()` with `timeout=0`:

```go
obs6 := Probe(ctx, a.Opts.Resolver, target.Domain, mdns.TypeAAAA, 0)
```

Inside `dns.go:24`, `mdns.Client{Timeout: timeout}` is created with `Timeout: 0`, meaning no socket-level timeout. The `ExchangeContext` call relies solely on the context for cancellation. If a DNS server is slow but the context deadline is generous (e.g., 5s), the AAAA query could hang for the entire duration with no recv-timeout on the UDP socket.

The primary query on line 26 also uses timeout=0 (pre-existing), but the dual-stack addition compounds this for the AAAA query.

**Fix:**
```go
// Derive timeout from context or use a reasonable default
timeout := 2 * time.Second
if deadline, ok := ctx.Deadline(); ok {
    if remaining := time.Until(deadline); remaining < timeout {
        timeout = remaining
    }
}
obs6 := Probe(ctx, a.Opts.Resolver, target.Domain, mdns.TypeAAAA, timeout)
```

---

### WR-04: FileSource validation errors lack target index context

**File:** `internal/targets/targets.go:36-39`
**Issue:** When `FileSource.Load()` iterates over parsed targets and `Validate()` fails, the returned error contains neither which index in the array failed nor the target's identity:

```go
for _, t := range targets {
    if err := t.Validate(); err != nil {
        return nil, err
    }
}
```

For a JSON file with 50 targets, "target name is required" gives no indication of which entry needs fixing. Compare to `scanner.go:44-49` where the original builtin-target validation at least prints the error.

**Fix:**
```go
for idx, t := range targets {
    if err := t.Validate(); err != nil {
        return nil, fmt.Errorf("target[%d] %q: %w", idx, t.Name, err)
    }
}
```

---

### WR-05: `report.hasSuccess()` missing PingObservation case

**File:** `internal/report/report.go:109-125`
**Issue:** The `hasSuccess` type-switch covers `DNSObservation`, `TCPObservation`, `TLSObservation`, `HTTPObservation`, `QUICObservation`, and `TraceObservation`, but not `PingObservation`. Currently this is a dormant bug because the summary does not include a Ping column, so `hasSuccess` is never called with `PingObservation`. If a Ping column is ever added to the summary (or if any future code uses this function with ping data), every successful ping would report as "fail".

**Fix:**
```go
func hasSuccess(data any) bool {
    switch v := data.(type) {
    // ... existing cases ...
    case model.PingObservation:
        return v.Success
    }
    return false
}
```

---

## Info

### IN-01: context import required for signature but ctx parameter is unused

**File:** `internal/probe/icmpping/icmp.go:18`
**Details:** The `ctx context.Context` parameter is accepted but never read. Go compiles this fine (unused function parameters are not errors), but it creates a misleading API -- callers pass a context expecting cancellation and do not get it.

### IN-02: Traceprobe test pattern -- conn opened then immediately closed before Probe

**File:** `internal/probe/traceprobe/trace_test.go:143-148, 193-198`
**Details:** Both `TestProbeGeneratesUniqueIDs` and `TestConcurrentTracerouteNoCrossContamination` call `icmp.ListenPacket("ip4:icmp", "0.0.0.0")` for the ICMP privilege check, then immediately close the connection before calling `traceprobe.Probe()` (which creates its own socket). The conn creation serves only as a permission gate. This is not incorrect but is confusing on first reading -- the conn variable is never used for the actual probe invocation.

### IN-03: Traceprobe tests pass timeout directly, masking the adapter's timeout=0 bug

**File:** `internal/probe/traceprobe/trace_test.go:82, 126, 175, 210`
**Details:** The tests call `traceprobe.Probe(ctx, "127.0.0.1", "", time.Second)` (or `2*time.Second`) directly, bypassing `Adapter.Run()`. They use a non-zero per-hop timeout, so the timeout=0 bug in the adapter is never exercised. The tests pass on localhost but the actual scanner integration path is broken. Consider a test that exercises the adapter path.

### IN-04: Summary does not display ICMP ping results

**File:** `internal/report/report.go:31`
**Details:** The summary header is `TARGET | DNS | TCP | TLS | QUIC | HTTP | TRACE | FINDINGS` and does not include a column for Ping, even when `--icmp-ping` is enabled. Successful pings produce data stored in `TargetResult.Results` but are invisible in the terminal output. Only permission errors are surfaced (as warnings in the scanner). Adding a Ping column would make the feature visible to end users.

---

_Reviewed: 2026-04-26T16:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: deep_
