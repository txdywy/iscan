# Codebase Concerns

**Analysis Date:** 2026-04-26

## Tech Debt

### Instant Retries with No Backoff

**Issue:** All retry loops in `scanner.go` (`scanTarget`) attempt retries consecutively with zero delay between attempts. There is no jitter, exponential backoff, or any rate-limiting mechanism.

- TCP retries: `scanner.go:98-104`
- HTTP retries: `scanner.go:119-125`
- QUIC retries: `scanner.go:133-151`
- TLS retries: `scanner.go:162-168`

**Impact:** During transient network failures, all retry attempts fail identically in rapid succession, wasting wall-clock time and increasing the risk of remote rate limiting. The three retries consume time without any increased likelihood of success.

**Fix approach:** Add `time.Sleep` with small jitter (e.g. `50ms * 2^attempt + rand`) before retries, or switch to a multiplicative backoff capped at 1 second.

### Unused Dead Code: FindingLocalNetworkIssue Constant

**Issue:** The `FindingLocalNetworkIssue` constant is defined in `internal/model/model.go:35` but never referenced anywhere in the codebase. No code path ever creates a finding of this type.

**Impact:** Confusing to maintainers. New contributors may assume this finding type is used and try to build on it, only to discover it has no effect. Adds cognitive overhead without value.

**Fix approach:** Either remove the constant, or implement at least one code path that can produce a local network issue finding (e.g. trace probe failing due to permission errors, all probes failing on a target).

### TLS Probe Accepts `insecureSkipVerify` As Parameter But Scanner Always Passes `true`

**Issue:** The TLS probe (`internal/probe/tlsprobe/tls.go:15`) accepts `insecureSkipVerify bool` as a parameter, giving the appearance of configurability. However, the scanner always passes `true` from `probeTLSWithRetries` (`internal/scanner/scanner.go:163`), making the parameter effectively unused.

**Impact:** Misleading API. The parameter suggests callers can optionally skip cert verification, but every caller hardcodes it to `true`.

**Fix approach:** Either remove the parameter and hardcode `InsecureSkipVerify: true` in the probe, or add a `ScanOption` to let users control it.

### System Resolver DNS Probe Collapses Error Type

**Issue:** The `probeDNS` function in `scanner.go:171-202` handles system resolver (`net.DefaultResolver`) lookups differently from explicit DNS probes. When the system resolver fails, only the raw error string is captured (`observation.Error = err.Error()`), with no `RCode` set and `Success` always false. There is no classification of the error type (NXDOMAIN vs SERVFAIL vs timeout vs no such host).

**Impact:** The classifier receives inconsistent DNS observation structures depending on whether the resolver is system or explicit. A SERVFAIL from the system resolver gets the same `Error` field as a network timeout. The classifier's `dnsInconsistent` and `suspiciousDNS` functions skip observations without usable answers (`dnsHasUsableAnswers` checks for error==`""`), so system resolver failures are silently excluded from analysis.

### Number of Probe Arguments Is High

**Issue:** Probe functions like `tlsprobe.Probe` and `quicprobe.Probe` accept 6-7 positional parameters (`host`, `port`, `sni`, `alpn`, `timeout`, `insecureSkipVerify`). TLS has a confusing sign with `host` vs `sni` as separate string params that are often the same value.

**Files:** `internal/probe/tlsprobe/tls.go:15`, `internal/probe/quicprobe/quic.go:16`

**Impact:** Easy to swap arguments at call sites (caller passes `target.Domain` twice via `observation.Host` and `target.Domain` at `scanner.go:112-113`). Error-prone during maintenance.

**Fix approach:** Consider an options struct pattern for probe configuration.

## Security Considerations

### TLS Certificate Verification Disabled (InsecureSkipVerify: true)

**Risk:** All three TLS-aware probes (`httpprobe`, `tlsprobe`, `quicprobe`) disable certificate verification entirely with `InsecureSkipVerify: true`. This means the tool is susceptible to MITM attacks and cannot detect certificate-based tampering.

**Files:**
- `internal/probe/httpprobe/http.go:19` -- `TLSClientConfig: &tls.Config{InsecureSkipVerify: true}`
- `internal/probe/tlsprobe/tls.go:22` -- `Config.ServerName` set but `InsecureSkipVerify` is `true`
- `internal/probe/quicprobe/quic.go:26` -- `InsecureSkipVerify: true`

**Current mitigation:** None. This is by design for a diagnostic tool -- the goal is to measure TLS handshake success/failure at the transport level regardless of certificate validity. The cert SHA-256 hash is still recorded for inspection.

**Recommendations:**
1. Document that certificate verification is intentionally disabled because the tool checks transport-layer connectivity, not PKI trust.
2. Add a `--validate-certs` flag to `ScanOptions` that enables verification.
3. For a "clean scan" mode, log a warning when `InsecureSkipVerify=true` is being used.

### Raw ICMP Socket (Privileged Operation)

**Risk:** The traceroute probe (`internal/probe/traceprobe/trace.go:39`) opens a raw ICMP socket (`icmp.ListenPacket("ip4:icmp", "0.0.0.0")`), which requires `CAP_NET_RAW` on Linux or root on macOS.

**Files:** `internal/probe/traceprobe/trace.go:39`

**Current mitigation:** The feature is gated behind a `--trace` flag (`cmd/iscan/main.go:97`), and permission errors are handled gracefully (`internal/scanner/scanner.go:72-73`).

**Recommendations:**
1. Add a clear error message at the `--trace` flag level when the user doesn't have permission, rather than silently producing an empty trace.
2. Consider using a UDP-based traceroute as a fallback (sends UDP probes, matches ICMP TTL exceeded).

## Performance Bottlenecks

### Scanner Cancellation Cascading Causes Data Loss

**Problem:** The `scanner.Run` function (`scanner.go:49-64`) uses `errgroup.WithContext` which cancels the shared context when the first goroutine returns an error. Since goroutines only error on cancellation (they return `gCtx.Err()` when they detect `gCtx.Done()`), a single slow probe on one target cancels ALL remaining targets.

**Files:** `internal/scanner/scanner.go:49-64`

**Cause:** If one target's probes exceed the timeout, the errgroup context is canceled, and all other target goroutines see `gCtx.Done()` and return immediately, discarding their partial results.

**Impact:** With the 5-second default timeout and 4 targets, if the first target takes 6 seconds (e.g., DNS timeout + TCP timeout), the remaining 3 targets return zero results. The user gets a report with incomplete data.

**Improvement path:** Use a `context.WithCancel` deriving from the user context for each goroutine independently, rather than sharing a single `errgroup` context. Only cancel the group for hard errors (not cancellation).

### Duplicate DNS Resolution On Each Retry Attempt

**Problem:** In `scanTarget` (`scanner.go:82-158`), DNS resolution happens once and addresses are cached. However, when TCP/TLS/HTTP retries happen, they reuse the same pre-resolved addresses. This means retries do not benefit from potentially different DNS results, and a transient DNS failure that returns empty answers cascades to all subsequent layers.

**Impact:** If the initial DNS lookup returns 0 answers (line 92-94), the TCP probe falls back to the raw domain name for all retries. A subsequent DNS resolution success is never captured.

### System Resolver DNS Latency Always Measured Even On Error

**Problem:** In `scanner.go:175-198`, `observation.Latency = time.Since(start)` is set BEFORE the error check. This means even failed DNS lookups record their latency. This is inconsistent with explicit resolver probes where latency is only set after `client.ExchangeContext` succeeds or fails (the latency is always recorded there too, but the start time is set right before exchange).

**Fix approach:** This is actually fine for latency tracking but the observation might be confusing -- a "failed" lookup with latency recorded could be misinterpreted as timing a partial response.

## Fragile Areas

### `TestBuildScanReportSkipsCancelledTargets` Hits Real Internet

**Files:** `internal/scanner/scanner_test.go:58-74`

**Why fragile:** This test calls `scanner.Run` with a 100ms timeout against the builtin target set (`example.com`, `cloudflare.com`, `google.com`), which requires live internet connectivity. The test:
- Fails when offline (no network)
- Is slow (100ms per 4 parallel targets still takes ~400ms+ in the worst case)
- Depends on external DNS resolution working (system resolver)
- May flake on high-latency connections

**Safe modification:** Add a test mode or dependency injection for the target list to use local test targets. Skip the test with `testing.Short()` when `-short` is set.

### Trace Probe Has No Test Coverage At All

**Files:** `internal/probe/traceprobe/trace.go` -- zero test files exist.

**Why fragile:** The traceroute logic has the most complex control flow in the codebase (TTL loop, ICMP reading, timeout detection, consecutive empty hop handling, IPv4-only fallback). With no tests, any refactoring risks breaking:
- The TTL loop termination logic (`consecutiveEmpty >= 3`)
- The reply parsing (`icmp.ParseMessage(1, reply[:n])`)
- The hop timeout detection (`isReadTimeout`)
- The context cancellation during the hop loop

### Targets Package Has No Test Coverage

**Files:** `internal/targets/targets.go` -- zero test files exist.

**Impact:** Low risk since it's a static data file, but if targets are ever loaded from config or made dynamic, the `Validate()` path would be untested at the integration level.

### `missingPort` in DNS Probe Has a Subtle Bug Path

**Files:** `internal/probe/dnsprobe/dns.go:73-83`

**Why fragile:** The `missingPort` function uses `errors.As(err, &addrErr)` to check if the error has type `*net.AddrError`. The `err` from `net.SplitHostPort` has type `*net.AddrError` in standard Go, but the string check `addrErr.Err == "missing port in address"` is locale-dependent and changes between Go versions. If Go's error messages change, this silently breaks, causing a "server:53" style address to NOT be handled (the fake server `""` is passed to ExchangeContext).

### DNS Truncation Fallback Could Mask Problems

**Files:** `internal/probe/dnsprobe/dns.go:50-68`

**Why fragile:** When a DNS response is truncated (TC flag), the probe retries over TCP silently. The final recorded observation replaces the original UDP answers entirely, so there is no indication in the observation that truncation happened. This means the classifier sees the TCP result but doesn't know the original UDP response was truncated.

## Scaling Limits

### Hardcoded Builtin Targets

**Current capacity:** 4 hardcoded targets in `internal/targets/targets.go`.

**Limit:** The tool `iscan` can only scan the targets defined at compile time. The `--target-set` flag currently only supports "builtin" (`cmd/iscan/main.go:49-51`).

**Scaling path:** Support custom target lists via JSON file (`--target-set custom.json`) or inline arguments. The `model.Target` struct is already well-defined and validated.

### Hardcoded Max TTL of 30 in Traceroute

**Current capacity:** 30 hops maximum (`internal/probe/traceprobe/trace.go:48`).

**Limit:** For unusual paths (satellite links, multi-hop VPNs) that exceed 30 hops, the collection silently truncates and may report `Success: false`.

**Scaling path:** Make max TTL configurable via a parameter or extend to 64 (the IPv4 limit).

## Missing Critical Features

### No IPv6 Traceroute Support

**Problem:** The trace probe (`internal/probe/traceprobe/trace.go:27-37`) explicitly filters to only IPv4 addresses:
```go
for _, candidate := range ips {
    if candidate.To4() != nil {
        ip = candidate
        break
    }
}
if ip == nil {
    observation.Error = "no IPv4 address for trace"
    return observation
}
```

**Blocks:** Users on IPv6-only networks (mobile, some ISPs) cannot use the traceroute feature at all. The probe silently returns an error even when perfectly valid IPv6 addresses exist.

**Priority:** Low for first release, but increasingly important as IPv6 adoption grows.

### No Custom Target File / Dynamic Target Loading

**Problem:** The `--target-set` flag is hardcoded to reject anything other than "builtin" (`main.go:49-51`). Users cannot define custom targets to probe.

**Blocks:** Enterprise users who need to probe internal services or specific testing endpoints.

**Priority:** Medium -- the model layer already supports it (`model.Target`) and `targets.BuiltinTargets()` returns a stable list, so the only missing piece is the CLI and deserialization.

### No Ping / Non-TCP Connectivity Check

**Problem:** The tool has no ICMP echo (ping) probe that works without root privileges. The trace probe requires raw sockets. Users on non-root environments have no way to measure basic latency or packet loss.

**Priority:** Low -- TCP probe on common ports fills most use cases.

## Test Coverage Gaps

### packages/internal/probe/traceprobe: 0% Coverage

- **What's not tested:** All of `trace.go` -- TTL loop, ICMP read timeout, consecutive empty detection, context cancellation, reply parsing
- **Files:** `internal/probe/traceprobe/trace.go`
- **Risk:** Medium -- the most complex single-probe logic in the codebase with no regression safety net
- **Priority:** High

### Package targets: 0% Coverage

- **What's not tested:** `BuiltinTargets()`, `BuiltinResolvers()`
- **Files:** `internal/targets/targets.go`
- **Risk:** Low -- static data, but would catch accidental data corruption
- **Priority:** Low

### QUIC Probe: Minimal Coverage

- **What's not tested:** Successful QUIC handshake (only tests failure against non-QUIC endpoint)
- **Files:** `internal/probe/quicprobe/quic_test.go`
- **Risk:** Low -- QUIC requires a live QUIC server to test
- **Priority:** Low

### Scanner: Integration Test Only

- **What's not tested:** The `scanTarget` function (core scanning logic), error handling in the retry loops, the parallel errgroup behavior with cancellation
- **Files:** `internal/scanner/scanner_test.go`
- **Risk:** Medium -- the scanner has the most complex orchestration and only one brittle integration test
- **Priority:** Medium

---

*Concerns audit: 2026-04-26*
