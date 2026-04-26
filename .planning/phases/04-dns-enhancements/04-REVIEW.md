---
phase: 04-dns-enhancements
reviewed: 2026-04-27T00:00:00Z
depth: standard
files_reviewed: 14
files_reviewed_list:
  - cmd/iscan/main.go
  - internal/classifier/classifier.go
  - internal/classifier/classifier_test.go
  - internal/model/model.go
  - internal/model/errors.go
  - internal/model/errors_test.go
  - internal/probe/dnsprobe/adapter.go
  - internal/probe/dnsprobe/dns.go
  - internal/probe/dnsprobe/doh.go
  - internal/probe/dnsprobe/doh_test.go
  - internal/probe/dnsprobe/dot.go
  - internal/probe/dnsprobe/dot_test.go
  - internal/probe/dnsprobe/ratelimit.go
  - internal/probe/dnsprobe/ratelimit_test.go
  - internal/scanner/scanner.go
  - internal/scanner/scanner_test.go
  - internal/targets/targets.go
findings:
  critical: 1
  warning: 4
  info: 3
  total: 8
status: issues_found
---

# Phase 4: Code Review Report

**Reviewed:** 2026-04-27T00:00:00Z
**Depth:** standard
**Files Reviewed:** 17
**Status:** issues_found

## Summary

Reviewed DNS enhancement changes across the probe, classifier, scanner, and targets packages. Found one critical bug in the DoT truncated response retry path where success is incorrectly reported, and several warnings including a non-functional retry middleware, inconsistent error states, and a false-positive-prone transparent DNS proxy detection for custom resolvers.

## Critical Issues

### CR-01: DoT truncated response retry does not set Success=false on failure

**File:** `internal/probe/dnsprobe/dot.go:86`
**Issue:** When a DNS-over-TLS response is truncated and the TCP-TLS retry fails, `obs.Success` is never set to `false`. It retains whatever value was set at line 49 from the first (truncated) response, which is typically `true` (since the truncated response had `RcodeSuccess`). The observation will report `Success: true` alongside an error message like `dot_truncated_retry_failed: connection refused`, creating a contradictory and misleading state.

This code path is hit when a DoT server returns a truncated UDP-style response over TLS and the subsequent TCP retry fails (e.g., server disconnect, timeout).

**Contrast with the UDP query code** at `internal/probe/dnsprobe/dns.go:92` which correctly sets `observation.Success = false` in the identical scenario. This was simply omitted from the DoT copy.

**Fix:**
```go
// dot.go line 86
} else {
    obs.Success = false
    obs.Error = "dot_truncated_retry_failed: " + err.Error()
}
```

## Warnings

### WR-01: Retry middleware is non-functional for all probes

**Files:**
- `internal/scanner/scanner.go:111-119`
- `internal/probe/middleware/retry.go:11-38`

**Issue:** The `middleware.Retry` function checks whether `lastResult.Data` is a non-empty `string` to decide whether to retry (line 30: `if errStr, ok := lastResult.Data.(string); ok && errStr != ""`). However, every probe in the registry returns typed observation structs as `Data`:

- DNS adapter returns `[]model.DNSObservation` (adapter.go:57)
- Other probes return `model.TCPObservation`, `model.TLSObservation`, etc.

None of these are `string`, so the type assertion always fails and `middleware.Retry` returns the result on the first attempt without ever retrying. The `--retries` CLI flag and `ScanOptions.Retries` field have no effect on actual probe execution.

The `middleware.Timeout` wrapper (which creates a context deadline) sits *outside* `Retry` in the chain and only overwrites `Data` with a string error *after* `Retry` has already returned. So even timeout errors are not retried.

**Note:** A properly-implemented retry function (`retryWithBackoff` in `scanner.go:206-241`) exists with its own test (`scanner/retry_test.go`) but is dead code — never called from any production path.

**Fix options:**
- Option A: Change the retry middleware to check for `Success` field on observation types via reflection or a common interface (e.g., `interface{ Success() bool }`).
- Option B: Replace the broken middleware chain with direct calls to `retryWithBackoff` inside each probe's `Run` method.
- Option C: Redesign the error signaling so probes return a distinguishable error type as `Data` on failure.

### WR-02: Transparent DNS proxy detection generates false positives for custom resolvers

**Files:**
- `internal/probe/dnsprobe/adapter.go:46-55`
- `internal/classifier/classifier.go:391-402`

**Issue:** The whoami probe (adapter.go lines 46-55) sends `whoami.akamai.net` queries to all non-system resolvers, including custom resolvers added via the `--resolver` flag. The classifier's `isKnownResolverIP` function (classifier.go:391-402) only recognizes well-known public resolver IPs (Cloudflare, Google, Quad9). A custom resolver (e.g., `--resolver=198.51.100.1`) will:

1. Receive the whoami query
2. Return its own IP (`198.51.100.1`) as the answer — this is *correct* whoami behavior
3. `isKnownResolverIP("198.51.100.1")` returns `false`
4. A `dns_transparent_proxy` finding is generated with `ConfidenceHigh`

This is a false positive. The whoami response for a non-system resolver will always appear to be a "transparent proxy" because the resolver's own IP is not in the known list.

**Fix:** Check whether the resolved IP matches the resolver's own server address before flagging it:

```go
// In detectTransparentDNSProxy (classifier.go), before appending a finding:
if resolvedIP == obs.Resolver {
    continue // whoami returned the resolver's own IP — expected
}
```

Alternatively, skip custom resolvers for whoami probes in the adapter (adapter.go:47-48 already skips system resolvers; extend the skip to all resolvers without a known IP in the well-known set).

### WR-03: Inconsistent RCode/Success state when UDP truncated TCP fallback fails

**File:** `internal/probe/dnsprobe/dns.go:68-94`

**Issue:** When a UDP DNS query receives a truncated response and the TCP fallback fails, the function returns an observation with:
- `Success: false` (correctly set at line 92)
- `RCode: "NOERROR"` (left over from the first UDP response at line 55)
- `Error: "truncated+tcp_fallback_failed: ..."`

The `RCode` field is misleading — it reflects the successful-but-truncated UDP response, not the actual outcome (failure). Callers inspecting `RCode` before `Success` will draw incorrect conclusions.

**Fix:**
```go
// dns.go line 92-93, after setting Success=false:
observation.Success = false
observation.RCode = ""  // or "SERVFAIL" — reset to indicate failure
observation.Error = "truncated+tcp_fallback_failed: " + err.Error()
```

### WR-04: Global rate limiter state accessed without synchronization

**File:** `internal/probe/dnsprobe/ratelimit.go:25-43`

**Issue:** The `defaultQPS` and `defaultBurst` package-level variables are written by `SetRateLimit` and read by `waitLimiter` without any synchronization primitive (mutex, atomic). `rate.Limit` is a `float64` alias — on 32-bit architectures, reading a 64-bit float while it is being written is a data race. On 64-bit architectures, the race is still a violation of the Go memory model.

Currently the code avoids the race because `SetRateLimit` is called once before goroutines start (scanner.go:42), but the API is fragile. A future caller who invokes `SetRateLimit` concurrently (e.g., from two parallel scan calls) will trigger a data race.

**Fix:** Add a sync.Mutex to protect `defaultQPS` and `defaultBurst`:

```go
var (
    resolverLimiters sync.Map
    mu               sync.Mutex
    defaultQPS       rate.Limit = 20
    defaultBurst     int        = 5
)

func SetRateLimit(qps int) {
    mu.Lock()
    defer mu.Unlock()
    if qps <= 0 {
        defaultQPS = rate.Inf
        defaultBurst = 1
    } else {
        defaultQPS = rate.Limit(qps)
    }
}

func waitLimiter(ctx context.Context, name string) error {
    mu.Lock()
    inf := defaultQPS == rate.Inf
    mu.Unlock()
    if inf {
        return nil
    }
    limiter := getLimiter(name)
    return limiter.Wait(ctx)
}
```

## Info

### IN-01: FindingLocalNetworkIssue is defined but never used

**File:** `internal/model/model.go:36`

**Issue:** The constant `FindingLocalNetworkIssue` is defined as a `FindingType` but is never referenced anywhere in the codebase (no classifier function generates it, no probe reports it, no test checks it). This is dead code that adds unnecessary maintenance surface area.

**Fix:** Either remove the constant or implement the classifier logic to generate this finding in appropriate scenarios.

### IN-02: Unnecessary reimplementation of strings.Contains and strings.Index

**File:** `internal/model/errors.go:33-51`

**Issue:** The functions `contains` and `indexString` are hand-rolled ASCII implementations of `strings.Contains` and `strings.Index`. The standard library versions are more efficient (use Rabin-Karp algorithm) and better tested. While the `strings` package is not currently imported in this file, it is already imported elsewhere in the model package. The hand-rolled version adds maintenance burden for zero benefit.

**Fix:** Replace with standard library calls:

```go
import "strings"

func IsLocalPermissionError(msg string) bool {
    lower := strings.ToLower(msg)
    return strings.Contains(lower, "operation not permitted") || strings.Contains(lower, "permission denied")
}
```

(Note: This also eliminates the separate `toLowerASCII`, `contains`, and `indexString` functions entirely.)

### IN-03: Dead code: retryWithBackoff function never called from production code

**File:** `internal/scanner/scanner.go:206-241`

**Issue:** The generic `retryWithBackoff[T]` function is defined and has its own test (`scanner/retry_test.go:11-34`) but is never called from any production code path. Meanwhile, the wired-up retry mechanism (`middleware.Retry` via the middleware chain in `buildProbes`) is broken (see WR-01). Having a working retry function that is dead code alongside a broken one that is live is confusing and error-prone.

**Fix:** Wire `retryWithBackoff` into the probe execution path, or remove the dead function and test.

---

_Reviewed: 2026-04-27T00:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
