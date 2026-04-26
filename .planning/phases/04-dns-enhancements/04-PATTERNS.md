# Phase 4: DNS Enhancements - Pattern Map

**Mapped:** 2026-04-26
**Files analyzed:** 14 (6 new, 8 modified)
**Analogs found:** 14 / 14

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `internal/probe/dnsprobe/doh.go` (new) | service | request-response | `internal/probe/dnsprobe/dns.go` | role-match |
| `internal/probe/dnsprobe/dot.go` (new) | service | request-response | `internal/probe/dnsprobe/dns.go` | exact |
| `internal/probe/dnsprobe/ratelimit.go` (new) | middleware | request-response | `internal/probe/middleware/retry.go` | role-match |
| `internal/probe/dnsprobe/doh_test.go` (new) | test | request-response | `internal/probe/dnsprobe/dns_test.go` | exact |
| `internal/probe/dnsprobe/dot_test.go` (new) | test | request-response | `internal/probe/dnsprobe/dns_test.go` | exact |
| `internal/probe/dnsprobe/ratelimit_test.go` (new) | test | request-response | `internal/probe/middleware/chain.go` + existing test patterns | partial |
| `internal/probe/dnsprobe/dns.go` (modified) | service | request-response | `internal/probe/dnsprobe/dns.go` (current) | exact |
| `internal/probe/dnsprobe/adapter.go` (modified) | controller | request-response | `internal/probe/dnsprobe/adapter.go` (current) | exact |
| `internal/probe/dnsprobe/dns_test.go` (modified) | test | request-response | `internal/probe/dnsprobe/dns_test.go` (current) | exact |
| `internal/model/model.go` (modified) | model | CRUD | `internal/model/model.go` (current) | exact |
| `internal/classifier/classifier.go` (modified) | controller | event-driven | `internal/classifier/classifier.go` (current) | exact |
| `internal/classifier/classifier_test.go` (modified) | test | event-driven | `internal/classifier/classifier_test.go` (current) | exact |
| `internal/targets/targets.go` (modified) | config | CRUD | `internal/targets/targets.go` (current) | exact |
| `cmd/iscan/main.go` (modified) | config | request-response | `cmd/iscan/main.go` (current) | exact |

## Pattern Assignments

### `internal/probe/dnsprobe/doh.go` (new, service, request-response)

**Analog:** `internal/probe/dnsprobe/dns.go` (lines 1-78)

**Imports pattern** (from `internal/probe/dnsprobe/dns.go` lines 1-12):
```go
package dnsprobe

import (
    "context"
    "net"
    "time"

    mdns "github.com/miekg/dns"

    "iscan/internal/model"
)
```

**DNSObservation construction pattern** (from `internal/probe/dnsprobe/dns.go` lines 14-20):
```go
func Probe(ctx context.Context, resolver model.Resolver, domain string, qtype uint16, timeout time.Duration) model.DNSObservation {
    query := mdns.Fqdn(domain)
    observation := model.DNSObservation{
        Resolver: resolver.Name,
        Query:    query,
        Type:     mdns.TypeToString[qtype],
    }
    msg := new(mdns.Msg)
    msg.SetQuestion(query, qtype)
    msg.SetEdns0(1232, false)
```

**Error handling + latency recording pattern** (from `internal/probe/dnsprobe/dns.go` lines 30-36):
```go
    start := time.Now()
    resp, _, err := client.ExchangeContext(ctx, msg, server)
    observation.Latency = time.Since(start)
    if err != nil {
        observation.Error = err.Error()
        return observation
    }
    observation.RCode = mdns.RcodeToString[resp.Rcode]
    observation.Success = resp.Rcode == mdns.RcodeSuccess
```

**HTTP client pattern** (from `internal/probe/httpprobe/http.go` lines 73-84):
```go
    req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
    if err != nil {
        observation.Error = err.Error()
        return observation
    }
    requestStart = time.Now()
    resp, err := client.Do(req)
    observation.Latency = time.Since(requestStart)
    if err != nil {
        observation.Error = err.Error()
        return observation
    }
```

**DoH-specific pattern** (from RESEARCH.md Pattern 2 lines 250-299):
The DoH function MUST use `net/http` POST to the DoH endpoint with `application/dns-message` content type,
using `mdns.Msg.Pack()` for request and `mdns.Msg.Unpack()` for response. The function signature follows
the existing `Probe` function pattern: takes `(ctx, resolver, query, qtype, timeout)` and returns `model.DNSObservation`.

---

### `internal/probe/dnsprobe/dot.go` (new, service, request-response)

**Analog:** `internal/probe/dnsprobe/dns.go` (lines 14-48) + `internal/probe/tlsprobe/tls.go` (lines 17-25 for TLS config)

**Imports pattern** (from `internal/probe/dnsprobe/dns.go` lines 1-12, plus crypto/tls from `internal/probe/tlsprobe/tls.go` lines 1-12):
```go
package dnsprobe

import (
    "context"
    "crypto/tls"
    "net"
    "time"

    mdns "github.com/miekg/dns"

    "iscan/internal/model"
)
```

**TLS config pattern** (from `internal/probe/tlsprobe/tls.go` lines 17-23):
```go
    client := &mdns.Client{
        Net:       "tcp-tls",
        Timeout:   timeout,
        TLSConfig: &tls.Config{InsecureSkipVerify: true},
    }
```

**Port handling pattern** (from `internal/probe/dnsprobe/dns.go` lines 25-28):
```go
    server := resolver.Server
    if server != "" && missingPort(server) {
        server = net.JoinHostPort(server, "853") // DoT default port 853, not 53
    }
```

**DoT-specific:** Use `client.ExchangeContext(ctx, msg, server)` with `Net: "tcp-tls"`. All other patterns
(DNSObservation construction, answer parsing, error handling) are identical to `internal/probe/dnsprobe/dns.go`.

---

### `internal/probe/dnsprobe/ratelimit.go` (new, middleware, request-response)

**Analog:** `internal/probe/middleware/retry.go` (lines 1-38)

**Middleware signature pattern** (from `internal/probe/middleware/retry.go` lines 11-14):
```go
func RateLimit(qps int, burst int) Middleware {
    return func(next probe.Probe) probe.Probe {
        return probe.ProbeFunc(func(ctx context.Context, target model.Target) model.ProbeResult {
            // rate limit logic before calling next.Run(ctx, target)
            return next.Run(ctx, target)
        })
    }
}
```

**Token bucket pattern** (from RESEARCH.md Pattern 5 lines 389-413):
```go
var (
    resolverLimiters sync.Map // map[string]*rate.Limiter
    rateLimitValue   rate.Limit = 20
)

func getResolverLimiter(name string) *rate.Limiter {
    actual, _ := resolverLimiters.LoadOrStore(name, rate.NewLimiter(rateLimitValue, 5))
    return actual.(*rate.Limiter)
}
```

**IMPORTANT:** Unlike existing middleware (which wraps probes at the scanner level), this rate limiter
operates INSIDE the DNS adapter, wrapping individual resolver queries -- not at the `probe.Probe` middleware
level. The `sync.Map` of per-resolver token buckets is the core data structure. Use `limiter.Wait(ctx)` for
context-cancellation-aware blocking.

---

### `internal/probe/dnsprobe/dns.go` (modified, service, request-response)

**Analog:** Current `internal/probe/dnsprobe/dns.go` (lines 1-91) -- same file, extended

**Existing pattern to preserve** (lines 14-79): The full `Probe` function with miekg/dns UDP/TCP exchange,
EDNS0, answer parsing, and truncated TCP fallback.

**Additions:**

1. **Transport-aware dispatch** (new pattern inspired by RESEARCH.md Pattern 1 lines 218-239):
```go
func Probe(ctx context.Context, resolver model.Resolver, domain string, qtype uint16, timeout time.Duration) model.DNSObservation {
    switch resolver.Transport {
    case "https":
        return dohQuery(ctx, resolver, domain, qtype, timeout)
    case "tcp-tls":
        return dotQuery(ctx, resolver, domain, qtype, timeout)
    case "system":
        return systemResolverQuery(ctx, resolver, domain, qtype, timeout)
    default: // "", "udp", "tcp"
        return udpQuery(ctx, resolver, domain, qtype, timeout)
    }
}
```

2. **System resolver** (new function using Go stdlib rather than miekg/dns):
Use `net.DefaultResolver.LookupHost(ctx, domain)` and map `net.DNSError` to RCODE values.
Pattern from RESEARCH.md Pattern 4 lines 351-379.

3. **Refactoring approach:** Extract the existing UDP/TCP logic into `udpQuery()`. Add `dohQuery()` and `dotQuery()`
as calls into the new files. The current `Probe()` function becomes a transport dispatcher.

---

### `internal/probe/dnsprobe/adapter.go` (modified, controller, request-response)

**Analog:** Current `internal/probe/dnsprobe/adapter.go` (lines 1-56)

**Adapter/init() pattern** (lines 49-56) -- to extend for multi-resolver:
```go
func init() {
    probe.Registry[model.LayerDNS] = &Adapter{
        Opts: DNSOpts{
            Resolver: model.Resolver{Name: "system", System: true},
            QType:    mdns.TypeA,
        },
    }
}
```

**Key modification:** The adapter must iterate over ALL resolvers (from `targets.BuiltinResolvers()` extended with
DoH/DoT resolvers) and call `Probe()` once per resolver per target. The scanner currently calls `buildProbes()` 
which expects one `ProbeResult` per probe per target. Two approaches:

- **Option A (recommended):** The adapter's `Run()` method calls a new `ProbeAll()` function that probes all
  resolvers and returns a slice of results. Change `Run()` to aggregate them into a single `ProbeResult`.
  This keeps the registry as `map[model.Layer]Probe{}`.

- **Option B:** `Run()` returns the first result. Not recommended -- loses multi-resolver signal.

**The adapter MUST NOT register multiple adapters via multiple `init()` calls** -- the `map[model.Layer]Probe{}`
registry (probe.go line 22) only holds one entry per layer.

---

### `internal/model/model.go` (modified, model, CRUD)

**Analog:** Current `internal/model/model.go` (lines 67-71, 27-37, 104-114)

**Resolver.Transport field addition** (extend `Resolver` struct around line 67):
```go
type Resolver struct {
    Name      string `json:"name"`
    Server    string `json:"server"`
    System    bool   `json:"system"`
    Transport string `json:"transport,omitempty"` // "udp", "tcp", "https", "tcp-tls", "system"
}
```

**New FindingType constants** (add alongside existing ones around line 27):
```go
const (
    FindingDNSNXDOMAIN      FindingType = "dns_nxdomain"
    FindingDNSSERVFAIL      FindingType = "dns_servfail"
    FindingDNSREFUSED       FindingType = "dns_refused"
    FindingDNSOtherRCODE    FindingType = "dns_other_rcode"
    FindingDNSTransparentProxy FindingType = "dns_transparent_proxy"
)
```

**ScanOptions.DNSRateLimit field** (add to `ScanOptions` struct around line 73):
```go
type ScanOptions struct {
    Timeout     time.Duration `json:"timeout"`
    Retries     int           `json:"retries"`
    Trace       bool          `json:"trace"`
    QUIC        bool          `json:"quic"`
    Parallelism int           `json:"parallelism"`
    ICMPPing    bool          `json:"icmp_ping,omitempty"`
    TargetSet   string        `json:"target_set,omitempty"`
    DNSRateLimit int          `json:"dns_rate_limit,omitempty"` // queries/sec per resolver
}
```

---

### `internal/classifier/classifier.go` (modified, controller, event-driven)

**Analog:** Current `internal/classifier/classifier.go` (lines 13-120)

**Existing finding emission pattern** (lines 24-31) -- replicate for per-RCODE findings:
```go
if dnsInconsistent(dnsObs) {
    findings = append(findings, model.Finding{
        Type:       model.FindingDNSInconsistent,
        Layer:      model.LayerDNS,
        Confidence: model.ConfidenceLow,
        Evidence:   []string{"resolver answer sets differ"},
        ObservedAt: now,
    })
}
```

**Per-RCODE finding generation** (new function, pattern from RESEARCH.md lines 489-528):
```go
func dnsRcodeFindings(observations []model.DNSObservation, now time.Time) []model.Finding {
    var findings []model.Finding
    for _, obs := range observations {
        if obs.RCode != "NOERROR" && obs.RCode != "" {
            findings = append(findings, model.Finding{
                Type:       rcodeFindingType(obs.RCode),
                Layer:      model.LayerDNS,
                Confidence: rcodeConfidence(obs.RCode),
                Evidence:   []string{fmt.Sprintf("%s returned %s for %s", obs.Resolver, obs.RCode, obs.Query)},
                ObservedAt: now,
            })
        }
    }
    return findings
}
```

**Transparent proxy detection** (new function):
Check if any DNS observation's answers contain an IP that differs from the configured resolver server address.
Only applicable when the probe sent a whoami.akamai.net query. Compare resolved IP vs `resolver.Server`.
High confidence when IPs differ, medium when the DNS query itself failed.

**Call within `Classify()`:** Add `findings = append(findings, dnsRcodeFindings(dnsObs, now)...)` after existing
DNS checks (around line 41) and transparent proxy detection after that.

---

### `internal/targets/targets.go` (modified, config, CRUD)

**Analog:** Current `internal/targets/targets.go` (lines 95-105)

**Extended resolver list** (add to `BuiltinResolvers()` around line 95):
```go
func BuiltinResolvers() []model.Resolver {
    return []model.Resolver{
        {Name: "system", System: true},
        {Name: "cloudflare", Server: "1.1.1.1:53", Transport: "udp"},
        {Name: "google", Server: "8.8.8.8:53", Transport: "udp"},
        {Name: "quad9", Server: "9.9.9.9:53", Transport: "udp"},
        {Name: "cloudflare-ipv6", Server: "[2606:4700:4700::1111]:53", Transport: "udp"},
        {Name: "google-ipv6", Server: "[2001:4860:4860::8888]:53", Transport: "udp"},
        {Name: "quad9-ipv6", Server: "[2620:fe::fe]:53", Transport: "udp"},
        {Name: "cloudflare-doh", Server: "1.1.1.1", Transport: "https"},
        {Name: "google-doh", Server: "dns.google", Transport: "https"},
        {Name: "cloudflare-dot", Server: "1.1.1.1", Transport: "tcp-tls"},
        {Name: "google-dot", Server: "dns.google", Transport: "tcp-tls"},
    }
}
```

**Transport detection function** (new, for parsing user-provided resolver URLs):
```go
func DetectTransport(server string) string {
    if strings.HasPrefix(server, "https://") {
        return "https"
    }
    if strings.HasPrefix(server, "tls://") {
        return "tcp-tls"
    }
    return "udp"
}
```

---

### `cmd/iscan/main.go` (modified, config, request-response)

**Analog:** Current `cmd/iscan/main.go` (lines 30-139)

**CLI flag pattern** (existing pattern lines 97-105 -- add new flags):
```go
scanCmd.Flags().IntVar(&dnsRateLimit, "dns-rate-limit", 20, "max DNS queries/sec per resolver")
```

**ScanOptions wiring** (existing pattern lines 56-63 -- add DNSRateLimit to the struct literal):
```go
scan := scanner.Run(ctx, model.ScanOptions{
    Timeout:     timeout,
    Retries:     retries,
    Trace:       trace,
    QUIC:        quic,
    ICMPPing:    icmpPing,
    TargetSet:   targetSet,
    DNSRateLimit: dnsRateLimit,
})
```

---

### `internal/probe/dnsprobe/doh_test.go`, `dot_test.go` (new, test)

**Analog:** `internal/probe/dnsprobe/dns_test.go` (lines 1-154)

**Test structure pattern** (from dns_test.go lines 16-28):
```go
func TestProbeDoH(t *testing.T) {
    server := startHTTPDoHServer(t) // local HTTP server handling application/dns-message
    observation := dnsprobe.Probe(context.Background(), model.Resolver{
        Name: "local", Server: server, Transport: "https",
    }, "example.com", mdns.TypeA, 2*time.Second)

    if !observation.Success {
        t.Fatalf("expected DoH success, got %#v", observation)
    }
    if observation.RCode != "NOERROR" {
        t.Fatalf("expected NOERROR, got %#v", observation)
    }
}
```

**Server helper pattern** (from dns_test.go lines 73-120):
Create a local test server (HTTP for DoH, TCP+TLS for DoT) that returns a known response.
Register with `t.Cleanup()` for teardown. The DoH test server uses `net/http/httptest`.
The DoT test server uses a local TLS listener with miekg/dns server.

---

### `internal/probe/dnsprobe/ratelimit_test.go` (new, test)

**Analog:** Go standard table-driven test pattern (as in `internal/model/errors_test.go` lines 9-27)

**Rate limiter test pattern (from RESEARCH.md lines 656-663):**
```go
func TestRateLimiterBlocksBelowLimit(t *testing.T) {
    // Create rate limiter at 100 qps, burst 1
    // First call succeeds immediately
    // Second call blocks (waits for next token)
    // Call with cancelled context returns immediately with error
}
```

Use table-driven tests with `t.Run()` subtests, matching the codebase convention seen in
`internal/model/errors_test.go` lines 29-52.

---

### `internal/classifier/classifier_test.go` (modified, test)

**Analog:** Current `internal/classifier/classifier_test.go` (lines 1-155)

**Existing test patterns to replicate** (lines 10-27):
```go
func TestClassifyReportsDNSRCODE_NXDOMAIN(t *testing.T) {
    result := model.TargetResult{
        Target: model.Target{Name: "example", Domain: "example.com"},
        Results: []model.ProbeResult{
            {Layer: model.LayerDNS, Data: model.DNSObservation{
                Resolver: "system", RCode: "NXDOMAIN", Success: false,
            }},
        },
    }
    findings := classifier.Classify(result)
    if !hasFinding(findings, model.FindingDNSNXDOMAIN) {
        t.Fatalf("expected dns_nxdomain finding, got %#v", findings)
    }
}
```

Helper functions `hasFinding` and `getFinding` (lines 143-155) should be reused for the new finding types.

---

## Shared Patterns

### Probe Interface + Adapter + init() Registration

**Source:** `internal/probe/probe.go` (lines 9-27), `internal/probe/dnsprobe/adapter.go` (lines 49-56)
**Apply to:** All probe files (doh.go, dot.go, modified dns.go, modified adapter.go)

Every probe in the codebase follows this pattern:
1. Define an `Opts` struct for configuration
2. Define an `Adapter` struct wrapping the opts
3. Implement `Run(ctx, target) ProbeResult` that calls the probe function
4. Register in `probe.Registry` via `init()`

The DNS adapter is unique in that it iterates over multiple resolvers. Keep the single-registry-slot approach
by returning a single `ProbeResult` that contains all resolver observations, or by changing `Run()` to loop
internally and aggregate observations.

### DNSObservation Construction

**Source:** `internal/probe/dnsprobe/dns.go` (lines 14-20, 30-38)
**Apply to:** All DNS probe functions (doh.go, dot.go, system resolver in dns.go)

Every DNS probe function:
- Creates `model.DNSObservation{Resolver: ..., Query: ..., Type: ...}` upfront
- Sets `msg.SetEdns0(1232, false)` for EDNS0 support
- Records `observation.Latency = time.Since(start)` after the exchange
- Sets `observation.RCode = mdns.RcodeToString[resp.Rcode]` and `observation.Success = ...` on success
- Sets `observation.Error = err.Error()` and returns on failure

### Error Handling

**Source:** All probe files (dns.go line 33-35, tlsprobe/tls.go lines 27-35, quicprobe/quic.go lines 37-43)
**Apply to:** All new probe functions (doh.go, dot.go, system resolver)

Standard pattern: check error immediately after the network call, set `observation.Error = err.Error()`,
set `observation.Success = false` implicitly (zero value), return the observation. No panics, no `log.Fatal`.

### Answer Parsing

**Source:** `internal/probe/dnsprobe/dns.go` (lines 39-48)
**Apply to:** DoH response parsing, DoT response parsing

```go
for _, answer := range resp.Answer {
    switch rr := answer.(type) {
    case *mdns.A:
        observation.Answers = append(observation.Answers, rr.A.String())
    case *mdns.AAAA:
        observation.Answers = append(observation.Answers, rr.AAAA.String())
    case *mdns.CNAME:
        observation.CNAMEs = append(observation.CNAMEs, rr.Target)
    }
}
```

### TLS with InsecureSkipVerify

**Source:** `internal/probe/tlsprobe/tls.go` (lines 19-23), `internal/probe/quicprobe/quic.go` (lines 24-28)
**Apply to:** DoT client (dot.go)

All probes in the codebase use `InsecureSkipVerify: true` for diagnostic TLS connections. The DoT client
must follow this same convention.

### Finding Emission in Classifier

**Source:** `internal/classifier/classifier.go` (lines 24-31)
**Apply to:** Per-RCODE findings, transparent proxy detection

Every finding follows the same struct literal pattern:
```go
findings = append(findings, model.Finding{
    Type:       model.FindingType,
    Layer:      model.LayerDNS,
    Confidence: model.ConfidenceHigh, // varies per RCODE
    Evidence:   []string{"descriptive string"},
    ObservedAt: now,
})
```

### Table-Driven Tests

**Source:** `internal/model/errors_test.go` (lines 9-52)
**Apply to:** Rate limiter tests, model validation tests

Use `t.Run()` subtests for table-driven tests:
```go
cases := []struct {
    name string
    ...
}{
    {"case 1", ...},
    {"case 2", ...},
}
for _, c := range cases {
    t.Run(c.name, func(t *testing.T) {
        // test body
    })
}
```

### Test Server Helpers with t.Cleanup

**Source:** `internal/probe/dnsprobe/dns_test.go` (lines 73-120)
**Apply to:** DoH and DoT tests

Each test file defines a `start*Server(t *testing.T) string` helper that:
1. Creates the server on a random port (`:0`)
2. Starts it in a goroutine
3. Registers shutdown with `t.Cleanup()`
4. Returns the local address string

---

## No Analog Found

All files have either an exact or role-match analog in the codebase. No files lack a close match.

| File | Role | Data Flow | Reason |
|---|---|---|---|
| (none) | -- | -- | All files have close existing analogs |

## Metadata

**Analog search scope:**
- `/Users/yiwei/iscan/internal/probe/dnsprobe/` -- DNS probe files (dns.go, adapter.go, dns_test.go)
- `/Users/yiwei/iscan/internal/probe/middleware/` -- Middleware patterns (retry.go, logging.go, timeout.go, chain.go)
- `/Users/yiwei/iscan/internal/probe/httpprobe/` -- HTTP client pattern (http.go, adapter.go)
- `/Users/yiwei/iscan/internal/probe/tlsprobe/` -- TLS config pattern (tls.go, adapter.go)
- `/Users/yiwei/iscan/internal/probe/quicprobe/` -- QUIC adapter pattern (quic.go, adapter.go)
- `/Users/yiwei/iscan/internal/probe/probe.go` -- Probe interface and registry
- `/Users/yiwei/iscan/internal/model/` -- Type definitions (model.go, errors.go, errors_test.go)
- `/Users/yiwei/iscan/internal/classifier/` -- Classifier logic (classifier.go, classifier_test.go)
- `/Users/yiwei/iscan/internal/targets/` -- Target/resolver configuration (targets.go)
- `/Users/yiwei/iscan/internal/scanner/` -- Scanner and test infrastructure (scanner.go, scanner_test.go)
- `/Users/yiwei/iscan/cmd/iscan/main.go` -- CLI flags and commands

**Files scanned:** 22 source files + 7 test files (29 total)
**Pattern extraction date:** 2026-04-26
