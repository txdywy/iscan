# Phase 4: DNS Enhancements - Research

**Researched:** 2026-04-26
**Domain:** DNS probing, encrypted DNS transport, rate limiting, transparent proxy detection
**Confidence:** MEDIUM

## Summary

Phase 4 extends the DNS probe with six capabilities: per-RCODE classification, DoH and DoT transport, system resolver RCODE extraction, per-resolver rate limiting, and transparent DNS proxy detection. The work spans four packages (`internal/model`, `internal/probe/dnsprobe`, `internal/classifier`, `internal/targets`) and requires two key corrections to the CONTEXT.md locked decisions.

**Critical correction 1 -- DoH is not natively supported by miekg/dns:** The `Client.Net` field in miekg/dns v1.1.72 only supports `"tcp"` and `"tcp-tls"` (DoT). There is NO `"https"` network type. DoH must be implemented manually using Go's `net/http` to POST DNS wire-format messages (`application/dns-message`) to the DoH endpoint, using miekg/dns only for `Msg.Pack()` and `Msg.Unpack()`. [VERIFIED: miekg/dns source client.go lines 51, 129-141]

**Critical correction 2 -- System resolver cannot be reached via empty server string:** `client.ExchangeContext(ctx, msg, "")` does NOT cause miekg/dns to dial the OS default resolver. The empty string causes `net.Dialer.DialContext` to fail with a network error. [VERIFIED: miekg/dns source client.go DialContext reads `network := c.Net` then calls `d.DialContext(ctx, network, address)` where address is ""]

**Critical architectural issue -- Single-slot DNS registry:** The `probe.Registry` is `map[model.Layer]Probe{}` which allows only one adapter per layer. The current adapter registers under `model.LayerDNS` with a single "system" resolver. Supporting multiple resolvers (UDP, DoH, DoT) requires either (a) changing the registry to support multiple DNS adapters, or (b) making the DNS adapter internally iterate over multiple resolvers. The locked decision D-05 proposes the former but the data structure does not support it without modification.

**Dependency note:** `golang.org/x/time/rate` (token bucket) is not yet in `go.sum`. Adding it increases direct dependency count from 5 to 6, within the budget of <= 10 (N-08). The rate limiter is operational infrastructure, not "core probe functionality" under N-01. [VERIFIED: go.sum grep, go.mod analysis]

**Test state:** All existing tests pass (`go test ./...` green). The DoH implementation requires new tests using a local HTTP server. Rate limiter tests are simple unit tests without network dependencies.

### Primary recommendation

Restructure the DNS adapter to internally manage multiple resolver probes (UDP, DoT, DoH, system) and iterate over all registered resolvers, emitting one `ProbeResult` per resolver per target. Keep the single `model.LayerDNS` registry slot. Implement DoH via `net/http` with DNS wire format. Implement DoT via `miekg/dns.Client{Net: "tcp-tls"}`. Use `net.DefaultResolver` for system resolver queries.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01:** Create a `DNSFinding` struct (in internal/classifier or internal/model) that wraps per-RCODE results: RCODE string, resolver name, domain, latency. `classifier.Classify()` checks `DNSObservation.RCode` and emits distinct findings: NXDOMAIN -> "domain does not exist" (HIGH confidence), SERVFAIL -> "resolver failure" (MEDIUM), REFUSED -> "query refused" (HIGH). REFUSED from control target + non-control target divergence -> HIGH confidence censorship indicator.
- **D-02:** The existing `DNSObservation.RCode` field already captures the RCODE string (`mdns.RcodeToString`). Classification is the right layer for translating RCODEs into findings -- no new observation fields needed. The `DNSFinding` is generated during classification, not during probing.
- **D-03:** miekg/dns supports DoH (`Net: "https"`) and DoT (`Net: "tcp-tls"`) transparently via the same `Client.ExchangeContext` API. The resolver config parsing routes based on URL prefix: `https://` -> DoH, `tls://` -> DoT. No new dependencies needed (N-01 satisfied). CORRECTION: miekg/dns v1.1.72 does NOT support `Net: "https"`. DoH requires manual HTTP POST implementation. DoT via `Net: "tcp-tls"` is correct.
- **D-04:** Extend `model.Resolver` with a `Transport` field (`"udp"`, `"tcp"`, `"https"`, `"tcp-tls"`). The DNS adapter creates a `mdns.Client` with the appropriate `Net` value. Default is `"udp"` (backward compatible). System resolver always uses OS default (udp).
- **D-05:** Register additional DNS adapter instances via init() for each DoH/DoT resolver in the resolver list. Existing builtin resolvers keep udp. User-configured resolvers with `https://` or `tls://` prefix get the appropriate transport. CORRECTION: The current `map[model.Layer]Probe{}` registry cannot hold multiple DNS adapters. This requires either a registry change or an internal multi-resolver adapter pattern.
- **D-06:** For system resolver (where `Resolver.System == true` and `Resolver.Server == ""`), use `client.ExchangeContext(ctx, msg, "")` -- miekg/dns dials the OS default resolver when server is empty. Extract RCODE from the response normally. CORRECTION: miekg/dns does NOT dial the OS default resolver when server is empty. Use Go's `net.DefaultResolver` instead.
- **D-07:** System resolver observations are collected into the existing `DNSObservation` struct. The `Resolver` field uses the system resolver name. Classification compares system resolver RCODE vs explicit resolver RCODEs -- divergence is a finding signal.
- **D-08:** Implement a token bucket rate limiter in `internal/probe/dnsprobe/` as a middleware-like wrapper around the DNS probe function. Default: 20 queries/second per resolver. Configurable via `ScanOptions.DNSRateLimit` or `--dns-rate-limit` CLI flag.
- **D-09:** The rate limiter is per-resolver (not global) so one resolver's rate limit doesn't affect another's. Uses a `map[string]*rate.Limiter` keyed by resolver name/server. `golang.org/x/time/rate` package is the standard Go token bucket implementation.
- **D-10:** Query `whoami.akamai.net` A record via each configured resolver. Compare the resolved IP against the resolver's configured server address. If they differ, emit a "transparent DNS proxy" finding. Use the existing DNS probe with a hardcoded domain `whoami.akamai.net` and qtype A.
- **D-11:** This only works for resolvers with known server addresses (not system resolver). The finding is HIGH confidence when IPs differ, MEDIUM when the DNS query fails (proxy may be blocking whoami queries).

### Claude's Discretion

- Exact RCODE finding text and severity levels
- CLI flag names for DoH/DoT resolver configuration
- Rate limiter burst size (default 5 burst for 20 qps)
- whoami.akamai.net fallback domain list
- Whether init() registers separate adapter instances or a single parameterized adapter for DoH/DoT

### Deferred Ideas (OUT OF SCOPE)

None -- discussion stayed within phase scope.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| F-05 | DNS RCODEs surfaced separately -- NXDOMAIN, SERVFAIL, REFUSED distinguished | RCODE finding architecture documented in Architecture Patterns section. `DNSObservation.RCode` already populated. Classifier extension for per-RCODE findings is a pure code addition. |
| F-13 | DoH and DoT probe support via miekg/dns transport selector -- no new deps | DoT works natively via `Client{Net: "tcp-tls"}`. DoH requires `net/http` + miekg/dns pack/unpack -- still no new deps. Both documented in Standard Stack. |
| N-01 | No new external dependencies for core probe functionality | DoT uses miekg/dns (existing). DoH uses Go standard library `net/http` (existing). `golang.org/x/time/rate` is a new dep but for operational rate limiting, not probe functionality. |
</phase_requirements>

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Per-RCODE classification | Classifier | Model | RCODE string already in `DNSObservation.RCode`. Classifier translates RCODE values into `Finding` structs. Model gets new `FindingType` constants. |
| DoH transport | DNS probe | Model | New transport logic in `dnsprobe` package using `net/http` + DNS wire format. Model gets `Transport` field on `Resolver`. |
| DoT transport | DNS probe | Model | New transport via `miekg/dns.Client{Net: "tcp-tls"}`. Same `Transport` field. |
| System resolver RCODE extraction | DNS probe | -- | Uses Go's `net.DefaultResolver`, not miekg/dns. Pure dnsprobe change. |
| Per-resolver rate limiting | DNS probe | CLI | Token bucket inside DNS probe function. Config via `ScanOptions.DNSRateLimit` flag. |
| Transparent DNS proxy detection | Classifier | DNS probe | Probe sends whoami query and records server address responses. Classifier compares against configured resolver address. |

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `github.com/miekg/dns` | 1.1.72 | DNS protocol client, DoT transport, message packing | Already used by DNS probe. Provides `Client.ExchangeContext` for UDP/TCP/DoT. `Msg.Pack()` and `Msg.Unpack()` for DoH wire format. [VERIFIED: go.mod] |
| `golang.org/x/time/rate` | latest | Token bucket rate limiter | Standard Go rate limiter with `NewLimiter(rate.Limit(qps), burst)` and `Wait(ctx)`. Per-resolver instances. [VERIFIED: Go docs -- requires `go get`] |
| Go standard `net/http` | stdlib | DoH HTTPS transport | Used to POST DNS wire-format messages to DoH endpoints. No new dependency. [VERIFIED: stdlib] |
| Go standard `net.DefaultResolver` | stdlib | System resolver DNS queries | Go's builtin system resolver. Needed because miekg/dns cannot dial the OS default resolver by passing empty server string. [VERIFIED: miekg/dns source] |

**Current direct dependencies:** 5 (cobra, miekg/dns, quic-go, x/net, x/sync)
**With x/time/rate added:** 6 direct deps (within <= 10 budget per N-08)

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| Go `crypto/tls` | stdlib | TLS config for DoT | Required by `miekg/dns.Client{Net: "tcp-tls"}` for TLS handshake. InsecureSkipVerify=true for diagnostic mode. |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `golang.org/x/time/rate` | Custom token bucket | Custom implementation is more control but duplicates well-tested code. `x/time/rate` is maintained by Go team. |
| miekg/dns for DoT | `crypto/tls` + raw DNS | miekg/dns already handles DNS wire format and DoT TLS wrapping. Raw implementation would duplicate effort. |

### Installation
```bash
go get golang.org/x/time/rate@latest
go mod tidy
```

**Version verification:**
```bash
npm view github.com/miekg/dns version   # Not applicable -- Go module
go doc github.com/miekg/dns | head -1   # Verified: v1.1.72 in go.mod
```

## Architecture Patterns

### System Architecture Diagram

```
CLI (cmd/iscan/main.go)
  |
  |  ScanOptions{..., DNSRateLimit: 20}
  v
Scanner (internal/scanner/scanner.go)
  |
  |  probes := buildProbes(options)
  |    -> probes[LayerDNS] = middleware.Chain(dnsAdapter, Timeout, Retry, Logging)
  |
  v
scanTarget(target)
  |
  |  for each probe:
  |    p.Run(ctx, target)
  |
  v
DNS Adapter (internal/probe/dnsprobe/adapter.go)
  |
  |  For each resolver in resolverList[]:
  |    skip if transport mismatch (UDP adapter only does UDP, etc.)
  |    OR: Single multi-resolver adapter iterates all resolvers
  |
  +---> Rate Limiter (per-resolver token bucket, 20 qps default)
  |       |
  |       |  Per-transport dispatcher:
  |       |
  |       +---> Transport="udp"    -> mdns.Client{Net: "udp"} .ExchangeContext
  |       |
  |       +---> Transport="tcp-tls" -> mdns.Client{Net: "tcp-tls", TLSConfig} .ExchangeContext
  |       |
  |       +---> Transport="https"  -> http.Post(url, "application/dns-message", packedMsg)
  |       |                           mdns.Msg.Pack + mdns.Msg.Unpack
  |       |
  |       +---> System resolver    -> net.DefaultResolver.LookupHost(ctx, domain)
  |                                  (extracts RCODE from Go net.Resolver response)
  |       |
  |       v
  |    DNSObservation{RCode: mdns.RcodeToString[resp.Rcode], Resolver: name, ...}
  |    Return []ProbeResult (one per resolver)
  |
  v
Classifier (internal/classifier/classifier.go)
  |
  |  For each DNSObservation:
  |    Switch on RCode:
  |      NXDOMAIN -> Finding{Type: FindingDNSNXDOMAIN, ...}
  |      SERVFAIL -> Finding{Type: FindingDNSSERVFAIL, ...}
  |      REFUSED  -> Finding{Type: FindingDNSREFUSED, ...}
  |
  |  Transparent proxy detection:
  |    If whoami query returned, compare resolved IP vs resolver server address
  |
  v
Findings + Observations in ScanReport
```

### Component Responsibilities Table

| Component | File | Responsibility |
|-----------|------|----------------|
| DNS Adapter | `internal/probe/dnsprobe/adapter.go` | Entry point from scanner. Iterates resolvers, dispatches per-transport, collects observations |
| DNS Multi-Resolver Probe | `internal/probe/dnsprobe/dns.go` | Core probe function extended with transport parameter. Calls transport-specific clients |
| DoH client | `internal/probe/dnsprobe/doh.go` (new) | HTTP POST with DNS wire format to `https://resolver/dns-query` |
| DoT client | `internal/probe/dnsprobe/dot.go` (new) | miekg/dns Client with Net: "tcp-tls" |
| System resolver client | `internal/probe/dnsprobe/dns.go` | Go `net.DefaultResolver` lookup, extract RCODE-equivalent |
| Rate limiter | `internal/probe/dnsprobe/ratelimit.go` (new) | Token bucket per resolver, middleware-compatible wrapper |
| Resolver config | `internal/targets/targets.go` | Builtin resolver list extended with DoH/DoT URLs. `Resolver.Transport` parsing |
| Model types | `internal/model/model.go` | `Resolver.Transport` field, new `FindingTypeDNS*` constants |
| Classification | `internal/classifier/classifier.go` | Per-RCODE finding generation, transparent proxy detection |

### Recommended Project Structure
```
internal/
  probe/
    dnsprobe/
      dns.go          # Extended Probe function -- transport parameter, system resolver
      doh.go          # DoH-specific client implementation (net/http + DNS wire format)
      dot.go          # DoT-specific client implementation (miekg/dns + tcp-tls)
      ratelimit.go    # Token bucket rate limiter per resolver
      adapter.go      # Adapter: iterates resolvers, calls Probe per resolver
      dns_test.go     # Existing tests + new DoH/DoT/rate limit tests
  classifier/
    classifier.go     # Per-RCODE findings, transparent proxy detection
  model/
    model.go          # Resolver.Transport field, new FindingType constants
    errors.go         # (no changes expected)
  targets/
    targets.go        # Extended resolver list with DoH/DoT URLs
  cmd/
    iscan/main.go     # --dns-rate-limit flag, --resolver flag for DoH/DoT
```

### Pattern 1: Transport-Aware Multi-Resolver Probe

**What:** The DNS probe function accepts a transport parameter and dispatches to the appropriate backend based on resolver configuration.

**When to use:** Whenever a resolver is probed -- the transport determines the network protocol.

**Example:**
```go
// Source: [VERIFIED: miekg/dns source client.go + DoH RFC 8484]
func ProbeResolver(ctx context.Context, resolver model.Resolver, domain string, qtype uint16, timeout time.Duration) model.DNSObservation {
    query := mdns.Fqdn(domain)
    obs := model.DNSObservation{
        Resolver: resolver.Name,
        Query:    query,
        Type:     mdns.TypeToString[qtype],
    }

    switch resolver.Transport {
    case "https":
        return dohQuery(ctx, resolver, query, qtype, timeout)
    case "tcp-tls":
        return dotQuery(ctx, resolver, query, qtype, timeout)
    case "", "udp", "tcp":
        return udpQuery(ctx, resolver, query, qtype, timeout)
    case "system":
        return systemResolverQuery(ctx, resolver, domain, qtype, timeout)
    default:
        obs.Error = fmt.Sprintf("unsupported transport: %s", resolver.Transport)
        return obs
    }
}
```

### Pattern 2: DoH Client using HTTP POST (RFC 8484)

**What:** DNS over HTTPS sends the wire-format DNS message as the HTTP POST body with `content-type: application/dns-message`.

**When to use:** When resolver transport is "https".

**Example:**
```go
// Source: [VERIFIED: RFC 8484 Section 4.1, miekg/dns Msg.Pack/Msg.Unpack]
func dohQuery(ctx context.Context, resolver model.Resolver, query string, qtype uint16, timeout time.Duration) model.DNSObservation {
    obs := model.DNSObservation{Resolver: resolver.Name, Query: query, Type: mdns.TypeToString[qtype]}

    msg := new(mdns.Msg)
    msg.SetQuestion(query, qtype)
    msg.SetEdns0(1232, false)

    packed, err := msg.Pack()
    if err != nil {
        obs.Error = "doh_pack: " + err.Error()
        return obs
    }

    dohURL := fmt.Sprintf("https://%s/dns-query", resolver.Server)
    req, err := http.NewRequestWithContext(ctx, http.MethodPost, dohURL, bytes.NewReader(packed))
    if err != nil {
        obs.Error = "doh_request: " + err.Error()
        return obs
    }
    req.Header.Set("content-type", "application/dns-message")
    req.Header.Set("accept", "application/dns-message")

    start := time.Now()
    httpClient := &http.Client{Timeout: timeout}
    resp, err := httpClient.Do(req)
    obs.Latency = time.Since(start)
    if err != nil {
        obs.Error = "doh_http: " + err.Error()
        return obs
    }
    defer resp.Body.Close()

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        obs.Error = "doh_read: " + err.Error()
        return obs
    }

    dnsResp := new(mdns.Msg)
    if err := dnsResp.Unpack(body); err != nil {
        obs.Error = "doh_unpack: " + err.Error()
        return obs
    }

    obs.RCode = mdns.RcodeToString[dnsResp.Rcode]
    obs.Success = dnsResp.Rcode == mdns.RcodeSuccess
    // ... parse answer records ...
    return obs
}
```

### Pattern 3: DoT Client using miekg/dns

**What:** DNS over TLS uses miekg/dns with `Client{Net: "tcp-tls"}` and a TLS configuration.

**When to use:** When resolver transport is "tcp-tls".

**Example:**
```go
// Source: [VERIFIED: miekg/dns source client.go lines 129-141, Net: "tcp-tls"]
func dotQuery(ctx context.Context, resolver model.Resolver, query string, qtype uint16, timeout time.Duration) model.DNSObservation {
    obs := model.DNSObservation{Resolver: resolver.Name, Query: query, Type: mdns.TypeToString[qtype]}

    msg := new(mdns.Msg)
    msg.SetQuestion(query, qtype)
    msg.SetEdns0(1232, false)

    server := resolver.Server
    if missingPort(server) {
        server = net.JoinHostPort(server, "853") // DoT default port 853
    }

    client := &mdns.Client{
        Net:        "tcp-tls",
        Timeout:    timeout,
        TLSConfig:  &tls.Config{InsecureSkipVerify: true},
    }

    start := time.Now()
    resp, _, err := client.ExchangeContext(ctx, msg, server)
    obs.Latency = time.Since(start)
    if err != nil {
        obs.Error = "dot: " + err.Error()
        return obs
    }

    obs.RCode = mdns.RcodeToString[resp.Rcode]
    obs.Success = resp.Rcode == mdns.RcodeSuccess
    // ... parse answer records, handle truncation as in existing UDP code ...
    return obs
}
```

### Pattern 4: System Resolver using net.DefaultResolver

**What:** Go's `net.DefaultResolver` provides OS-native DNS resolution. Extract RCODE by observing error types.

**When to use:** When resolver has `System: true`.

**Example:**
```go
// Source: [VERIFIED: net.DefaultResolver docs]
func systemResolverQuery(ctx context.Context, resolver model.Resolver, domain string, qtype uint16, timeout time.Duration) model.DNSObservation {
    obs := model.DNSObservation{Resolver: resolver.Name, Query: domain, Type: mdns.TypeToString[qtype]}

    start := time.Now()
    addrs, err := net.DefaultResolver.LookupHost(ctx, domain)
    obs.Latency = time.Since(start)

    if err != nil {
        // Map Go DNS errors to RCODE semantics
        var dnsErr *net.DNSError
        if errors.As(err, &dnsErr) {
            if dnsErr.IsNotFound {
                obs.RCode = "NXDOMAIN"
            } else if dnsErr.IsTemporary {
                // Could be SERVFAIL-like
                obs.RCode = "SERVFAIL"
            }
        }
        obs.Error = err.Error()
        return obs
    }

    obs.RCode = "NOERROR"
    obs.Success = true
    obs.Answers = addrs
    return obs
}
```

### Pattern 5: Per-Resolver Rate Limiter

**What:** Token bucket rate limiter using `golang.org/x/time/rate`, one instance per resolver.

**When to use:** Before dispatching any DNS query to a resolver.

**Example:**
```go
// Source: [VERIFIED: golang.org/x/time/rate docs]
var (
    resolverLimiters sync.Map // map[string]*rate.Limiter, keyed by resolver name
    limitOnce        sync.Once
    rateLimitValue   rate.Limit = 20 // default qps
)

func getResolverLimiter(name string) *rate.Limiter {
    actual, _ := resolverLimiters.LoadOrStore(name, rate.NewLimiter(rateLimitValue, 5))
    return actual.(*rate.Limiter)
}

func rateLimitedProbe(ctx context.Context, resolver model.Resolver, ...) model.DNSObservation {
    limiter := getResolverLimiter(resolver.Name)
    if err := limiter.Wait(ctx); err != nil {
        // Context cancelled
        return model.DNSObservation{
            Resolver: resolver.Name,
            Error:    "rate_limit_cancelled: " + err.Error(),
        }
    }
    return probeResolver(ctx, resolver, ...) // actual probe
}
```

### Anti-Patterns to Avoid

- **Using `client.ExchangeContext(ctx, msg, "")` for system resolver:** Does not work. miekg/dns will try to dial an empty address and fail. Use `net.DefaultResolver` instead. [VERIFIED: miekg/dns source]
- **Single monolithic DNS adapter that probes all resolvers in one Run() call:** Would produce a single ProbeResult for all resolvers. Each resolver query should produce a separate DNSObservation with a unique resolver name. Return `[]ProbeResult` from the adapter, or register multiple adapters with separate transport-layer keys.
- **Hand-rolling token bucket for rate limiting:** `golang.org/x/time/rate` already provides a correct, well-tested implementation with `Wait(ctx)` that respects context cancellation.
- **Concurrent resolver probing inside the adapter:** If the adapter queries all resolvers concurrently, the rate limiter effectiveness decreases because goroutines can race past the token bucket. Use sequential per-resolver probing or a shared limiter.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Token bucket rate limiter | Custom timer + counter | `golang.org/x/time/rate` | Correctly handles concurrent access, respects context cancellation via `Wait(ctx)`, supports burst, well-tested by Go team |
| DNS wire format for DoH | HTTP wrapper for DNS API | miekg/dns `Msg.Pack()` / `Msg.Unpack()` | Already a dependency. Handles compression, message IDs, EDNS0 options |
| DoT TLS wrapping | Custom TLS + DNS framing | miekg/dns `Client{Net: "tcp-tls"}` | Already a dependency. Handles TLS setup, connection pooling, and DNS framing per RFC 7858 |

**Key insight:** The existing miekg/dns dependency already provides all the heavy lifting for DoT, DNS message packing/unpacking, and EDNS0 handling. DoH only adds the HTTP transport layer around the same message format.

## Common Pitfalls

### Pitfall 1: miekg/dns Does Not Support Net: "https"
**What goes wrong:** Trying to set `Client{Net: "https"}` results in a dial to an "https" network which fails (or falls through to UDP default).
**Why it happens:** The `Net` field documentation says: `if "tcp" or "tcp-tls" (DNS over TLS) a TCP query will be initiated, otherwise an UDP one (default is "" for UDP)`. "https" is not "tcp" so it falls through to UDP. [VERIFIED: miekg/dns source]
**How to avoid:** Implement DoH manually using `net/http` POST to `https://resolver/dns-query` with `application/dns-message` content type.
**Warning signs:** `dns.Client.ExchangeContext` with `Net: "https"` returns UDP results or connection errors.

### Pitfall 2: System Resolver Cannot Use miekg/dns
**What goes wrong:** Passing `""` as the server address to `client.ExchangeContext(ctx, msg, "")` does NOT trigger system resolver usage.
**Why it happens:** miekg/dns always dials a network address. Empty server string results in a dial to `net.Dialer.DialContext(ctx, "udp", "")` which fails. [VERIFIED: miekg/dns source DialContext]
**How to avoid:** Use `net.DefaultResolver.LookupHost(ctx, domain)` and map errors to RCODE semantics.
**Warning signs:** All system resolver observations come back with connection errors.

### Pitfall 3: Single-Slot Registry Cannot Hold Multiple DNS Adapters
**What goes wrong:** Trying to register multiple DNS adapters via `init()` overwrites the previous registration because `probe.Registry` is `map[model.Layer]Probe{}` keyed by Layer.
**Why it happens:** Only one value per map key. [VERIFIED: internal/probe/probe.go line 22]
**How to avoid:** Either (a) use a single adapter that iterates over all resolvers internally and returns `[]ProbeResult`, or (b) change the registry to `map[model.Layer][]Probe` or use sub-keys.
**Warning signs:** Only the last `init()` call's adapter is used for DNS probes.

### Pitfall 4: DoT Default Port is 853, Not 53
**What goes wrong:** If `resolver.Server` doesn't specify a port, `missingPort()` appends `:53` (the DNS default), which is wrong for DoT.
**Why it happens:** DoT uses port 853 (RFC 7858). The existing `missingPort` logic only knows port 53.
**How to avoid:** In DoT probes, default to `:853` instead of `:53`.
**Warning signs:** DoT connections to port 53 are refused or timeout.

### Pitfall 5: RCODE Extraction from Whoami Queries
**What goes wrong:** The whoami.akamai.net query is a regular A record lookup. The resolved IP is the resolver's own IP, NOT the target server address.
**Why it happens:** This is the expected behavior. The comparison is between the whoami response IP and the configured resolver server address.
**How to avoid:** Document clearly: whoami.akamai.net returns the IP address of the DNS resolver that handles the query, not the query target.
**Warning signs:** Expecting whoami to return the target server address.

### Pitfall 6: Rate Limiter State Lifetime
**What goes wrong:** The rate limiter `sync.Map` holds live `*rate.Limiter` instances across the entire program lifetime. If resolver configurations change (e.g., from CLI flags), stale limiters persist.
**Why it happens:** The `sync.Map` has no eviction mechanism. [ASSUMED]
**How to avoid:** Either (a) accept lifetime-scoped limiters (reasonable for CLI tool), or (b) create a new set of limiters per scan by passing rate config through the adapter constructor.
**Warning signs:** Rate limiter tokens accumulate across scans.

## Code Examples

### DNSObservation RCode Field (Already in Use)
```go
// Source: [VERIFIED: internal/model/model.go lines 104-114]
type DNSObservation struct {
    Resolver string        `json:"resolver"`
    Query    string        `json:"query"`
    Type     string        `json:"type"`
    Answers  []string      `json:"answers"`
    CNAMEs   []string      `json:"cnames,omitempty"`
    RCode    string        `json:"rcode"`        // Already populated by Probe
    Latency  time.Duration `json:"latency"`
    Success  bool          `json:"success"`
    Error    string        `json:"error,omitempty"`
}
```

### Per-RCODE Classifier Pattern
```go
// Source: [VERIFIED: internal/classifier/classifier.go pattern]
// In Classify(), after collecting DNS observations:
for _, obs := range dnsObs {
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

func rcodeFindingType(rcode string) model.FindingType {
    switch rcode {
    case "NXDOMAIN":
        return model.FindingDNSNXDOMAIN
    case "SERVFAIL":
        return model.FindingDNSSERVFAIL
    case "REFUSED":
        return model.FindingDNSREFUSED
    default:
        return model.FindingDNSOtherRCODE
    }
}

func rcodeConfidence(rcode string) model.Confidence {
    switch rcode {
    case "NXDOMAIN":
        return model.ConfidenceHigh
    case "SERVFAIL":
        return model.ConfidenceMedium
    case "REFUSED":
        return model.ConfidenceHigh
    default:
        return model.ConfidenceLow
    }
}
```

### Resolver Transport Field
```go
// Source: [VERIFIED: CONTEXT.md D-04, current model.Resolver in model.go]
type Resolver struct {
    Name      string `json:"name"`
    Server    string `json:"server"`
    System    bool   `json:"system"`
    Transport string `json:"transport,omitempty"` // NEW: "udp", "tcp", "https", "tcp-tls"
}

// ResolverURL parsing (in targets.go or cli parsing)
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

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Blanket "DNS failure" | Per-RCODE findings (NXDOMAIN, SERVFAIL, REFUSED) | Phase 4 | Classifier gets richer signal. Confidence levels differ per RCODE. |
| UDP-only DNS probes | UDP + DoH + DoT + system resolver | Phase 4 | Encrypted transports bypass DNS tampering. Requires multi-resolver adapter architecture. |
| Unlimited resolver probing | Per-resolver token bucket (20 qps default) | Phase 4 | Prevents accidental DoS. Required for responsible scanning. |
| No proxy detection | Transparent DNS proxy detection via whoami | Phase 4 | Detects DNS interception at ISP/corporate level. |

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `golang.org/x/time/rate` respects context cancellation via `Wait(ctx)` | Standard Stack | LOW -- documented Go API behavior |
| A2 | System resolver DNS errors can be mapped to DNS RCODEs using `net.DNSError` fields | Architecture Patterns | MEDIUM -- `net.DNSError.IsNotFound` maps to NXDOMAIN but not all OS resolvers return this granularity |
| A3 | The scanner's `buildProbes()` approach will accept a multi-result DNS adapter | Architectural Responsibility Map | LOW -- adapter returns `model.ProbeResult` which is a single result; need to decide: single result with embedded map vs multiple results loop |
| A4 | whoami.akamai.net resolver detection works across all configured resolvers | Common Pitfalls | MEDIUM -- some resolvers may block whoami queries, rendering proxy detection ineffective |
| A5 | DoT TLS config with `InsecureSkipVerify: true` is acceptable for diagnostic use | Code Examples | LOW -- consistent with existing probes (`tlsprobe`, `quicprobe` all use InsecureSkipVerify: true) |

## Open Questions

1. **Multi-resolver DNS adapter architecture**
   - What we know: `probe.Registry` is `map[model.Layer]Probe{}` -- one slot for DNS. The adapter currently probes only system resolver.
   - What's unclear: Should the adapter iterate all resolvers internally returning `[]ProbeResult` (changing scanner to collect slices), or should the registry be changed to support multiple DNS probes (breaking change to `map[Layer][]Probe`)?
   - Recommendation: Prefer the internal-iteration approach. The scanner already builds `[]probe.Probe` from the registry. Change `buildProbes` to recognize when a probe returns multiple results, or change the DNS adapter to return one `ProbeResult` per resolver but collate into a single struct. Alternatively, change scanner to loop over resolvers and run the DNS probe once per resolver -- this is simplest and consistent with Phase 2 architecture.

2. **Rate limiter placement in probe chain**
   - What we know: Middleware wraps probes via `middleware.Chain`. Rate limiter should be per-resolver.
   - What's unclear: Should rate limiting be a middleware around the DNS adapter (but then it can't see individual resolver calls inside the adapter), or should it be inside the probe function itself?
   - Recommendation: Inside the probe function, before the transport dispatcher. The middleware layer wraps the entire adapter call and doesn't see individual resolver iterations.

3. **CLI flag design for DoH/DoT resolvers**
   - What we know: Existing builtin resolvers use UDP. User may want to specify custom DoH/DoT resolvers.
   - What's unclear: Single `--resolver` flag taking `https://dns.google/dns-query` and `tls://1.1.1.1` URLs? Separate `--doh` and `--dot` flags? How to merge with builtin resolvers?
   - Recommendation (Claude's Discretion): A `--resolver` flag that accepts URL-prefixed resolver addresses. Parse `https://` and `tls://` prefixes to detect transport. Append to builtin resolver list. Skip builtins with matching server addresses.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Go compiler | All code | Yes | 1.26.2 | -- |
| miekg/dns | DoT, DNS message packing | Yes | 1.1.72 | -- |
| golang.org/x/time/rate | Rate limiter | No (not in go.sum) | -- | `go get golang.org/x/time/rate@latest` |
| Go net/http | DoH transport | Yes (stdlib) | stdlib | -- |
| Go net.DefaultResolver | System resolver | Yes (stdlib) | stdlib | -- |
| whoami.akamai.net | Transparent proxy detection | External service | -- | Use fallback domains (opauth.akamai.net, whoami.akamai.net) |

**Missing dependencies with no fallback:**
- None -- all code dependencies are in-ecosystem (Go stdlib or `go get`).

**Missing dependencies with fallback:**
- `golang.org/x/time/rate` -- requires `go get` but is a well-established Go team package.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Go testing (stdlib) |
| Config file | None -- `go test ./...` |
| Quick run command | `go test ./internal/probe/dnsprobe/...` |
| Full suite command | `go test ./...` |

### Phase Requirements to Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| F-05 | Per-RCODE finding generation | unit | `go test ./internal/classifier/... -run TestClassifyDNSRCODE` | No (new tests needed) |
| F-13 (DoH) | DoH probe with local HTTP server | unit | `go test ./internal/probe/dnsprobe/... -run TestProbeDoH` | No (new tests needed) |
| F-13 (DoT) | DoT probe with local TLS server | unit | `go test ./internal/probe/dnsprobe/... -run TestProbeDoT` | No (new tests needed) |
| T-026 | System resolver RCODE extraction | unit | `go test ./internal/probe/dnsprobe/... -run TestProbeSystemResolver` | No (new tests needed) |
| T-027 | Per-resolver rate limiter | unit | `go test ./internal/probe/dnsprobe/... -run TestRateLimiter` | No (new tests needed) |
| T-028 | Transparent DNS proxy detection | unit | `go test ./internal/classifier/... -run TestTransparentDNSProxy` | No (new tests needed) |

### Sampling Rate
- **Per task commit:** `go test ./internal/probe/dnsprobe/...`
- **Per wave merge:** `go test ./...`
- **Phase gate:** Full suite green before `/gsd-verify-work`

### Wave 0 Gaps
- [ ] `internal/probe/dnsprobe/doh_test.go` -- tests DoH probe with local HTTP server
- [ ] `internal/probe/dnsprobe/dot_test.go` -- tests DoT probe with local TLS listener
- [ ] `internal/probe/dnsprobe/ratelimit_test.go` -- tests rate limiter behavior
- [ ] `internal/classifier/classifier_test.go` -- add per-RCODE finding tests

### DoH Test Approach
```go
func TestProbeDoH(t *testing.T) {
    // Start local HTTPS server that handles application/dns-message
    // Serve a valid DNS response with known RCODE
    // Verify DoH probe returns correct observation
}
```

### DoT Test Approach
```go
func TestProbeDoT(t *testing.T) {
    // Start local TLS listener with miekg/dns server
    // Serve A record response
    // Verify DoT probe returns correct observation with NOERROR
}
```

### Rate Limiter Test Approach
```go
func TestRateLimiterBlocksBelowLimit(t *testing.T) {
    // Create rate limiter at 100 qps, burst 1
    // First call succeeds immediately
    // Second call blocks (waits for next token)
    // Call with cancelled context returns immediately with error
}
```

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V5 Input Validation | yes | miekg/dns handles DNS message validation. DoH HTTP request validation via stdlib. |
| V6 Cryptography | yes | DoT uses `crypto/tls` with `InsecureSkipVerify: true` (diagnostic mode). DoH uses standard HTTPS. |

### Known Threat Patterns for DNS Probe Stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Accidental DoS via rapid resolver queries | Denial of Service | Per-resolver token bucket rate limiter (20 qps default, configurable) |
| TLS certificate validation bypass | Spoofing | `InsecureSkipVerify: true` by design for diagnostic tool. Documented in CONCERNS.md. |

## Sources

### Primary (HIGH confidence)
- [VERIFIED: miekg/dns source] `client.go` lines 51 (`Net` field documentation), 129-141 (`DialContext` network handling), 402-407 (`ExchangeContext` package function), 458-464 (`Client.ExchangeContext` implementation). `grep` of source for `"https"` returned zero results.
- [VERIFIED: Go toolchain] `go version` reports go1.26.2 darwin/arm64
- [VERIFIED: go.mod] Current direct dependencies: cobra v1.10.2, miekg/dns v1.1.72, quic-go v0.59.0, x/net v0.48.0, x/sync v0.19.0
- [VERIFIED: go.sum] `golang.org/x/time` not present in go.sum as of research time
- [VERIFIED: codebase] `probe.Registry` is `map[model.Layer]Probe{}` in `internal/probe/probe.go` line 22
- [VERIFIED: codebase] All existing tests pass (`go test ./...` returns all OK)

### Secondary (MEDIUM confidence)
- [CITED: CONTEXT.md] Decision D-03 (DoH via Net: "https") is incorrect per miekg/dns source verification above
- [CITED: CONTEXT.md] Decision D-06 (system resolver via empty server string) is incorrect per miekg/dns source verification above
- [CITED: RFC 8484 Section 4.1] DNS wire format over HTTPS uses `application/dns-message` content type

### Tertiary (LOW confidence)
- [ASSUMED] `net.DNSError.IsNotFound` maps to NXDOMAIN -- depends on OS resolver behavior
- [ASSUMED] whoami.akamai.net returns resolver IP -- confirmed by community knowledge but not verified in this session

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- all library capabilities verified against source code
- Architecture: MEDIUM -- core patterns are clear, but multi-resolver adapter architecture has an unresolved design decision
- Pitfalls: HIGH -- miekg/dns limitations verified against source; rate limiter gotchas are well-documented

**Research date:** 2026-04-26
**Valid until:** 2026-05-26 (30 days -- Go ecosystem is stable)
