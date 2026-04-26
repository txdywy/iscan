# Phase 4: DNS Enhancements - Context

**Gathered:** 2026-04-27
**Status:** Ready for planning

<domain>
## Phase Boundary

DNS probing produces richer diagnostic signal with RCODE-specific findings, encrypted transport options (DoH, DoT), system resolver RCODE extraction, and per-resolver rate limiting. Adds transparent DNS proxy detection as a new finding type.

**Requirements addressed:** F-05 (DNS RCODEs surfaced separately), F-13 (DoH and DoT probe support via miekg/dns)
</domain>

<decisions>
## Implementation Decisions

### RCODE Handling Architecture
- **D-01:** Create a `DNSFinding` struct (in internal/classifier or internal/model) that wraps per-RCODE results: RCODE string, resolver name, domain, latency. `classifier.Classify()` checks `DNSObservation.RCode` and emits distinct findings: NXDOMAIN → "domain does not exist" (HIGH confidence), SERVFAIL → "resolver failure" (MEDIUM), REFUSED → "query refused" (HIGH). REFUSED from control target + non-control target divergence → HIGH confidence censorship indicator.
- **D-02:** The existing `DNSObservation.RCode` field already captures the RCODE string (`mdns.RcodeToString`). Classification is the right layer for translating RCODEs into findings — no new observation fields needed. The `DNSFinding` is generated during classification, not during probing.

### DoH/DoT Transport
- **D-03:** miekg/dns supports DoH (`Net: "https"`) and DoT (`Net: "tcp-tls"`) transparently via the same `Client.ExchangeContext` API. The resolver config parsing routes based on URL prefix: `https://` → DoH, `tls://` → DoT. No new dependencies needed (N-01 satisfied).
- **D-04:** Extend `model.Resolver` with a `Transport` field (`"udp"`, `"tcp"`, `"https"`, `"tcp-tls"`). The DNS adapter creates a `mdns.Client` with the appropriate `Net` value. Default is `"udp"` (backward compatible). System resolver always uses OS default (udp).
- **D-05:** Register additional DNS adapter instances via init() for each DoH/DoT resolver in the resolver list. Existing builtin resolvers keep udp. User-configured resolvers with `https://` or `tls://` prefix get the appropriate transport.

### System Resolver RCODE Extraction
- **D-06:** For system resolver (where `Resolver.System == true` and `Resolver.Server == ""`), use `client.ExchangeContext(ctx, msg, "")` — miekg/dns dials the OS default resolver when server is empty. Extract RCODE from the response normally. The system resolver RCODE is reported per-domain alongside explicit resolver results.
- **D-07:** System resolver observations are collected into the existing `DNSObservation` struct. The `Resolver` field uses the system resolver name. Classification compares system resolver RCODE vs explicit resolver RCODEs — divergence is a finding signal.

### Per-Resolver Rate Limiting
- **D-08:** Implement a token bucket rate limiter in `internal/probe/dnsprobe/` as a middleware-like wrapper around the DNS probe function. Default: 20 queries/second per resolver. Configurable via `ScanOptions.DNSRateLimit` or `--dns-rate-limit` CLI flag.
- **D-09:** The rate limiter is per-resolver (not global) so one resolver's rate limit doesn't affect another's. Uses a `map[string]*rate.Limiter` keyed by resolver name/server. `golang.org/x/time/rate` package is the standard Go token bucket implementation (already commonly available, no new dependency risk).

### Transparent DNS Proxy Detection
- **D-10:** Query `whoami.akamai.net` A record via each configured resolver. Compare the resolved IP against the resolver's configured server address. If they differ, emit a "transparent DNS proxy" finding. Use the existing DNS probe with a hardcoded domain `whoami.akamai.net` and qtype A.
- **D-11:** This only works for resolvers with known server addresses (not system resolver). The finding is HIGH confidence when IPs differ, MEDIUM when the DNS query fails (proxy may be blocking whoami queries).

### Claude's Discretion
- Exact RCODE finding text and severity levels
- CLI flag names for DoH/DoT resolver configuration
- Rate limiter burst size (default 5 burst for 20 qps)
- whoami.akamai.net fallback domain list
- Whether init() registers separate adapter instances or a single parameterized adapter for DoH/DoT
</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### DNS probe codebase
- `internal/probe/dnsprobe/dns.go` — Current DNS Probe function, miekg/dns client usage, truncated TCP fallback
- `internal/probe/dnsprobe/adapter.go` — Current DNS adapter, dual-stack AAAA logic added in Phase 3
- `internal/model/model.go` — DNSObservation, Resolver, Target types
- `internal/classifier/classifier.go` — Current classification logic, where per-RCODE findings will be added

### Requirements
- `.planning/REQUIREMENTS.md` — F-05 (DNS RCODEs), F-13 (DoH/DoT), N-01 (no new deps)
- `.planning/ROADMAP.md` §138-176 — Phase 4 tasks T-023 to T-028, delivery criteria

### Architecture
- `.planning/codebase/ARCHITECTURE.md` — Pipeline structure, probe-classifier relationship
- `.planning/codebase/CONVENTIONS.md` — Code patterns, error handling
</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `miekg/dns` — Already used by DNS probe, supports DoH (`Net: "https"`) and DoT (`Net: "tcp-tls"`) natively via the same `Client.ExchangeContext` API
- `internal/probe/dnsprobe/dns.go` — Existing Probe function with UDP/TCP fallback. Can be extended to accept transport parameter
- `internal/model/model.go` — `DNSObservation` already captures `RCode` string. `Resolver` has `Name`, `Server`, `System` fields
- `internal/classifier/classifier.go` — `Classify()` function that iterates observations and emits findings

### Established Patterns
- **Probe interface with adapter:** Phase 2 pattern — every probe follows Opts + Adapter + init() from Phase 2
- **Middleware composition:** Timeout, Retry, Logging middleware wraps probes via `middleware.Chain`. Rate limiter could follow same pattern
- **Findings via classification:** Classifier generates `model.Finding` structs — RCODE findings follow this pattern

### Integration Points
- `internal/probe/dnsprobe/adapter.go` — Add transport-aware adapter variants or parameterize existing adapter
- `internal/model/model.go` — Add Transport field to Resolver
- `internal/classifier/classifier.go` — Add per-RCODE finding generation
- `internal/targets/targets.go` or `cmd/iscan/main.go` — Add DoH/DoT resolver configuration
</code_context>

<specifics>
## Specific Ideas

- miekg/dns DoH: `client := &mdns.Client{Net: "https"}` — works with standard `ExchangeContext`
- miekg/dns DoT: `client := &mdns.Client{Net: "tcp-tls"}` — requires TLS config for certificate verification
- whoami.akamai.net returns the resolver IP that handled the query — comparison with configured resolver address detects proxies
- Rate limiter: `golang.org/x/time/rate` token bucket per resolver key
- System resolver RCODE: empty server string → miekg/dns uses OS default resolver
</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope.
</deferred>

---

*Phase: 04-DNS Enhancements*
*Context gathered: 2026-04-27 via --auto*
