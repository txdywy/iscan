---
phase: 04-dns-enhancements
verified: 2026-04-27T23:00:00Z
status: passed
score: 15/15 must-haves verified
overrides_applied: 0
gaps: []
---

# Phase 4: DNS Enhancements Verification Report

**Phase Goal:** DNS probing produces richer diagnostic signal with RCODE-specific findings, encrypted transport options (DoH, DoT), system resolver RCODE extraction, and per-resolver rate limiting.

**Verified:** 2026-04-27T23:00:00Z
**Status:** passed
**Re-verification:** No (initial verification)

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Resolver struct has a Transport field to select protocol per resolver | VERIFIED | model.go line 76: `Transport string \`json:"transport,omitempty"\`` |
| 2 | FindingType constants exist for each DNS RCODE category (NXDOMAIN, SERVFAIL, REFUSED, other, transparent proxy) | VERIFIED | model.go lines 37-41: 5 new FindingType constants (`dns_nxdomain`, `dns_servfail`, `dns_refused`, `dns_other_rcode`, `dns_transparent_proxy`) |
| 3 | ScanOptions carries DNSRateLimit and CustomResolvers fields | VERIFIED | model.go lines 87-88: `DNSRateLimit int`, `CustomResolvers []Resolver` fields on ScanOptions |
| 4 | DNS probe dispatches to correct transport based on Resolver.Transport | VERIFIED | dns.go lines 18-29: Probe() dispatches via switch on `resolver.Transport` with cases for "https", "tcp-tls", "system", default (udp) |
| 5 | DoH queries send DNS wire-format via HTTP POST to https://server/dns-query | VERIFIED | doh.go lines 35-42: HTTP POST to `https://{server}/dns-query` with `application/dns-message` content type; TestProbeDoH and TestProbeDoHError pass |
| 6 | DoT queries use miekg/dns Client with Net:tcp-tls and InsecureSkipVerify | VERIFIED | dot.go lines 32-38: `&mdns.Client{Net: "tcp-tls", TLSConfig: &tls.Config{InsecureSkipVerify: true}}`; TestProbeDoT and TestProbeDoTDefaultPort pass |
| 7 | System resolver uses net.DefaultResolver.LookupHost | VERIFIED | dns.go lines 101-122: `systemResolverQuery()` calls `net.DefaultResolver.LookupHost(ctx, domain)` |
| 8 | Per-resolver token bucket rate limiter prevents accidental DoS | VERIFIED | ratelimit.go: `resolverLimiters sync.Map` keyed by resolver name, 20 qps default, 5 burst. 3 rate limiter tests pass |
| 9 | Adapter iterates all resolvers from targets.BuiltinResolvers() internally | VERIFIED | adapter.go line 20: `resolvers := targets.BuiltinResolvers()`, line 23: `for _, resolver := range resolvers` |
| 10 | Adapter returns []DNSObservation as ProbeResult.Data for multi-observation collection | VERIFIED | adapter.go line 21: `var observations []model.DNSObservation`, line 57: `return probe.NewResult(model.LayerDNS, observations)` |
| 11 | Per-RCODE findings generated for NXDOMAIN (HIGH), SERVFAIL (MEDIUM), REFUSED (HIGH), and other RCODEs (LOW) | VERIFIED | classifier.go: `dnsRcodeFindings()`, `rcodeFindingType()`, `rcodeConfidence()`. 6 RCODE tests pass |
| 12 | Transparent DNS proxy detected when whoami response IP differs from known resolver IPs | VERIFIED | classifier.go: `detectTransparentDNSProxy()`, `isKnownResolverIP()` covering 12 public resolver IPs. 3 proxy detection tests pass |
| 13 | Classifier handles both single DNSObservation and []DNSObservation ProbeResult.Data | VERIFIED | classifier.go lines 297-313: `collectAllDNSObservations()` handles both `[]model.DNSObservation` (new format) and `model.DNSObservation` (backward compat) |
| 14 | Users can specify custom DoH/DoT resolvers via --resolver flag with URL prefix parsing | VERIFIED | main.go lines 60-76: parses `https://` and `tls://` URL prefixes, calls `targets.AddCustomResolvers()`. `--help` shows `--resolver` flag |
| 15 | Users can configure per-resolver rate limit via --dns-rate-limit flag (default 20) | VERIFIED | main.go line 130: `--dns-rate-limit` flag with default 20. scanner.go line 42: `dnsprobe.SetRateLimit(rateLimit)`. `--help` shows flag |

**Score:** 15/15 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
| -------- | --------- | ------ | ------- |
| `internal/model/model.go` | Resolver.Transport, 5 FindingType constants, ScanOptions.DNSRateLimit + CustomResolvers | VERIFIED | All fields present. 5 FindingType constants (lines 37-41). Transport field (line 76). DNSRateLimit and CustomResolvers (lines 87-88) |
| `internal/targets/targets.go` | 4 DoH/DoT builtin resolvers, DetectTransport, AddCustomResolvers, WhoamiDomain | VERIFIED | 4 DoH/DoT resolvers (lines 128-131). DetectTransport (lines 24-32). AddCustomResolvers (lines 18-20). WhoamiDomain (line 12). All 7 existing resolvers have explicit Transport |
| `internal/probe/dnsprobe/dns.go` | Transport dispatcher in Probe(), udpQuery(), systemResolverQuery() | VERIFIED | Probe() dispatcher (lines 18-29). udpQuery() (lines 32-97). systemResolverQuery() (lines 101-122) |
| `internal/probe/dnsprobe/doh.go` | dohQuery() function with HTTP POST + DNS wire format | VERIFIED | dohQuery() (lines 18-86). HTTP POST to `https://{server}/dns-query` with `application/dns-message` |
| `internal/probe/dnsprobe/dot.go` | dotQuery() function with miekg/dns tcp-tls client | VERIFIED | dotQuery() (lines 16-91). `mdns.Client{Net: "tcp-tls", ...}` with port 853 default. Truncated response retry |
| `internal/probe/dnsprobe/ratelimit.go` | Per-resolver token bucket with getLimiter, SetRateLimit, waitLimiter | VERIFIED | getLimiter (lines 18-21). SetRateLimit (lines 25-33). waitLimiter (lines 37-43). sync.Map for per-resolver state |
| `internal/probe/dnsprobe/adapter.go` | Multi-resolver iteration with rate limiting per resolver query | VERIFIED | Adapter.Run() iterates all resolvers (line 23), rate limits per query (lines 25, 37, 50), whoami probing (lines 46-55), returns []DNSObservation (line 57) |
| `internal/classifier/classifier.go` | collectAllDNSObservations, dnsRcodeFindings, detectTransparentDNSProxy | VERIFIED | All 3 functions present. collectAllDNSObservations handles dual format. Per-RCODE findings with appropriate confidence. Transparent proxy detection with isKnownResolverIP |
| `cmd/iscan/main.go` | --resolver and --dns-rate-limit CLI flags, custom resolver parsing | VERIFIED | Flag variables (lines 42-43). --resolver processing (lines 60-76). Flags registered (lines 130-131). Help output shows both flags |
| `internal/scanner/scanner.go` | dnsprobe.SetRateLimit() wiring from ScanOptions.DNSRateLimit | VERIFIED | Lines 38-42: defaults to 20 qps, calls `dnsprobe.SetRateLimit(rateLimit)` before buildProbes() |

### Key Link Verification

| From | To | Via | Status | Details |
| ---- | --- | --- | ------ | ------- |
| targets.BuiltinResolvers | model.Resolver.Transport | Transport field on each Resolver | WIRED | All 11 builtin resolvers have explicit Transport (6 udp, 1 system, 2 https, 2 tcp-tls) |
| Probe() dispatcher in dns.go | dohQuery() in doh.go | case "https" switch branch | WIRED | dns.go line 21: `case "https": return dohQuery(...)` |
| Probe() dispatcher in dns.go | dotQuery() in dot.go | case "tcp-tls" switch branch | WIRED | dns.go line 23: `case "tcp-tls": return dotQuery(...)` |
| Probe() dispatcher in dns.go | systemResolverQuery() in dns.go | case "system" switch branch | WIRED | dns.go line 25: `case "system": return systemResolverQuery(...)` |
| adapter.Run() | waitLimiter() in ratelimit.go | Per-resolver rate limit before each Probe() call | WIRED | adapter.go lines 25, 37, 50: `waitLimiter(ctx, resolver.Name)` before each Probe() call |
| adapter.Run() | targets.BuiltinResolvers() | Resolver list iteration | WIRED | adapter.go line 20: `resolvers := targets.BuiltinResolvers()` |
| main.go --resolver flag | targets.AddCustomResolvers() | URL prefix parsing with DetectTransport | WIRED | main.go lines 60-76: parses prefix, calls `targets.AddCustomResolvers(customResolvers)` |
| scanner.Run() | dnsprobe.SetRateLimit() | ScanOptions.DNSRateLimit field | WIRED | scanner.go lines 38-42: defaults to 20, calls `dnsprobe.SetRateLimit(rateLimit)` |
| Classify() | dnsRcodeFindings() | append after existing DNS checks | WIRED | classifier.go lines 42-43: `findings = append(findings, dnsRcodeFindings(dnsObs, now)...)` |
| Classify() | detectTransparentDNSProxy() | whoami observation analysis | WIRED | classifier.go lines 45-46: `findings = append(findings, detectTransparentDNSProxy(dnsObs, now)...)` |

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
| -------- | ------------- | ------ | ------------------ | ------ |
| adapter.go | observations []DNSObservation | targets.BuiltinResolvers() -> Probe() -> transport dispatch | ✓ FLOWING | Observations are populated by actual Probe() calls across all resolvers, not hardcoded. Each resolver gets its own DNSObservation via transport-specific queries |
| classifier.go | dnsObs []DNSObservation | collectAllDNSObservations(result.Results) -> r.Data type assertion | ✓ FLOWING | Handles both []DNSObservation (new) and single DNSObservation (backward compat) from ProbeResult.Data |
| ratelimit.go | resolverLimiters sync.Map | getLimiter() -> LoadOrStore with rate.NewLimiter | ✓ FLOWING | Per-resolver token buckets created on demand, shared across calls. Rate limit configurable via SetRateLimit |
| main.go customResolvers | []model.Resolver | --resolver flag parsing -> DetectTransport() | ✓ FLOWING | URL prefixes stripped, transport detected, added via targets.AddCustomResolvers, flows to BuiltinResolvers() |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
| -------- | ------- | ------ | ------ |
| Binary builds | `go build ./...` | No errors | PASS |
| All tests pass | `go test ./... -count=1` | All 15 packages pass | PASS |
| `go vet` no issues | `go vet ./...` | No output (pass) | PASS |
| --help shows --dns-rate-limit | `./iscan scan --help` | Shows `--dns-rate-limit int (default 20)` | PASS |
| --help shows --resolver | `./iscan scan --help` | Shows `--resolver strings` | PASS |

### Requirements Coverage

| Requirement | Source Plan(s) | Description | Status | Evidence |
| ----------- | -------------- | ----------- | ------ | -------- |
| F-05 | 04-04, 04-05 | DNS RCODEs surfaced separately — NXDOMAIN, SERVFAIL, REFUSED distinguished | SATISFIED | `dnsRcodeFindings()` generates per-RCODE findings. 6 new classifier tests verify NXDOMAIN/HIGH, SERVFAIL/MEDIUM, REFUSED/HIGH, other/LOW, NOERROR bypass, and slice data format |
| F-13 | 04-01, 04-02, 04-03, 04-05 | DoH and DoT probe support via miekg/dns transport selector — no new deps | SATISFIED | DoH via Go stdlib net/http (no new dep). DoT via existing miekg/dns Client{Net:"tcp-tls"}. Tests verify both transports with local servers |
| N-01 | 04-01, 04-02 | No new external dependencies for core probe functionality | SATISFIED | DoH uses Go stdlib (no new dep). DoT uses existing miekg/dns. `golang.org/x/time/rate` added for operational rate limiting (Plan 03 correctly omits N-01 from its requirements; research doc notes this is "operational infrastructure, not core probe functionality") |

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
| ---- | ---- | ------- | -------- | ------ |
| (none) | - | - | - | No anti-patterns found in any modified files |

## Gaps Summary

No gaps found. All 5 ROADMAP delivery criteria are satisfied. All 15 observable truths are VERIFIED. All artifacts exist, are substantive, wired, and data flows correctly. All 9+6+3=18 classifier tests, all 4+3+4=11 dnsprobe tests, and all other test suites pass with zero regressions. Build and vet pass cleanly.

**Phase goal achieved:** DNS probing now produces richer diagnostic signal with RCODE-specific findings (NXDOMAIN/HIGH, SERVFAIL/MEDIUM, REFUSED/HIGH, other/LOW), encrypted transport options (DoH via HTTP POST with DNS wire format, DoT via miekg/dns tcp-tls), system resolver RCODE extraction (via net.DefaultResolver), per-resolver rate limiting (20 qps default, token bucket), and transparent DNS proxy detection (via whoami.akamai.net comparison against known resolver IPs).

---

_Verified: 2026-04-27T23:00:00Z_
_Verifier: Claude (gsd-verifier)_
