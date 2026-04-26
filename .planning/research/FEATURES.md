# Feature Landscape: Network Censorship Detection CLI

**Project:** iscan
**Domain:** Layered network diagnostics for censorship detection
**Researched:** 2026-04-26
**Confidence:** HIGH (Context7 + official docs verified)

---

## Competitor Analysis

### Major Platforms

| Tool | Type | DNS | TCP | TLS | HTTP | QUIC | Trace | ICMP | DoH/ DoT | WS | STUN | Proxy | Outputs | Key Differentiator |
|------|------|-----|-----|-----|------|------|-------|------|---------|----|------|-------|---------|-------------------|
| **OONI Probe** | Mobile/CLI | Yes | Yes | Yes | Yes | No | Yes | No | Yes | No | Yes | No | JSON, CSV, OONI Explorer | Largest global censorship dataset (2B+ measurements) |
| **OONI Probe CLI** | CLI (Go) | Yes | Yes | Yes | Yes | No | Yes | No | Yes | No | Yes | No | JSONL | Reference implementation, spec-compliant |
| **RBMK** | CLI (Go) | Yes (UDP/TCP/DoT/DoH) | Yes | Yes | Yes | No | No | No | Yes | No | No | No | JSONL | Modular, scriptable, dig/curl-like syntax |
| **Censored Planet (CenTrace)** | CLI (Python) | No | HTTP trace | HTTPS trace | Yes | No | Yes (app-layer) | No | No | No | No | No | PCAP, JSON | Finds *where* middlebox sits (in-path vs on-path) |
| **Censored Planet (CenFuzz)** | CLI (Go) | No | No | No | Fuzz | No | No | No | No | No | No | No | JSON | Identifies censor *trigger rules* via request fuzzing |
| **M-Lab NDT** | Web/CLI | No | BW test | No | No | No | Paris trace | No | No | No | No | No | JSON | Bandwidth + latency under load |
| **Cloudflare Speed Test** | Web/CLI (Rust) | DNS timing | TCP timing | TLS timing | BW test | No | No | No | No | No | No | No | JSON | Bufferbloat detection, AIM scoring |
| **RIPE Atlas** | Hardware/CLI | Yes | Ping | SSL cert | Yes | No | Yes | Yes | No | No | No | No | JSON | Global distributed probe network (9000+ probes) |
| **iscan (current)** | CLI (Go) | Yes (UDP/TCP fallback) | Yes | Yes (SNI compare) | Yes | Yes (SNI compare) | Yes | No | No | No | No | No | JSON, Terminal | Layered protocol profile + recommendation engine |

### Key Observations

1. **OONI is the 800-pound gorilla** -- 2B+ measurements, 28K+ networks, 242+ countries. Competing on breadth is futile. iscan must compete on **depth** (per-probe detail, layered analysis, actionable recommendations) and **speed** (CLI-native, no backend dependency).

2. **No tool combines all features** -- OONI lacks QUIC. RBMK lacks traceroute. CenTrace is research-only. M-Lab/Cloudflare are bandwidth-focused. RIPE Atlas requires hardware. iscan's QUIC support is already a differentiator.

3. **Only OONI has a comparison/control server** -- iscan uses builtin targets and multi-resolver comparison instead, which is more portable (no backend required) but less authoritative.

4. **RBMK is the closest architectural cousin** -- same language (Go), same CLI-first philosophy. RBMK is more modular/scriptable; iscan is more integrated/opinionated.

---

## Table Stakes

Features users expect in a censorship detection tool. Missing these = product feels incomplete.

### Current iscan Coverage

| Feature | Expected? | iscan Status | Priority |
|---------|-----------|-------------|----------|
| DNS multi-resolver probing | Yes | Existing (system, Cloudflare, Google, Quad9) | Done |
| DNS EDNS0 support | Yes | Existing (1232-byte EDNS0 on all queries) | Done |
| DNS TCP fallback on truncation | Yes | Existing | Done |
| TCP connectivity check | Yes | Existing with error classification (timeout/refused/reset/unreachable) | Done |
| TLS handshake probe | Yes | Existing with SNI, version, ALPN, cert fingerprint capture | Done |
| TLS SNI comparison (same IP, different SNI) | Yes | Existing via target.CompareSNI field | Done |
| HTTP GET request (status code, body check) | Yes | Existing with redirect prevention | Done |
| HTTP timing breakdown (DNS, connect, TLS, TTFB) | Nice-to-have | Existing via httptrace | Done |
| ICMP traceroute | Yes | Existing (IPv4 only, max 30 hops, MAD jitter) | Done |
| Terminal output (human-readable) | Yes | Existing (tabwriter table) | Done |
| JSON output (structured data) | Yes | Existing (MarshalIndent) | Done |
| Configurable timeout and retries | Yes | Existing (timeout, retries with exponential backoff) | Done |
| Concurrent multi-target scanning | Yes | Existing (errgroup with configurable parallelism) | Done |
| Control targets for baseline comparison | Yes | Existing (example.com, cloudflare.com as controls) | Done |
| Graceful interrupt handling | Yes | Existing (SIGINT/SIGTERM via signal.NotifyContext) | Done |

### Missing Table Stakes

| Feature | Why Expected | Complexity | Priority |
|---------|--------------|------------|----------|
| **ICMP Ping probe** | Independent reachability check without root (if privileged ping binary available); baseline latency measurement | Low | High |
| **Custom target sets** (JSON file) | Users need to test their own domains, not just builtin set | Low | High |
| **IPv6 support** across all probes | Growing IPv6 adoption; censorship can differ per address family | Medium | High |
| **Filtering/flagging of suspicious DNS answers** (private IPs, loopback) | Existing (isSuspiciousIP) but should also flag RFC1918 answers, NXDOMAIN rewrites, sinkhole IPs | Low | Medium |
| **DNS resolver comparison** (consistency across resolvers) | Existing (dnsInconsistent) but could expose resolver-level detail per resolver pair | Low | Medium |
| **Error output to stderr, JSON to stdout** | Standard CLI convention for pipeline composability | Low | Medium |
| **Exit code signaling** (0 = no issues, 1 = issues found, 2 = error) | Standard CLI convention for scripting/CI use | Low | Low |

---

## Differentiators

Features that set iscan apart from OONI/RBMK/Censored Planet.

### Already Built

| Feature | Why Valuable | Competitor Gap | Confidence |
|---------|-------------|----------------|------------|
| **QUIC/UDP handshake probe** with SNI comparison | Detects QUIC-specific blocking (GFW treats QUIC differently from TCP/TLS). OONI has NO QUIC support. | OONI: none; RBMK: none | HIGH |
| **Layered protocol profiling** (DNS, TCP, TLS, QUIC, Path) | Aggregates per-layer health scores into one network profile. No other tool produces a single "network health" summary. | OONI: per-test output; RBMK: per-command only | HIGH |
| **Protocol ranking recommendation engine** | Answers "what protocol works best on this network?" -- uniquely actionable. No competitor does this. | OONI: detection only; RBMK: measurement only | HIGH |
| **SNI-correlated failure detection** | Same IP, different SNI -> one succeeds, one fails -> censorship signal. Standard in OONI but rare in CLI tools. | RBMK: none; CenTrace: not focused on this | MEDIUM |

### Planned / Should Build

| Feature | Why Valuable | Competitor Gap | Complexity |
|---------|-------------|----------------|------------|
| **Encrypted DNS probe** (DoH, DoT, DoQ) | Detects whether encrypted DNS services themselves are blocked (separate from domain-level blocking). OONI has dnscheck; no CLI tool combines this with QUIC probing. | RBMK: partial (dig DoT/DoH); OONI: separate test | Medium |
| **WebSocket (WS/WSS) handshake probe** | Detects WebSocket-specific blocking used to censor real-time apps (Signal, WhatsApp Web). No existing CLI censorship tool tests WebSocket reachability. | OONI/RBMK/CenTrace: none | Medium |
| **Proxy protocol probe** (SOCKS5, HTTP CONNECT) | Tests whether proxy/protocol tunnels are blocked. Useful for users evaluating circumvention tools. | OONI: separate tor/psiphon tests (heavy); no lightweight proxy check | Medium |
| **HTML report with visual indicators** | Self-contained, shareable report for non-technical stakeholders. OONI has web explorer (not local). | OONI: cloud explorer; RBMK: no HTML | Medium |
| **Scan comparison/diff mode** | Compare two scan results to see what changed (before/after ISP change, different times of day). No tool does this. | All competitors: no diff mode | Medium |
| **Target tagging / run-by-category** | Run probes against "control only" or "sensitive" or "all" targets. Enables focused re-runs. | OONI: per-test selection; iscan: all-or-nothing | Low |
| **Health score trending** (store historical scan data) | Track network health over time to identify degradation patterns or blocking escalation. | OONI: cloud explorer (not local); no CLI does this | High |

### Anti-Differentiators (Do Not Build)

| Feature | Why Avoid |
|---------|-----------|
| **Bandwidth speed test** (download/upload measurement) | M-Lab NDT and Cloudflare Speed Test own this space. High bandwidth cost, little censorship signal value. |
| **OONI Explorer-style cloud database** | Requires backend infrastructure, data storage, privacy policy. iscan is a local CLI tool. |
| **Mobile app / GUI** | Explicitly out of scope. CLI-first, HTML report as limit. |
| **Internet-wide scanning** (zgrab2, Census-style) | Too noisy; requires consent/large infrastructure. |
| **Real-time pcap analysis** | Network sniffer territory. iscan is an active probe tool. |
| **Circumvention / VPN / Tor proxy bypass** | Diagnostic tool, not circumvention. Recommending protocols is the boundary. |

---

## Feature Gap Analysis

### What iscan Has That Others Dont

| Feature | Present In |
|---------|-----------|
| QUIC handshake with SNI comparison | iscan only |
| Per-layer health profile (single-page summary) | iscan only |
| Protocol ranking recommendations | iscan only |
| MAD-based jitter computation for path quality | iscan only |
| SNI comparison on both TLS and QUIC | iscan only |
| Layered detection (DNS -> TCP -> TLS -> HTTP -> QUIC -> Trace) | iscan only |

### What Others Have That iscan Lacks

| Feature | Present In | Impact | Priority for iscan |
|---------|-----------|--------|-------------------|
| DNS-over-TLS probe | OONI dnscheck, RBMK dig | Detects encrypted DNS blocking | High (PROBE-07) |
| DNS-over-HTTPS probe | OONI dnscheck, RBMK dig | Detects DoH blocking | High (PROBE-06) |
| WebSocket handshake probe | None (tool gap) | Detects real-time app blocking | Medium (PROBE-05) |
| Proxy protocol probe | OONI tor/psiphon tests | Tests circumvention protocol blocking | Medium (PROBE-08) |
| ICMP Ping probe | RIPE Atlas, standard ping | Low-overhead reachability check | Medium (PROBE-04) |
| HTTP header manipulation detection | OONI http_host | Detects transparent HTTP proxies | Low (research tool) |
| HTTP invalid request line test | OONI | Fingerprints middlebox type | Low (research tool) |
| Application-layer traceroute (CenTrace style) | CenTrace | Locates middlebox on path | Low (research tool) |
| HTML report output | None (tool gap) | Shareable diagnostics | High (REPORT-01) |
| CSV/YAML output | None (tool gap) | Pipeline compatibility | Medium (REPORT-02) |
| Scan comparison / diff mode | None (tool gap) | Before/after comparison | Medium (REPORT-03) |
| Long-term trend tracking | None (tool gap) | Health monitoring | Low (REPORT-04) |
| Self-updating target lists (Citizen Lab integration) | OONI | Always-fresh test URLs | Low (maintenance burden) |

### Gap Prioritization for Roadmap

**Phase 1 (next):** ICMP Ping (PROBE-04), Custom target sets (PROBE-03), IPv6 (PROBE-02)
**Phase 2:** DoH/DoT (PROBE-06, PROBE-07), WebSocket (PROBE-05)
**Phase 3:** HTML report (REPORT-01), CSV/YAML export (REPORT-02)
**Phase 4:** Proxy probe (PROBE-08), Scan comparison (REPORT-03)
**Phase 5:** Trend tracking (REPORT-04), HTTP manipulation detection (low priority)

---

## SNI / DNS Blocking Detection Techniques

### SNI-Based Blocking Detection

SNI (Server Name Indication) is the plaintext hostname sent in the TLS ClientHello. Censors use DPI to read the SNI and block connections to specific hostnames while allowing others on the same IP.

#### Technique 1: Same-Address, Different-SNI Comparison (Existing)

**How it works:** Probe the same IP address with two different SNI values -- one for a known-safe domain (example.com) and one for a suspected-blocked domain. If the safe SNI succeeds and the blocked SNI fails, the failure is SNI-correlated.

**iscan implementation:** The `Target.CompareSNI` field in model.go specifies additional SNI values to test against each resolved IP. The classifier's `sniCorrelatedFailures()` function groups TLS observations by address and flags cases where at least one SNI succeeded and another failed on the same address.

**Confidence:** HIGH (implemented and tested)

**Limitations:**
- Requires the safe SNI's server to be reachable on the same address (CDN co-location helps)
- Does not distinguish between SNI-based blocking and IP-based blocking when the safe SNI also fails
- Single-observation per SNI (no retry across different addresses for the same SNI)

#### Technique 2: SNI Fingerprint Variation (Planned)

**How it works:** Send TLS ClientHello with different SNI encoding variants to detect censor parsing behavior. Inspired by OONI's http_host test for HTTP, but applied at the TLS layer.

**Variants to test:**
- Normal SNI (baseline)
- SNI with appended null byte
- SNI with tab character
- Subdomain-prefixed SNI (random.example.com vs example.com)
- SNI with non-ASCII characters

**Detection signal:** If normal SNI triggers blocking but a variant succeeds, the censor's SNI parser has a specific weakness.

**Complexity:** Medium (requires raw TLS ClientHello construction or synthetics)
**Priority:** Low (research feature, not core diagnostic)

#### Technique 3: Encrypted Client Hello (ECH) Reachability (Planned)

**How it works:** Attempt TLS connection with and without ECH. If plaintext TLS fails but ECH succeeds, blocking is SNI-based.

**Complexity:** High (requires ECH support in Go crypto/tls)
**Priority:** Very Low (ECH is not widely deployed yet; Go 1.24+ has basic ECH support but ecosystem is immature)

### DNS Manipulation Detection

#### Technique 1: Multi-Resolver Comparison (Existing)

**How it works:** Query the same domain against multiple DNS resolvers (system, Cloudflare, Google, Quad9). If answer sets differ between resolvers, DNS tampering is suspected.

**iscan implementation:** `dnsInconsistent()` in classifier.go groups answers by query type and resolver, then checks if resolvers returned non-overlapping answer sets. `suspiciousDNS()` flags private/loopback/link-local IPs in answers.

**Confidence:** HIGH

**Refinements needed:**
- Currently flags ANY difference as inconsistent. Should distinguish between GeoDNS (legitimate, IPs differ by location) and censorship (NXDOMAIN rewrites, sinkhole IPs).
- Should compare resolver pairs explicitly (e.g., "system vs Cloudflare disagree") rather than just a binary inconsistent/consistent flag.
- Should detect NXDOMAIN rewrites where one resolver returns valid IPs and another returns NXDOMAIN.

#### Technique 2: EDNS0 Padding Analysis (Existing)

**How it works:** All iscan DNS queries include EDNS0 with a 1232-byte UDP buffer (`msg.SetEdns0(1232, false)`). If the response is truncated (TC bit set), iscan falls back to TCP automatically.

**Detection signal:** If a resolver consistently returns truncated responses that don't actually need truncation (small answer sets with TC=1), this suggests a transparent DNS proxy or middlebox interfering.

**Current status:** TCP fallback is implemented but the TC-bit pattern analysis is not exposed as a finding. TC-bit-only failures (where TCP fallback also fails) are surfaced as errors.

**Improvement opportunity:** Add a `FindingDNSProxied` type when TC=1 occurs with unexpectedly small answer payloads, suggesting middlebox interference.

#### Technique 3: Control vs Probe Comparison (Existing via Control Targets)

**How it works:** Targets marked with `Control: true` (example.com, cloudflare.com) serve as known-good baselines. If control targets fail DNS/TCP/TLS/HTTP across all resolvers, it suggests a local network issue rather than targeted censorship.

**Implementation:** The scanner runs control targets alongside diagnostic targets. The classifier produces `FindingLocalNetworkIssue` when all probes fail.

**Limitation:** Control target reachability is a strong but not definitive signal -- censors can block control targets too (China blocks example.com). Multi-resolver comparison is more reliable.

**Improvement:** Add an explicit `control_accessible` boolean to the profile and use it to weight findings confidence. If control targets are unreachable, lower confidence on all censorship findings.

#### Technique 4: Transparent DNS Proxy Detection (Planned)

**How it works:** Query the whoami.akamai.net (or similar) resolver-identification domain to determine what resolver IP the network actually uses vs what was requested.

**Detection signal:** If you request Cloudflare DNS (1.1.1.1) but whoami.akamai.net returns an ISP resolver IP, a transparent DNS proxy is intercepting your queries.

**Complexity:** Low (single DNS query against multiple resolvers)
**Priority:** Medium

#### Technique 5: DNS Timing Anomaly Detection (Planned)

**How it works:** Compare DNS latency between resolvers. Anomalous latency patterns can indicate transparent proxies or censorship devices that add processing delay.

**Detection signal:** If system resolver latency is significantly higher than Cloudflare/Google (which should be farther), a middlebox may be inspecting queries.

**Current status:** DNS latency is collected but not analyzed for anomaly patterns. The profile only uses average latency for tier scoring.

**Complexity:** Low
**Priority:** Low

### QUIC-Specific Detection (Existing)

**How it works:** iscan sends QUIC Initial packets with different SNI values, analogous to TLS SNI comparison. The QUIC handshake observes connection success/failure and reports version, ALPN, and cert fingerprint.

**Why it matters:** Censorship of QUIC can differ from TCP/TLS:
- GFW has separate QUIC DPI middleboxes (reported in 2025 research) that inspect QUIC Initial SNI
- Some networks block QUIC entirely (no port 443 UDP connectivity)
- QUIC uses version negotiation which censors may mishandle

**Current status:** QUIC probe with SNI comparison is implemented. QUIC failure is classified as `FindingQUICFailure`. There is no separate "QUIC blocking only" vs "UDP blocked entirely" distinction yet.

**Improvement:** If QUIC fails for all targets (including control targets), flag `FindingUDPBlocked` to distinguish QUIC-specific censorship from general UDP blocking. This can be a trigger for the protocol ranking to deprioritize UDP-friendly recommendations.

---

## Target Diversity and Selection

### Current Target Set (Builtin)

| Target | Purpose | Ports | QUIC | CompareSNI |
|--------|---------|-------|------|------------|
| example.com | Control (minimal censorship risk) | 443 | Yes | None |
| cloudflare.com | Control (CDN-backed, rarely blocked entirely) | 443 | Yes | None |
| www.google.com | Diagnostic (frequently blocked in some regimes) | 443 | Yes | example.com |
| example.net | No-QUIC control (QUIC port disabled) | 443 | No | None |

### Gaps in Target Selection

1. **No controversial/political targets** -- All current targets are benign. To detect censorship, targets must include domains that censors actually block (human rights, journalism, political opposition). This carries risk in surveillance-heavy jurisdictions.

2. **No geographic diversity** -- All targets are US-based. Regional censorship often targets local sites.

3. **No service-type diversity** -- No social media, file sharing, VPN provider, or messaging platform targets.

**Recommendation:** Add a separate `--sensitive` probe mode that tests against a curated list of potentially blocked targets (with a clear risk warning). The default (`--target-set builtin`) stays safe.

### Target List Sources

| Source | Use Case | Format | Freshness |
|--------|----------|--------|-----------|
| Citizen Lab test-lists | Curated censorship test URLs (30 categories) | GitHub CSV | Community-maintained |
| Alexa Top 1M / Tranco | General availability baseline | CSV | Daily |
| Builtin (current) | Zero-config safe defaults | Go constant | Version-locked |
| Custom JSON (planned) | User-defined targets | JSON | User-managed |

**Recommendation for iscan:** Ship a JSON-encoded builtin target set embedded in the binary for zero-config startup. Allow `--target-set path/to/targets.json` for custom sets. Do NOT auto-fetch external lists (maintains offline capability, avoids dependency on upstream availability).

---

## Reporting Format Requirements

### Terminal Output (Existing)

- Tabwriter-formatted table: per-target status across all protocol layers
- Findings summary: comma-separated finding types per target
- Protocol rankings with scores and Chinese/English bilingual explanations
- Warning lines for permission errors, skipped probes

### JSON Output (Existing)

- Full `ScanReport` (targets, findings, timing, options)
- Extended JSON optionally includes `Profile` and `Recommendation`

### HTML Report (Planned -- REPORT-01)

Self-contained (no external CSS/JS) HTML report with:
- Per-target protocol status table (color-coded)
- Expandable detail sections per probe
- Network health profile visualization (tier badges)
- Protocol ranking results
- Color scheme: green (ok), yellow (warning), red (failure), gray (skipped)
- Dark theme support

### CSV/YAML Export (Planned -- REPORT-02)

- CSV: flat table of target x protocol results for spreadsheet analysis
- YAML: human-editable output suitable for version control

### Comparison Mode (Planned -- REPORT-03)

- Load two JSON scan results, produce diff report
- Per-target: which findings changed, which protocols changed status
- Health score comparison (before/after)
- Output as terminal diff table or HTML comparison report

---

## Feature Dependency Graph

```
PROBE-03 (Custom targets)
  |
  v
PROBE-04 (ICMP Ping) --- independent UDP/ICMP layer check
  |
  v
PROBE-02 (IPv6) --- modifies all existing probes
  |
  v
PROBE-06 (DoH)
PROBE-07 (DoT)   --- requires HTTP+TLS foundation (existing)
  |
  v
PROBE-05 (WebSocket) --- requires TCP+TLS foundation (existing)
  |
  v
PROBE-08 (Proxy) --- requires TCP foundation (existing)
  |
  v
REPORT-01 (HTML) --- requires JSON output (existing)
REPORT-02 (CSV/YAML) --- requires JSON output (existing)
  |
  v
REPORT-03 (Diff mode) --- requires REPORT-01/02 first
  |
  v
REPORT-04 (Trend tracking) --- requires REPORT-03 first
```

---

## Sources

- OONI Web Connectivity specification: https://ooni.github.io/post/web-connectivity/
- OONI Probe CLI documentation: https://pkg.go.dev/github.com/ooni/probe-cli/v3
- OONI Nettest catalog: https://ooni.github.io/nettest/
- OONI dnscheck / DoT/DoH blocking: https://ooni.github.io/post/2022-doh-dot-paper-dnsprivacy21/
- RBMK project: https://pkg.go.dev/github.com/rbmk-project/rbmk
- Censored Planet CenTrace: https://github.com/censoredplanet/CenTrace
- Censored Planet CenFuzz: https://github.com/censoredplanet/CenFuzz
- Citizen Lab test-lists: https://github.com/citizenlab/test-lists
- M-Lab NDT specification: https://www.npmjs.com/package/@m-lab/ndt7
- Cloudflare Speed Test: https://github.com/cloudflare/speedtest
- Cloudflare Mach (CLI): https://github.com/cloudflare/networkquality-rs
- RIPE Atlas documentation: https://atlas.ripe.net/docs/faq/technical-details/
- OONI http_host test: https://ooni.github.io/nettest/http-host/
- GFW QUIC DPI research (2025): https://www.privateoctopus.com/2025/08/01/can-quic-evade-middle-meddlers.html
- GFW middlebox fingerprinting (ACM CCS 2025): https://arxiv.org/abs/2509.09081
