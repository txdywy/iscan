# Project Research Summary

**Project:** iscan -- Layered Network Diagnostics CLI
**Domain:** Network censorship detection and diagnostics
**Researched:** 2026-04-26
**Confidence:** MEDIUM (HIGH for stack and features, MEDIUM for architecture and pitfalls)

## Executive Summary

iscan is a Go-based CLI tool for layered network diagnostics focused on censorship detection. It occupies a unique niche: **no existing tool combines QUIC probing, layered protocol profiling, and actionable protocol recommendations** in a single CLI binary. The research confirms that iscan's current architecture is functional but would benefit from systematic refactoring toward interface-driven extensibility before feature expansion.

The single most important finding across all research is the need for a **unified `Probe` interface with middleware-based cross-cutting concerns**. Currently, adding a new protocol requires editing 5+ files across the codebase. All four research areas converge on this: STACK confirms the probe functions work but recommends abstraction; ARCHITECTURE provides a detailed interface design with middleware wrappers; FEATURES identifies probes that need adding (DoH, DoT, WebSocket); PITFALLS shows that timeout and retry logic is duplicated and buggy across all probes.

Key risks are concentrated in three areas: **ICMP identifier collision** (silent data corruption in concurrent traceroute), **profile averaging over mixed targets** (dilutes censorship signals by lumping controls with diagnostics), and **static confidence in classification** (masks evidence strength, making all findings look equally reliable). These are fixable but need prioritization before feature expansion.

## Key Findings

### Top Cross-Cutting Findings (5)

1. **Unified probe interface is the highest-ROI refactoring.** All four research areas support this. It eliminates duplicated retry/timeout logic (STACK), enables clean addition of DoH/DoT/WebSocket (FEATURES), decouples scanner from probe details (ARCHITECTURE), and fixes the timeout propagation bugs identified across every probe package (PITFALLS P7, P15, P16).

2. **Control vs diagnostic target separation must be built into the pipeline.** FEATURES identifies this as a gap, ARCHITECTURE proposes cross-target correlation, and PITFALLS (P6, P21) shows that profile averaging over all targets dilutes censorship signals. The profile should compute separate health dimensions for control targets (network baseline) and diagnostic targets (censorship signals).

3. **Dynamic confidence scoring replaces the current static assignment.** PITFALLS P12 documents that all findings carry the same confidence regardless of evidence strength. FEATURES identifies confidence-weighted findings as a gap. ARCHITECTURE proposes a confidence propagation model with modifiers (corroboration, cross-target agreement). Medium complexity, deferrable until basic detectors are stable.

4. **Timeout and context management is the most pervasive bug class.** PITFALLS documents 7+ timeout-related issues: shared per-hop timeout (P3), timeout not propagated to individual probes (P7), DNS TCP fallback latency inflation (P8), QUIC double-timeout (P15), errgroup cancellation cascading (P16). The root cause: every probe manages timeouts independently. A unified middleware layer eliminates this at the architecture level.

5. **DNS error handling needs nuance across three dimensions.** RCODE distinction (P5: NXDOMAIN vs SERVFAIL needs different treatment), EDNS0 integrity on TCP retry (P2), and system resolver cache opacity (P10) collectively mean the DNS probe produces less diagnostic signal than it could. STACK confirms `miekg/dns` supports all needed features; the gap is in how the probe uses them.

### Per-Area Insights

#### Stack (from STACK.md)

The dependency footprint is minimal (5 direct dependencies) and appropriate.

- **All current probes use the right libraries** -- `miekg/dns` (not AdGuard DNS proxy), `quic-go` (not experimental `x/net/quic`), `crypto/tls` (not `utls`). No library migration needed.
- **DoH/DoT require no new dependencies.** `miekg/dns` v1.x supports `Net: "https"` and `Net: "tcp-tls"`. Encrypted DNS is a transport parameter change.
- **The concurrency pattern is correct** -- `errgroup` with `SetLimit` for target-level parallelism, sequential probes per target. Missing piece: per-attempt context deadlines derived from parent context.
- **Pressure for change is in architecture, not stack.** The current dependencies serve the current codebase well.

#### Features (from FEATURES.md)

iscan already has unique differentiators (QUIC probing, layered profiles, protocol recommendations) that no competitor fully matches.

- **Competing with OONI on breadth is futile.** iscan competes on depth (per-probe detail), speed (CLI-native), and actionable output (protocol ranking, not just raw data).
- **Highest-priority gaps:** ICMP Ping (PROBE-04), Custom target sets (PROBE-03), IPv6 support (PROBE-02), Encrypted DNS (PROBE-06/07), HTML reports (REPORT-01).
- **Do not build:** Bandwidth speed tests, cloud database, mobile app, circumvention tools. Outside diagnostic CLI scope.

#### Architecture (from ARCHITECTURE.md)

The architecture is functional with four structural anti-patterns needing refactoring:

1. **No unified probe interface** -- each probe has a different signature. Adding a new protocol touches 5+ files.
2. **Retry logic duplicated in scanner** -- `retryWithBackoff` at every probe callsite instead of middleware.
3. **Monolithic classifier** -- `Classify()` is one function with inline heuristics.
4. **Flat TargetResult struct** -- adding a protocol adds a new slice field. A type-erased `ProbeResult` decouples model from protocol count.

The proposed `Probe` interface + middleware decorator pattern (modeled on OONI's `netxlite`) is the right direction. The registry + `init()` registration pattern is battle-tested and avoids Go plugin complexity.

#### Pitfalls (from PITFALLS.md)

22 documented pitfalls. The most actionable:

- **CRITICAL (P1):** ICMP identifier collision -- `os.Getpid() & 0xffff` causes cross-process hop misattribution in concurrent traceroute. Fix: per-instance atomic counter, validate inner ICMP in TimeExceeded responses.
- **CRITICAL (P2):** EDNS0 not preserved on TCP retry -- `Msg.Copy()` doesn't copy OPT pseudo-records. Fix: fresh message for TCP fallback.
- **HIGH (P6):** Profile averages over all targets including controls -- dilutes censorship signals. Fix: separate control/diagnostic profile computation.
- **HIGH (P12):** Static confidence assignment -- same LOW for 1 failure as 10. Fix: dynamic evidence scoring with corroboration modifiers.
- **MEDIUM (P16):** errgroup cancellation cascading -- one target failure cancels all others. Fix: return nil from errgroup for per-target errors.

## Implications for Roadmap

Based on dependency analysis across all four research areas:

### Phase 1: Critical Bug Fixes
**Rationale:** Data corruption bugs (ICMP ID collision, EDNS0 TCP retry) and reliability issues (timeout propagation, errgroup cancellation) must be fixed before adding features. Building on a buggy base compounds technical debt.

**Delivers:** Correct traceroute, reliable DNS probing, bounded scan durations, no cross-target cancellation.

**Addresses pitfalls:** P1 (ICMP ID collision), P2 (EDNS0 TCP retry), P3 (shared per-hop timeout), P7 (timeout propagation), P8 (DNS TCP latency), P15 (QUIC double-timeout), P16 (errgroup cancellation).

**Estimated effort:** Low-medium. Each fix is localized (traceprobe, dnsprobe, quicprobe, scanner).

### Phase 2: Probe Interface Unification
**Rationale:** Foundational refactoring enabling ALL subsequent feature additions. Every new probe (DoH, DoT, WebSocket, ICMP Ping) becomes a single `Probe.Run()` implementation + registration. Without this, adding probes remains costly and error-prone.

**Delivers:**
- `probe.Probe` interface and `ProbeResult` type-erased container
- Middleware wrappers for retry, timeout, logging
- `init()`-based registration in each probe package
- Phase-driven scanner (declarative probe ordering)
- Old standalone functions as internal helpers (backward compat)

**Implementation approach:** Incremental migration. Keep old functions, add thin adapter structs, remove old code after consumer migration.

**Avoids pitfalls:** P12 (middleware can inject tracing), P16 (uniform error handling in scanner).

**Estimated effort:** Medium. Touches all probe packages and scanner.

### Phase 3: Missing Table Stakes
**Rationale:** These features require Phase 2's probe interface for clean implementation. They address the most obvious user-facing gaps.

**Delivers:**
- ICMP Ping probe (PROBE-04) -- reusable ICMP socket, separate from traceroute
- Custom target sets via JSON/YAML configuration file (PROBE-03)
- IPv6 support across all existing probes (PROBE-02)

**Addresses features:** PROBE-02, PROBE-03, PROBE-04.

**Estimated effort:** Medium. Custom targets requires `TargetSource` interface. IPv6 is cross-probe.

### Phase 4: DNS Enhancements
**Rationale:** DNS is the foundation layer. Fixing RCODE handling, adding encrypted DNS transports, and per-resolver rate limiting significantly improves diagnostic signal quality.

**Delivers:**
- RCODE-specific findings (NXDOMAIN, SERVFAIL, REFUSED) with differentiated confidence
- DoH/DoT via `miekg/dns` `Net: "https"` / `Net: "tcp-tls"` -- no new deps
- System resolver RCODE extraction via `miekg/dns` for all resolvers
- Per-resolver rate limiting (20 queries/second default)
- Transparent DNS proxy detection via whoami.akamai.net

**Addresses features:** PROBE-06 (DoH), PROBE-07 (DoT), DNS RCODE handling from P5.

**Avoids pitfalls:** P2 (fresh message for TCP), P5 (RCODE distinction), P10 (system resolver cache), P13 (IPv6 address parsing), P17 (rate limiting).

**Estimated effort:** Medium. Mostly dnsprobe and classifier.

### Phase 5: Classification and Profile Improvements
**Rationale:** Classification consumes probe observations. Improve it after probes produce richer data (RCODE distinction, control/diagnostic separation).

**Delivers:**
- `Detector` interface with composable, registered heuristics
- Dynamic confidence scoring (evidence-weighted, not static)
- Control vs diagnostic target separation in profile computation
- Cross-target correlation pass (control+diagnostic comparison)
- TLS/QUIC divergence detection (UDP blocked finding)

**Avoids pitfalls:** P6 (profile averaging), P12 (static confidence), P21 (DNS agreement across all targets).

**Estimated effort:** Medium-high. New `Detector` interface, refactored classifier, modified profile and recommend.

### Phase 6: Report Format Extensibility
**Rationale:** Report generation is independent. The Formatter strategy pattern can proceed in parallel with other phases.

**Delivers:**
- `Formatter` interface with registry (same pattern as probes)
- HTML self-contained report (REPORT-01) with color-coded protocol table
- CSV/YAML export (REPORT-02)
- `--format` CLI flag replacing `--json`/`--summary`

**Addresses features:** REPORT-01, REPORT-02.

**Estimated effort:** Low-medium. Formatter interface is mechanical; HTML needs template design.

### Phase 7: Advanced Probes
**Rationale:** WebSocket and Proxy probes build on Phase 2's unified interface. Lower priority since no competitor offers them as integrated probes.

**Delivers:**
- WebSocket handshake probe (PROBE-05) via `github.com/coder/websocket`
- Proxy protocol probe (SOCKS5, HTTP CONNECT) (PROBE-08) via `golang.org/x/net/proxy`

**Addresses features:** PROBE-05, PROBE-08.

**Estimated effort:** Medium per probe. Each is a standalone `Probe.Run()`.

### Phase 8: Analysis and Comparison
**Rationale:** Diff mode and trending require all previous phases for stable output and reliable findings.

**Delivers:**
- Scan comparison/diff mode (REPORT-03)
- Historical trend tracking (REPORT-04) -- optional, low priority

**Addresses features:** REPORT-03, REPORT-04.

**Estimated effort:** Medium-high. Diff logic is non-trivial.

### Phase Ordering Rationale

- **Phases 1-2 must precede all others.** Bug fixes prevent data corruption. Probe interface unification is the foundation for all feature additions.
- **Phases 3-4 are independent** once Phase 2 is complete. ICMP Ping, Custom Targets, and IPv6 can proceed in parallel with DNS Enhancements.
- **Phase 5 depends on Phases 3-4** because richer probe data enables better classification.
- **Phase 6 is independent** of Phases 4-5 but benefits from knowing the final observation model.
- **Phases 7-8 are optional** and can be deferred. WebSocket and Proxy probes address niche use cases.

### Research Flags

Phases likely needing deeper research during planning:
- **Phase 3 (IPv6):** Probe-specific IPv6 behavior -- does `crypto/tls` handle IPv6 in SNI differently? Does `quic-go` have IPv6 edge cases? How does ICMPv6 traceroute differ from IPv4?
- **Phase 5 (Classification):** Dynamic confidence model needs validation against real censorship datasets. Modifier weights need empirical tuning.
- **Phase 7 (Advanced Probes):** WebSocket probing in a censorship context is niche. No competitor implements it.

Phases with standard patterns (skip research-phase):
- **Phase 2 (Probe Interface):** Well-documented in OONI's netxlite and ARCHITECTURE.md. Mechanical refactoring.
- **Phase 4 (DNS):** `miekg/dns` DoH/DoT support is documented. RCODE handling is well-understood.
- **Phase 6 (Report Formats):** Standard Go template rendering. Simple CSV writing.

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | HIGH | Verified against official docs and source code. All recommended libraries are production-grade. |
| Features | HIGH | Competitor analysis verified against OONI docs, RBMK source, Censored Planet papers. Feature gaps are well-understood. |
| Architecture | MEDIUM | Proposed architecture is sound (based on OONI netxlite patterns) but not yet implemented. Migration path is unvalidated. |
| Pitfalls | MEDIUM | 22 pitfalls identified from source code and reference architecture review. Project-specific interaction effects between pitfalls are speculative. |

**Overall confidence:** MEDIUM

### Gaps to Address

- **Real censorship data for classifier validation:** Classification heuristics and dynamic confidence model need testing against known censorship events (OONI dataset, Citizen Lab data). Without this, the classifier may produce false positives/negatives not obvious in synthetic tests.
- **IPv6 probe behavior across all protocols:** IPv6 socket behavior differs from IPv4 (dual-stack, ICMPv6 vs ICMPv4, raw socket permissions). Each probe needs IPv6-specific testing.
- **Per-layer timeout values:** Research recommends separate timeouts per probe type (DNS 2-5s, TLS 3-5s, QUIC 5-10s, Trace 1s/hop) but these need empirical validation.
- **Cross-platform ICMP permission handling:** Current `sudo` on macOS vs `setcap` on Linux is documented but permission messaging could be more polished (e.g., provide the setcap command on permission failures).

## Sources

### Primary (HIGH confidence)
- OONI Probe CLI architecture and netxlite documentation -- interface-based probing patterns
- `miekg/dns` v1.x documentation -- DNS probing, DoH/DoT support via Net parameter
- `quic-go` documentation -- QUIC handshake probe, timeout semantics
- Go `crypto/tls` standard library -- TLS handshake probe patterns
- Go `net/http/httptrace` -- HTTP phase-level timing

### Secondary (MEDIUM confidence)
- RBMK project source -- closest architectural cousin, alternative patterns
- Censored Planet CenTrace/CenFuzz -- censorship detection methodology
- Cloudflare Speed Test / M-Lab NDT -- bandwidth test approaches (anti-patterns for iscan)
- RIPE Atlas documentation -- distributed probing, traceroute edge cases
- Citizen Lab test-lists -- target diversity sources

### Tertiary (LOW confidence)
- GFW QUIC DPI research (2025) -- QUIC-specific blocking patterns, single-source, evolving landscape
- `quic-go` v0.39.0+ handshake timeout semantics -- changelog-based, version-specific
- `testing/synctest` proposal -- experimental in Go 1.24, not yet graduated

---
*Research completed: 2026-04-26*
*Ready for roadmap: yes*
