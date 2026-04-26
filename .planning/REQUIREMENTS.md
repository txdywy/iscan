# iscan — Requirements

## Overview

iscan is a layered network diagnostics CLI that probes DNS, TCP, TLS, HTTP, QUIC, and traceroute against configurable targets to detect network-level interference. It produces evidence-backed findings, network health profiles, and protocol ranking recommendations.

## Scoping Principles

1. **Depth over breadth** — per-probe diagnostic detail matters more than covering every protocol. iscan competes with actionable output (protocol ranking), not test count.
2. **CLI-first** — terminal + JSON output is the product. HTML/CSV/YAML are supplementary export formats.
3. **Zero new dependencies for core capabilities** — DoH/DoT and SOCKS5 are available from already-present dependencies.
4. **Fix before feature** — critical data-integrity bugs (ICMP ID collision, EDNS0 TCP retry, errgroup cascading) block feature expansion.
5. **Not a circumvention tool** — diagnostics only. No TOR/VPN/proxy bypass, no packet capture, no mobile app.

## Functional Requirements

### Priority: P0 (Must Have)

| ID | Requirement | Source |
|----|-------------|--------|
| F-01 | Traceroute must not corrupt hop data under concurrent use — per-instance ICMP ID, validate inner ICMP in TimeExceeded | PITFALLS P1 |
| F-02 | DNS TCP fallback must preserve EDNS0 options — fresh message on TCP retry | PITFALLS P2 |
| F-03 | All probes must respect parent context deadline — no probe hangs beyond scan timeout | PITFALLS P7, P15, P16 |
| F-04 | errgroup cancellation must be per-target only — one target failure must not cancel remaining targets | PITFALLS P16 |
| F-05 | DNS RCODEs must be surfaced separately — NXDOMAIN, SERVFAIL, REFUSED distinguished | PITFALLS P5 |

### Priority: P1 (Should Have)

| ID | Requirement | Source |
|----|-------------|--------|
| F-06 | Unified `Probe` interface with `ProbeResult` type-erased container — all probes implement same signature | ARCHITECTURE |
| F-07 | Middleware wrappers for retry, timeout, logging — cross-cutting concerns not duplicated per probe | STACK, ARCHITECTURE |
| F-08 | `init()`-based probe registration — new protocols register themselves, no scanner changes | ARCHITECTURE |
| F-09 | Control vs diagnostic target separation in profile computation — profile excludes control targets | PITFALLS P6 |
| F-10 | ICMP Ping probe — independent reachability check, no root required if possible | PROBE-04 |
| F-11 | Custom target sets via JSON file (`--target-set path`) | PROBE-03 |
| F-12 | IPv6 support for traceroute, DNS, TCP/TLS probes | PROBE-02 |
| F-13 | DoH and DoT probe support via `miekg/dns` transport selector (no new deps) | PROBE-06, PROBE-07 |
| F-14 | Self-contained HTML report with color-coded protocol status table | REPORT-01 |

### Priority: P2 (Nice to Have)

| ID | Requirement | Source |
|----|-------------|--------|
| F-15 | Dynamic confidence scoring — evidence-weighted, not static per finding type | PITFALLS P12 |
| F-16 | `Detector` interface with composable registered heuristics — decoupled from classifier | ARCHITECTURE |
| F-17 | Cross-target correlation pass — compares control vs diagnostic findings | ARCHITECTURE |
| F-18 | CSV and YAML report export | REPORT-02 |
| F-19 | WebSocket (WS/WSS) handshake probe | PROBE-05 |
| F-20 | SOCKS/HTTP proxy protocol probe | PROBE-08 |
| F-21 | Scan comparison/diff mode (compare two scan results) | REPORT-03 |
| F-22 | Long-term trend tracking (store and visualize historical scans) | REPORT-04 |

### Out of Scope
- Real-time packet capture / pcap analysis
- TOR/VPN/proxy bypass or circumvention
- GUI or web dashboard
- Mobile app
- Bandwidth speed tests
- Cloud database or centralized data sharing

## Non-Functional Requirements

| ID | Requirement | Rationale |
|----|-------------|-----------|
| N-01 | No new external dependencies for core probe functionality | DoH/DoT/SOCKS5 available from existing deps |
| N-02 | Cross-platform (macOS + Linux) | CLI tool — no OS-specific code beyond ICMP |
| N-03 | Sequential probes within a target, parallel across targets (errgroup with SetLimit) | Layered diagnostics need ordering within target |
| N-04 | Graceful SIGINT/SIGTERM shutdown with partial results | User patience, long-running scans |
| N-05 | JSON always produced; HTML/CSV/YAML as `--format` flag | Structured output for pipelines |
| N-06 | `InsecureSkipVerify: true` for TLS/QUIC probes | Diagnostic tool, not authentication |
| N-07 | All probes must complete within bounded time (parent context deadline) | Prevent hangs, predictable UX |
| N-08 | Dependency budget: ≤ 10 direct dependencies | Minimal surface area for security review |
| N-09 | Traceroute requires root/ICMP privileges; all other probes without special permissions | UX — minimize friction for common use |
| N-10 | EDNS0 enabled on all DNS queries by default | Signal quality — detect middlebox interference |

## Constraints

- Language: Go 1.24+
- Module layout: `cmd/` for entry point, `internal/` for packages
- Current dependencies: cobra, miekg/dns, quic-go, golang.org/x/{net,sync}
- All new probes must fit within the `internal/probe/` package structure
- Classifier stays in `internal/classifier/`
- Profiles and recommendations stay in `internal/profile/` and `internal/recommend/`
- Reports stay in `internal/report/`

## Traceability

| ID | Requirement | Phase | Priority |
|----|-------------|-------|----------|
| F-01 | Traceroute no ICMP ID collision — per-instance atomic ID, validate inner ICMP | Phase 1 | P0 |
| F-02 | DNS TCP fallback preserves EDNS0 options | Phase 1 | P0 |
| F-03 | All probes respect parent context deadline | Phase 1 | P0 |
| F-04 | errgroup per-target cancellation only | Phase 1 | P0 |
| F-05 | DNS RCODEs surfaced separately | Phase 4 | P0 |
| F-06 | Unified `Probe` interface with `ProbeResult` | Phase 2 | P1 |
| F-07 | Middleware wrappers (retry, timeout, logging) | Phase 2 | P1 |
| F-08 | `init()`-based probe registration | Phase 2 | P1 |
| F-09 | Control vs diagnostic target separation in profile | Phase 5 | P1 |
| F-10 | ICMP Ping probe | Phase 3 | P1 |
| F-11 | Custom target sets via `--target-set` | Phase 3 | P1 |
| F-12 | IPv6 support for traceroute, DNS, TCP/TLS | Phase 3 | P1 |
| F-13 | DoH and DoT probe support | Phase 4 | P1 |
| F-14 | Self-contained HTML report | Phase 6 | P1 |
| F-15 | Dynamic confidence scoring | Phase 5 | P2 |
| F-16 | `Detector` interface with composable heuristics | Phase 5 | P2 |
| F-17 | Cross-target correlation pass | Phase 5 | P2 |
| F-18 | CSV and YAML report export | Phase 6 | P2 |
| F-19 | WebSocket (WS/WSS) handshake probe | Phase 7 | P2 |
| F-20 | SOCKS/HTTP proxy protocol probe | Phase 7 | P2 |
| F-21 | Scan comparison/diff mode | Phase 8 | P2 |
| F-22 | Long-term trend tracking | Phase 8 | P2 |
| N-01 | No new external deps for core probe functionality | Phase 4, Phase 7 (trade-off) | — |
| N-02 | Cross-platform (macOS + Linux) | All phases | — |
| N-03 | Sequential probes per target | Phase 2 | — |
| N-05 | JSON always; `--format` flag | Phase 6 | — |
| N-07 | Bounded completion time | Phase 1, Phase 2 | — |
| N-10 | EDNS0 enabled by default | Phase 1 (TCP retry fix) | — |

---
*Derived from research-informed scoping, 2026-04-26*
