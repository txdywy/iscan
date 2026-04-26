# iscan

## What This Is

iscan is a layered network diagnostics CLI tool that runs DNS, TCP, TLS, HTTP, QUIC, and traceroute probes against configurable targets to detect network-level interference. It produces evidence-backed findings (rather than absolute censorship claims), network health profiles, and protocol ranking recommendations.

## Core Value

Detect network censorship — identify DNS/TLS/QUIC/HTTP layer blocking, filtering, and interception with structured evidence that enables users to diagnose what's being blocked and how.

## Requirements

### Validated

- ✓ DNS multi-resolver probing with EDNS0 and TCP fallback — existing
- ✓ TCP connectivity checks with error classification — existing
- ✓ TLS handshake probes with SNI comparison — existing
- ✓ HTTP application-layer probes with redirect prevention — existing
- ✓ QUIC/UDP handshake probes with SNI comparison — existing
- ✓ ICMP traceroute probes — existing
- ✓ Classifier with 9 finding types (DNS inconsistent, suspicious DNS, TCP/TLS/HTTP/QUIC failure, SNI correlated, path quality) — existing
- ✓ Network health profiling (DNS/TCP/TLS/QUIC/Path) — existing
- ✓ Protocol ranking recommendation engine (long-lived/UDP/conservative/redundant) — existing
- ✓ JSON and tabwriter-formatted terminal report output — existing
- ✓ Concurrent multi-target scanning with configurable parallelism — existing
- ✓ Graceful shutdown on SIGINT/SIGTERM — existing
- ✓ Secure retry logic with exponential backoff — existing

### Active

- [ ] **PROBE-01**: Probe retry robustness — systematic edge case handling across all probes
- [ ] **PROBE-02**: IPv6 support for traceroute, DNS, and TCP/TLS probes
- [ ] **PROBE-03**: Custom target set support via JSON file (--target-set path)
- [ ] **PROBE-04**: ICMP Ping probe (independent reachability check, no root required if possible)
- [ ] **PROBE-05**: WebSocket (WS/WSS) handshake probe
- [ ] **PROBE-06**: DNS over HTTPS (DoH) probe
- [ ] **PROBE-07**: DNS over TLS (DoT) probe
- [ ] **PROBE-08**: SOCKS/HTTP proxy protocol probe
- [ ] **REPORT-01**: HTML report output with visual indicators
- [ ] **REPORT-02**: Multi-format export (CSV, YAML)
- [ ] **REPORT-03**: Scan comparison/diff mode (compare two scan results)
- [ ] **REPORT-04**: Long-term trend tracking (store and visualize historical scans)

### Out of Scope

- Real-time packet capture / pcap analysis — not a network sniffer
- TOR/VPN/proxy bypass — diagnostic tool, not circumvention
- GUI or web dashboard — CLI-first, HTML report is the limit
- Mobile app — Unix/macOS CLI tool only

## Context

Personal network diagnostics tool written in Go. Uses standard Go module layout with cmd/ entry point and internal/ packages. Brownfield project with existing codebase map in .planning/codebase/. Previously completed fixes include: signal handling, target validation, configurable parallelism, EDNS0/TCP DNS fallback, QUIC SNI comparison, generic classifier aggregation, MAD jitter, retry with backoff, HTTP trace timing fix, traceroute ICMP validation, DNS TCP fallback error propagation, and QUIC IPv6 address handling.

## Constraints

- **Language**: Go 1.24+ — no other languages
- **Dependencies**: Minimal — current deps are cobra, miekg/dns, quic-go, golang.org/x/{net,sync}
- **Platform**: Cross-platform (macOS, Linux) — CLI only, no GUI
- **Permissions**: Traceroute requires root/ICMP privileges; all other probes run without special permissions
- **Output**: Terminal (tabwriter) + JSON always; HTML/CSV/YAML as additional formats

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| CLI-only, no GUI | Focus on diagnostics, not UI | — Pending |
| Go over Python/Rust | Fast startup, cross-compile, existing Go code | ✓ Good |
| Builtin target set + optional JSON | Quick start without config, extensible | — Pending |
| Probe per protocol (not unified interface) | Simplicity over abstraction at current scale | ✓ Good |
| InsecureSkipVerify for probes | Diagnostic tool — we probe, don't authenticate | ✓ Good |

---

*Last updated: 2026-04-26 after initialization*
