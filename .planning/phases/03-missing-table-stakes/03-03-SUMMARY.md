---
phase: 03-missing-table-stakes
plan: 03
status: completed
type: execute
wave: 3
subsystem: all-probes
tags:
  - ipv6
  - dual-stack
  - icmpv6
  - dns-aaaa
  - address-family
requires: [03-01, 03-02]
provides: [PROBE-02]
affects:
  - internal/model/model.go
  - internal/targets/targets.go
  - internal/probe/dnsprobe/adapter.go
  - internal/probe/traceprobe/trace.go
  - internal/probe/traceprobe/adapter.go
  - internal/probe/traprobe/trace_test.go
  - internal/probe/tcp/tcp.go
  - internal/probe/tcp/adapter.go
  - internal/probe/tlsprobe/adapter.go
  - internal/probe/httpprobe/adapter.go
  - internal/probe/quicprobe/adapter.go
  - cmd/iscan/main.go
tech-stack:
  added:
    - golang.org/x/net/ipv6 (for ICMPv6 support)
  patterns:
    - Target.AddressFamily field controls address family selection site-wide
    - Empty AddressFamily = dual-stack = backward compatible
    - Conditional code paths for IPv4 vs IPv6 in traceroute
    - Pre-resolution for TLS adapter to restrict address family while preserving SNI
key-files:
  created: []
  modified:
    - internal/model/model.go: Add AddressFamily field to Target
    - internal/targets/targets.go: Add cloudflare-ipv6, google-ipv6, quad9-ipv6 resolvers
    - internal/probe/dnsprobe/adapter.go: Dual-stack AAAA query support
    - internal/probe/traceprobe/trace.go: ICMPv6 traceroute (ip6:icmp, proto 58, EchoRequest/EchoReply)
    - internal/probe/traceprobe/adapter.go: Pass AddressFamily to Probe
    - internal/probe/tcp/tcp.go: New ProbeNetwork with configurable network
    - internal/probe/tcp/adapter.go: Select tcp4/tcp6 based on AddressFamily
    - internal/probe/tlsprobe/adapter.go: Pre-resolve IP for AddressFamily with SNI preservation
    - internal/probe/httpprobe/adapter.go: net.JoinHostPort for IPv6 URL bracketing
    - internal/probe/quicprobe/adapter.go: Documentation comment
    - cmd/iscan/main.go: Strip brackets from raw IPv6 ping targets
decisions:
  - "AddressFamily empty = dual-stack (backward compatible); no default IP family change"
  - "TLS adapter pre-resolves IP when AddressFamily set; preserves original domain as SNI"
  - "DNS AAAA query added alongside A query for dual-stack targets; merged into single ProbeResult"
  - "QUIC probe needs no code change -- quic-go natively supports IPv6"
metrics:
  duration: 4 minutes
  completed_at: 2026-04-26T23:41:05+08:00
  total_commits: 3
  files_modified: 12
  insertions: 135
  deletions: 22
  tests: all passing (17 test suites)
---

# Phase 03 Plan 03: IPv6 Support Across All Probes

**One-liner:** Added Target.AddressFamily field, IPv6 resolver addresses, dual-stack DNS AAAA queries, ICMPv6 traceroute support, address-family-aware TCP/TLS dialing, IPv6-bracketed HTTP URLs, and CLI bracket stripping for ping targets.

## Objective

Add IPv6 support across all existing probes per D-06/D-07/D-08. DNS probes query AAAA records using IPv6 resolver addresses. Traceroute gains ICMPv6 support for IPv6 targets. TCP and TLS probes restrict address families when Target.AddressFamily is set. HTTP and QUIC probes are verified IPv6-compatible.

## Tasks Executed

| # | Name | Type | Commit | Key Files |
|---|------|------|--------|-----------|
| 1 | Add AddressFamily, IPv6 resolvers, dual-stack DNS | auto | `0a31bc2` | model.go, targets.go, dnsprobe/adapter.go |
| 2 | Add ICMPv6 traceroute support | auto | `4f8c8b0` | traceprobe/trace.go, traceprobe/adapter.go, trace_test.go |
| 3 | Wire AddressFamily into TCP/TLS/HTTP/QUIC adapters and CLI | auto | `9220a5b` | tcp/tcp.go, tcp/adapter.go, tlsprobe/adapter.go, httpprobe/adapter.go, quicprobe/adapter.go, main.go |

## Deviations from Plan

None - plan executed exactly as written.

## Acceptance Criteria Verification

All acceptance criteria verified:

- [x] Target.AddressField field in model.go
- [x] IPv6 resolver entries (cloudflare-ipv6, google-ipv6, quad9-ipv6) in targets.go
- [x] AAAA query support in dnsprobe/adapter.go (TypeAAAA, AddressFamily condition)
- [x] ICMPv6 support in traceprobe (ip6:icmp, ipv6 types, proto 58, SetHopLimit)
- [x] AddressFamily passed from adapter to traceprobe Probe
- [x] TCP adapter uses ProbeNetwork with tcp4/tcp6 based on AddressFamily
- [x] TLS adapter pre-resolves IP for AddressFamily with net.LookupIP
- [x] HTTP adapter uses net.JoinHostPort for IPv6 URL bracketing
- [x] CLI normalizes bracketed IPv6 input in ping command
- [x] `go build ./...` succeeds
- [x] `go vet ./...` succeeds
- [x] `go test ./...` passes all 17 test suites

## Verification

Build, vet, and all tests pass. See `go test ./...` output in execution log.

```bash
go build ./...    # success
go vet ./...      # success
go test ./...     # 17 suites, all ok
```

## Notes

- Task 2 required updating `trace_test.go` to match new ProbeHop and Probe signatures (3 call sites fixed as deviation Rule 3)
- QUIC probe needed zero code changes -- quic-go's `quic.DialAddr` natively handles IPv6
- The ICMPv6 TimeExceeded inner-packet validation (mismatch detection) works identically for IPv4 and IPv6 since the ICMP header layout is the same per the plan
- All existing functionality preserved: AddressFamily empty = dual-stack = original behavior

## Self-Check: PASSED

All 12 modified files confirmed present, all 3 commits confirmed in git log.
