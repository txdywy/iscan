---
phase: 03-missing-table-stakes
plan: 01
subsystem: network-probes
tags: [go, icmp, ping, cli]
requires:
  - phase: 02-probe-interface-unification
    provides: unified Probe interface with Registry, middleware, and adapter pattern
provides:
  - ICMP Ping probe as LayerPing registered in probe.Registry
  - PingObservation model type with Target, Address, RTT, TTL, Latency, Success, Error
  - `iscan ping <target>` standalone CLI subcommand
  - `--icmp-ping` flag on `iscan scan` to include ping in probe suite
affects:
  - 03-03 (IPv6 support will add ICMPv6 echo capability)
  - Phase 8 (scan comparison can compare ping baselines)
tech-stack:
  added: []
  patterns:
    - ICMP echo using golang.org/x/net/icmp (same library as traceroute)
    - Single-shot ping with random probe ID, no retry loop
    - Permission error handling via model.IsLocalPermissionError (matching traceprobe pattern)
key-files:
  created:
    - internal/probe/icmpping/icmp.go
    - internal/probe/icmpping/adapter.go
    - internal/probe/icmpping/icmpping_test.go
  modified:
    - internal/model/model.go
    - internal/scanner/scanner.go
    - cmd/iscan/main.go
key-decisions:
  - "ICMP Ping implemented as independent LayerPing probe, registered via init() in probe.Registry"
  - "Ping is single-shot (one ICMP Echo request, one reply) — no retry loop per T-03-02 acceptance"
  - "Permission errors gracefully captured in PingObservation.Error, surfaced as scanner warnings — matches traceprobe pattern for T-03-01 mitigation"
  - "CLI: `iscan ping <target>` for standalone use, `--icmp-ping` flag on scan for suite inclusion"
patterns-established:
  - "New probes follow adapter pattern: raw Probe function + Adapter struct + init() + probe.Registry"
requirements-completed:
  - F-10
duration: 2min
completed: 2026-04-26
---

# Phase 03 Plan 01: ICMP Ping Probe Summary

**ICMP ping as a first-class LayerPing probe with standalone CLI subcommand and scan-suite integration, using golang.org/x/net/icmp for raw ICMP echo with permission-error-safe degradation**

## Performance

- **Duration:** 2 min
- **Started:** 2026-04-26T15:21:13Z
- **Completed:** 2026-04-26T15:23:26Z
- **Tasks:** 3
- **Files modified:** 6

## Accomplishments

- Added `LayerPing` constant and `PingObservation` struct to model package with Target, Address, RTT, TTL, Latency, Success, and Error fields
- Added `ICMPPing` field to `ScanOptions` enabling conditional inclusion in scan probe list
- Created `internal/probe/icmpping/` package with Probe function (single ICMP Echo request/response), Adapter wrapping into unified Probe interface, and init() registration in probe.Registry
- Permissions errors return as observation.Error (never panics or crashes), matching the traceprobe pattern for T-03-01 threat mitigation
- Wired `iscan ping <target>` cobra subcommand with RTT+TTL output and permission error hint
- Added `--icmp-ping` flag to `iscan scan`, adding LayerPing to probe suite between TLS and HTTP probes
- Permission error warnings in scanner Run() alongside existing trace permission warnings

## Task Commits

Each task was committed atomically:

1. **Task 1: Add model types for ICMP Ping** - `6fc083c` (feat)
2. **Task 2: Implement ICMP ping probe and adapter** - `5c6ee9d` (feat)
3. **Task 3: Wire ICMP Ping into scanner and CLI** - `51481bc` (feat)

## Files Created/Modified

- `internal/model/model.go` - Added LayerPing, PingObservation, ScanOptions.ICMPPing
- `internal/probe/icmpping/icmp.go` - Probe() sends ICMP Echo, parses reply, returns PingObservation
- `internal/probe/icmpping/adapter.go` - Adapter wraps Probe into Probe interface, init() registration
- `internal/probe/icmpping/icmpping_test.go` - Table-driven tests for compile contract and invalid target
- `internal/scanner/scanner.go` - Blank import for side effect, LayerPing in buildProbes, permission warnings
- `cmd/iscan/main.go` - `ping` subcommand, `--icmp-ping` flag on scan

## Decisions Made

- Followed Phase 2 adapter pattern: raw Probe function + Adapter struct wrapping into Probe interface, registered via init() in probe.Registry (matching traceprobe exactly)
- Single-shot ping (no retry loop) per T-03-02 acceptance — network diagnostic, not amplification vector
- Permission errors handled gracefully: error string in PingObservation.Error, scanner surfaces via model.IsLocalPermissionError as warnings, CLI prints permission hint to stderr
- Ping placed between TLS and HTTP in probe ordering (matches logical flow: DNS → TCP → TLS → Ping → HTTP → QUIC → Trace)

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Known Stubs

None - all fields in PingObservation are purposefully populated by Probe().

## Threat Flags

None found — all new surface (raw ICMP socket, PingObservation address field) is explicitly covered in the plan's threat model (T-03-01 mitigated, T-03-02 accepted, T-03-03 accepted).

## Next Phase Readiness

- ICMP Ping probe is ready for IPv6 support in Plan 03-03 (ICMPv6 via `ipv6.ICMPTypeEcho`)
- All existing tests continue to pass (`go test ./...`)
- Full build and vet pass cleanly

---

*Phase: 03-missing-table-stakes*
*Plan: 01*
*Completed: 2026-04-26*
