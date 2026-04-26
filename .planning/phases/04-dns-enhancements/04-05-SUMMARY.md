---
phase: 04-dns-enhancements
plan: 05
subsystem: cli
tags: [dns, doh, dot, rate-limit, cli-flags, whoami]
requires:
  - phase: 04-dns-enhancements-01
    provides: DoH/DoT transports, custom resolver model, DNSRateLimit/CustomResolvers on ScanOptions
  - phase: 04-dns-enhancements-03
    provides: rate limiter (SetRateLimit), multi-resolver adapter
  - phase: 04-dns-enhancements-04
    provides: DetectTransport, AddCustomResolvers functions
provides:
  - --resolver CLI flag with https://, tls://, and plain host URL prefix parsing
  - --dns-rate-limit CLI flag (default 20, 0=unlimited)
  - Custom resolver parsing wired through targets.AddCustomResolvers
  - DNSRateLimit wired to dnsprobe.SetRateLimit() before building probes
  - whoami.akamai.net probing for transparent DNS proxy detection per resolver (skipping system resolver)
affects: [04-classification, 04-research]
tech-stack:
  added: []
  patterns: [CLI flag wiring for DNS features, whoami probing in adapter]
key-files:
  created: []
  modified:
    - cmd/iscan/main.go - Added --resolver, --dns-rate-limit flags; resolver URL parsing; ScanOptions wiring
    - internal/scanner/scanner.go - Added dnsprobe import; SetRateLimit() call with default 20 qps
    - internal/targets/targets.go - Added WhoamiDomain constant (whoami.akamai.net)
    - internal/probe/dnsprobe/adapter.go - Added whoami probing loop per resolver
key-decisions:
  - "CLI flag name --resolver with https:// and tls:// URL prefix parsing (from CONTEXT.md Claude Discretion item)"
  - "whoami.akamai.net as primary whoami target (per CONTEXT.md)"
  - "Rate limiter default burst size 5 (already implemented in Plan 03)"
  - "Default DNS rate limit 20 qps when --dns-rate-limit is not set"
requirements-completed: [F-13, F-05]
duration: 3min
completed: 2026-04-27
---

# Phase 04 Plan 05: CLI Integration and Whoami Probing Summary

**--resolver and --dns-rate-limit CLI flags with URL prefix parsing, wired to DNS rate limiter and custom resolvers, plus whoami.akamai.net transparent proxy probing**

## Performance

- **Duration:** 3 min
- **Started:** 2026-04-27T01:20:00+08:00
- **Completed:** 2026-04-27T01:23:00+08:00
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments
- Added `--resolver` CLI flag accepting `https://`, `tls://`, and bare host addresses with `DetectTransport()` prefix parsing
- Added `--dns-rate-limit` CLI flag (default 20, 0=unlimited) to control per-resolver query rate
- Wired `DNSRateLimit` and `CustomResolvers` from CLI flags through `ScanOptions` to scanner
- Configured `dnsprobe.SetRateLimit()` in `scanner.Run()` with default 20 qps fallback
- Added `WhoamiDomain` constant (`whoami.akamai.net`) to `targets.go` for transparent DNS proxy detection
- Extended DNS adapter to probe `whoami.akamai.net` per resolver (skipping system resolver per D-11)
- Full test suite passes with zero regressions

## Task Commits

Each task was committed atomically:

1. **Task 1: Add --resolver and --dns-rate-limit CLI flags to main.go** - `61f89f6` (feat)
2. **Task 2: Wire DNSRateLimit, custom resolvers, and whoami probing through scanner** - `f394766` (feat)

**Plan metadata:** `pending` (docs: complete 04-05 plan)

## Files Created/Modified

- `cmd/iscan/main.go` - Added `--resolver` and `--dns-rate-limit` CLI flags (StringSliceVar, IntVar), URL prefix parsing with `DetectTransport()`, `AddCustomResolvers()` and `ScanOptions` wiring
- `internal/targets/targets.go` - Added `WhoamiDomain` constant for transparent DNS proxy detection
- `internal/scanner/scanner.go` - Changed dnsprobe import from blank to named, added `SetRateLimit()` call with default 20 qps
- `internal/probe/dnsprobe/adapter.go` - Added whoami probing loop after target domain probing, skipping system resolver

## Decisions Made

- CLI flag name `--resolver` with URL prefix parsing (from CONTEXT.md Claude's Discretion items, following RESEARCH OQ-3)
- `whoami.akamai.net` as primary transparent proxy detection target (per CONTEXT.md fallback recommendation)
- Rate limiter default burst size 5 (already implemented in Plan 03, carried forward)
- Default DNS rate limit of 20 qps configured in scanner when `--dns-rate-limit` is not set (plan-specified default)

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None - all modifications compiled and passed tests on first attempt.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- CLI flags `--resolver` and `--dns-rate-limit` are ready for user-facing usage
- Transparent proxy detection via whoami probing is wired; classification logic in next plan will consume these observations
- Full test suite passes with zero regressions
- Build and vet pass cleanly

---

*Phase: 04-dns-enhancements-05*
*Completed: 2026-04-27*
