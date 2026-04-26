---
phase: 04-dns-enhancements
plan: 03
subsystem: dnsprobe
tags:
  - rate-limiting
  - per-resolver
  - adapter-refactor
  - multi-resolver
dependency_graph:
  requires:
    - "04-dns-enhancements-02 (DoH/DoT probes)"
    - "04-dns-enhancements-01 (targets.BuiltinResolvers, custom resolvers)"
  provides:
    - "Per-resolver rate limiting for DNS probes"
    - "Multi-resolver adapter output ([]DNSObservation)"
  affects:
    - "04-dns-enhancements-04 (classifier must handle []DNSObservation slice)"
    - "04-dns-enhancements-05 (scanner wiring for SetRateLimit)"
tech-stack:
  added:
    - "golang.org/x/time v0.15.0 (token bucket rate limiter)"
  patterns:
    - "sync.Map keyed by resolver name for per-resource state"
    - "waitLimiter before each Probe() call in adapter"
key-files:
  created:
    - "internal/probe/dnsprobe/ratelimit.go"
    - "internal/probe/dnsprobe/ratelimit_test.go"
  modified:
    - "internal/probe/dnsprobe/adapter.go"
decisions:
  - "Burst size 5 for 20 qps default (Claude's Discretion)"
  - "SetRateLimit on new limiters only; existing limiters keep old rate (accepted pitfall)"
  - "Test file uses package dnsprobe (not dnsprobe_test) to access unexported rate limiter functions"
metrics:
  duration: "2026-04-26T17:16:23Z to ~17:19:00Z (~3 min)"
  completed_date: "2026-04-26"
---

# Phase 4 Plan 3: Per-resolver Rate Limiting and Adapter Refactor Summary

Per-resolver token bucket rate limiter (20 qps default, 5 burst) using `golang.org/x/time/rate` and multi-resolver adapter that iterates all configured resolvers with per-resolver rate limiting, returning aggregated `[]DNSObservation`.

## Tasks Completed

| # | Name | Commit | Files |
|---|------|--------|-------|
| 1 | Create ratelimit.go with per-resolver token bucket + ratelimit_test.go | `c8342b2` | `internal/probe/dnsprobe/ratelimit.go`, `internal/probe/dnsprobe/ratelimit_test.go`, `go.mod`, `go.sum` |
| 2 | Update adapter.go -- multi-resolver iteration with rate limiting | `9c61923` | `internal/probe/dnsprobe/adapter.go` |

## Deviations from Plan

None - plan executed exactly as written.

## Verification Results

- `go build ./...` -- PASS
- `go vet ./...` -- PASS
- `go test ./internal/probe/dnsprobe/... -count=1` -- PASS (11 tests: 4 existing + 3 new rate limiter + 4 DoH/DoT)
- `go test ./... -count=1` -- PASS (all packages, no regressions)

## Success Criteria

1. [x] ratelimit.go provides per-resolver token bucket rate limiter (20 qps, 5 burst)
2. [x] SetRateLimit(int) allows overriding default rate
3. [x] waitLimiter(ctx, name) blocks until token available or context cancelled
4. [x] Tests verify limiter sharing, context cancellation, unlimited mode
5. [x] adapter.go iterates all resolvers, probes A + AAAA, applies rate limiting
6. [x] Adapter returns []DNSObservation as ProbeResult.Data
7. [x] golang.org/x/time/rate added to go.mod (direct deps: 5 to 6)
8. [x] Build succeeds with zero errors

## Known Stubs

None.

## Threat Flags

None -- threat register items T-04-05 (DoS mitigation via token bucket) and T-04-06 (information disclosure, accepted) are fully addressed.

## Self-Check: PASSED

- `internal/probe/dnsprobe/ratelimit.go` -- present and contains all required functions
- `internal/probe/dnsprobe/ratelimit_test.go` -- present and contains all 3 required tests
- `internal/probe/dnsprobe/adapter.go` -- modified with empty Adapter{}, multi-resolver loop, rate limiting
- Commit `c8342b2` -- verified in git log
- Commit `9c61923` -- verified in git log
