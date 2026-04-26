# Plan 01-01 Summary: ICMP Traceroute Fixes

**Status:** Complete
**Date:** 2026-04-26

## Changes

| File | Change |
|------|--------|
| `internal/model/model.go` | Added `Mismatch bool \`json:"mismatch"\`` to TraceHop struct |
| `internal/probe/traceprobe/trace.go` | Replaced `os.Getpid()` with `crypto/rand` ICMP ID; added inner ICMP body validation in TimeExceeded; capped per-hop timeout at 2s; exported `ProbeHop` for testing |
| `internal/probe/traceprobe/trace_test.go` | Added 4 tests (2 inner body validation, 1 unique IDs, 1 concurrent isolation) |

## Verification

- `go build ./internal/probe/traceprobe/` — PASS
- `go vet ./internal/probe/traceprobe/ ./internal/model/` — PASS
- `go test ./internal/probe/traceprobe/ -v -timeout 30s` — 4/4 PASS (all skip gracefully without ICMP privileges)

## Decisions Applied

- D-01: crypto/rand ICMP identifier per Probe call
- D-02: Accept TimeExceeded with Mismatch warning, not reject
- D-03: Mismatch bool on TraceHop
- D-10: Concurrent traceroute isolation test
- D-11: Unit test for inner ICMP body validation
