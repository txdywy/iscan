# Plan 02-01 Summary: Probe Interface + Type-Erased Container

**Status:** Complete
**Date:** 2026-04-26

## Changes

| File | Change |
|------|--------|
| `internal/probe/probe.go` (NEW) | Probe interface, ProbeFunc adapter, Registry map |
| `internal/model/model.go` (MODIFY) | Added ProbeResult struct; TargetResult: named slices → Results []ProbeResult |

## Verification

- `go vet ./internal/probe/ ./internal/model/` — PASS
- All Layer constants preserved
- All observation types preserved
