---
phase: 03-missing-table-stakes
plan: 02
subsystem: targets, scanner, cli
tags: [feature, target-source, json, cli]
dependency-graph:
  requires: [02-05]
  provides: [03-01, 03-03]
  affects: [scanner, cmd/iscan]
tech-stack:
  added: []
  patterns: [TargetSource interface, FileSource pattern]
key-files:
  created:
    - internal/targets/targets_test.go
  modified:
    - internal/targets/targets.go
    - internal/model/model.go
    - internal/scanner/scanner.go
    - internal/scanner/scanner_test.go
    - cmd/iscan/main.go
decisions:
  - "SelectSource helper returns BuiltinSource for empty or 'builtin' strings, FileSource for any other path"
  - "FileSource validates each target after JSON decode, rejecting on first validation error"
metrics:
  duration: 3m 55s
  completed: 2026-04-26
---

# Phase 3 Plan 2: Custom Target Sets via JSON File (F-11)

## One-liner

Add TargetSource interface with BuiltinSource and FileSource for loading targets from JSON files, wired through scanner and CLI --target-set flag.

## Tasks Executed

| # | Task | Status | Commit |
|---|------|--------|--------|
| 1 | Add TargetSource interface, BuiltinSource, and FileSource | Done | 8c9fc62 |
| 2 | Add TargetSet field to ScanOptions and update scanner | Done | 51132b6 |
| 3 | Update CLI to wire --target-set to FileSource | Done | 6947225 |
| 4 | Full project verification | Done | 6947225 |

## Commits

- `8c9fc62`: feat(03-missing-table-stakes): add TargetSource interface, BuiltinSource, FileSource
- `51132b6`: feat(03-missing-table-stakes): add TargetSet field and update scanner for TargetSource
- `6947225`: feat(03-missing-table-stakes): wire --target-set CLI flag to FileSource

## Changes

| File | Change |
|------|--------|
| `internal/targets/targets.go` | Added TargetSource interface, BuiltinSource, FileSource, SelectSource helper |
| `internal/targets/targets_test.go` | New file with 8 tests covering FileSource (valid JSON, invalid JSON, validation error, file not found) and SelectSource routing |
| `internal/model/model.go` | Added `TargetSet string` field to ScanOptions |
| `internal/scanner/scanner.go` | Replaced hardcoded `targets.BuiltinTargets()` with `targets.SelectSource(options.TargetSet).Load()` |
| `internal/scanner/scanner_test.go` | Added TestRunAcceptsCustomTargetSet test for builtin default path |
| `cmd/iscan/main.go` | Removed validation block rejecting non-"builtin" target sets, wired TargetSet to ScanOptions |

## Verification

- `go build ./...` — PASS
- `go vet ./...` — PASS (zero warnings)
- `go test ./... -count=1` — PASS (all 16 test packages, 0 failures)

All pre-existing tests pass with zero behavior change. Scanner smoke tests (`TestBuildScanReportSkipsCancelledTargets`, `TestTargetFailureDoesNotCancelOthers`) continue to pass against builtin targets.

## Deviations from Plan

None. Plan executed exactly as written.

## Known Stubs

None.

## Threat Flags

None. The FileSource reads user-provided JSON files validated by `model.Target.Validate()`. No new network endpoints, auth paths, or trust boundaries introduced.

## Self-Check: PASSED

- [x] `internal/targets/targets.go` exists — FOUND
- [x] `internal/targets/targets_test.go` exists — FOUND
- [x] `internal/model/model.go` has TargetSet field — FOUND
- [x] `internal/scanner/scanner.go` uses targets.SelectSource — FOUND
- [x] `cmd/iscan/main.go` wires TargetSet to ScanOptions — FOUND
- [x] Commit 8c9fc62 exists — FOUND
- [x] Commit 51132b6 exists — FOUND
- [x] Commit 6947225 exists — FOUND
- [x] `go test ./... -count=1` passes — CONFIRMED
- [x] `go vet ./...` passes with zero warnings — CONFIRMED
