# Plan 01-02 Summary: errgroup Cancellation Isolation

**Status:** Complete
**Date:** 2026-04-26

## Changes

| File | Change |
|------|--------|
| `internal/model/model.go` | Added `Error string \`json:"error,omitempty"\`` to TargetResult struct |
| `internal/scanner/scanner.go` | Replaced `errgroup.WithContext` with per-target `context.WithCancel`; goroutines always return nil; errors collected in TargetResult.Error |
| `internal/scanner/scanner_test.go` | Added `TestTargetFailureDoesNotCancelOthers` integration test |

## Verification

- `go build ./internal/scanner/` — PASS
- `go vet ./internal/scanner/ ./internal/model/` — PASS
- `go test ./internal/scanner/ -v -timeout 30s` — 6/6 PASS (including new test: 4 targets scanned in 11.4s)

## Decisions Applied

- D-04: Per-target context.WithCancel instead of shared errgroup.WithContext
- D-05: Target errors in TargetResult.Error, not via errgroup.Wait()
