# Phase 5.03 Summary

Implemented the shared classifier confidence calibrator and wired it into detector output so confidence now comes from corroboration instead of fixed per-finding defaults.

## Highlights
- Added `internal/classifier/confidence.go` with `ConfidenceSignals` and `CalibrateConfidence`.
- Updated classifier output to use the shared calibrator for confidence decisions.
- Preserved the existing `model.Confidence` enum and Phase 4 RCODE behavior.

## Verification
- `go test ./internal/classifier -count=1`
