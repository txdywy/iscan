# Phase 1: Critical Bug Fixes - Discussion Log

**Date:** 2026-04-26

## Areas Discussed

### ICMP ID Approach
- **Question:** How to generate per-instance ICMP identifier?
- **Options:** Atomic counter (recommended in PITFALLS.md) / Random ID from crypto/rand
- **Selection:** Random ID from crypto/rand
- **Question:** TimeExceeded inner ICMP validation behavior?
- **Options:** Reject mismatched (strict) / Accept with warning
- **Selection:** Accept with warning

### errgroup Cancellation Isolation
- **Question:** How to isolate per-target cancellation?
- **Options:** Independent context.WithCancel per target (recommended) / Custom error type for errgroup
- **Selection:** Independent context.WithCancel per target
- **Question:** How to handle failed target results?
- **Options:** Return partial results + error (recommended) / Silently skip
- **Selection:** Return partial results + error

### Context Propagation Pattern
- **Question:** How to ensure all probes respect parent deadline?
- **Options:** Child context.WithTimeout per probe (recommended) / Extract deadline and pass as timeout
- **Selection:** Child context.WithTimeout per probe
- **Question:** How to distribute timeout budget across probes?
- **Options:** Even split of remaining parent time (recommended) / Hard-coded per-probe defaults / Configurable per-probe timeouts
- **Selection:** Even split of remaining parent time

### Testing Approach for Fixes
- **Question:** Testing strategy for verifying fixes?
- **Options:** Local test servers / Live network tests (recommended) / Mock interfaces
- **Selection:** Live network tests
- **Question:** Concurrent traceroute test for ICMP ID isolation?
- **Options:** Include concurrent test (recommended) / Skip concurrent test
- **Selection:** Include concurrent test

## Deferred Ideas

None — discussion stayed within phase scope.

## Next Steps
- Phase context written to: `.planning/phases/01-critical-bug-fixes/01-CONTEXT.md`
- Ready for: `/gsd-plan-phase 1`
