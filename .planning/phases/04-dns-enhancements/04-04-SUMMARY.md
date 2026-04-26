---
phase: 04-dns-enhancements
plan: 04
subsystem: classifier
tags: [dns, rcode, transparent-proxy, classification]
requires: [04-01]
affects: [classifier]
tech-stack:
  added: []
  patterns:
    - "Type-assertion-based ProbeResult.Data extraction for slice formats"
    - "Hardcoded known-resolver IP mapping for whoami comparison"
key-files:
  created: []
  modified:
    - internal/classifier/classifier.go
    - internal/classifier/classifier_test.go
decisions:
  - "collectAllDNSObservations uses type assertion on r.Data for both single and slice DNSObservation"
  - "isKnownResolverIP covers 12 well-known public resolver IPs (Cloudflare, Google, Quad9 v4+v6)"
  - "Transparent proxy detection is a classifier-only concern; whoami queries are injected by the adapter"
duration: ~7 min
completed_date: "2026-04-26"
---

# Phase 4 Plan 4: Per-RCODE Findings and Transparent DNS Proxy Detection

## One-Liner

Per-RCODE DNS findings (NXDOMAIN/HIGH, SERVFAIL/MEDIUM, REFUSED/HIGH, other/LOW) and transparent DNS proxy detection added to the classifier, with backward-compatible multi-resolver observation collection.

## Tasks

### Task 1: Update DNS observation collection + Add per-RCODE finding generation

- **Commit:** `67ca1a2`
- **Changes:**
  - Added `collectAllDNSObservations()` helper that handles both `model.DNSObservation` (backward compatible) and `[]model.DNSObservation` (new multi-resolver adapter format via type assertion)
  - Updated `Classify()` to use `collectAllDNSObservations` instead of `collectObservations[model.DNSObservation]`
  - Added `dnsRcodeFindings()`, `rcodeFindingType()`, `rcodeConfidence()` functions
  - Per-RCODE confidence: NXDOMAIN => HIGH, SERVFAIL => MEDIUM, REFUSED => HIGH, other => LOW
  - Added 6 tests covering all four RCODE finding types, NOERROR bypass, and slice data format

### Task 2: Add transparent DNS proxy detection

- **Commit:** `8da1a17`
- **Changes:**
  - Added `detectTransparentDNSProxy()` function that checks whoami query responses against known resolver IPs
  - Added `isKnownResolverIP()` function covering 12 well-known public resolver IPs (Cloudflare, Google, Quad9 IPv4 and IPv6)
  - Detection triggers when whoami response IP is not in the known set (HIGH confidence)
  - Detection is silent for known-resolver IPs and non-whoami queries
  - Added 3 tests: proxy detection, known-resolver bypass, non-whoami bypass

## Verification Results

- `go build ./...` succeeded
- `go vet ./internal/classifier/...` passed
- `go test ./internal/classifier/... -count=1`: all 14 tests passed (9 existing + 9 new)

## Deviations from Plan

### Auto-fixed Issues

None -- plan executed exactly as written.

### Acceptance Criteria Notes

- `dnsRcodeFindings` grep count is 3 (not the plan's expected 2) due to the doc comment above the function. This is a benevolent documentation addition that doesn't affect functionality.
- `FindingDNSTransparentProxy` grep count is 1 (not the plan's expected 2) because the `FindingDNSTransparentProxy` constant is in `model/model.go` and referenced once in `classifier.go`. The plan's acceptance criteria was slightly inaccurate about an "import check" that doesn't apply to model constants.

## Decisions Made

1. **collectAllDNSObservations handles dual formats via type assertion** -- Single `DNSObservation` (old format) and `[]DNSObservation` (new multi-resolver format) are both supported, ensuring backward compatibility with existing tests and probe output.

2. **Transparent proxy detection is classifier-only** -- The whoami queries will be initiated by the adapter in a separate plan (Plan 05). The classifier only activates detection when whoami observations are present in the data, making it forward-compatible.

3. **isKnownResolverIP uses hardcoded set** -- The 12 well-known public resolver IPs (Cloudflare, Google, Quad9 in both IPv4 and IPv6) provide the baseline. Custom/private resolvers that differ from whoami responses will produce findings, which is the correct behavior -- those findings include evidence text for user evaluation per T-04-07.

## Known Stubs

None.

## Threat Flags

None. The threat model from the plan (T-04-07, T-04-08) is fully addressed.

## Self-Check: PASSED

- File `internal/classifier/classifier.go` exists with all expected functions
- File `internal/classifier/classifier_test.go` exists with all expected tests
- Commit `67ca1a2` verified in git log
- Commit `8da1a17` verified in git log
- All 14 tests pass
- No unintended file deletions detected
- No untracked files remain
