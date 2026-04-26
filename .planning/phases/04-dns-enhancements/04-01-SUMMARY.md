---
phase: 04-dns-enhancements
plan: 01
subsystem: model-types
tags: [dns, resolver, transport, finding-type, go]

# Dependency graph
requires:
  - phase: 02-probe-interface-unification
    provides: model types (Resolver, ScanOptions, FindingType)
provides:
  - Resolver.Transport field for multi-protocol DNS probing
  - 5 DNS RCODE FindingType constants for per-RCODE classification
  - ScanOptions.DNSRateLimit and CustomResolvers fields for probe configuration
  - 4 DoH/DoT builtin resolvers in BuiltinResolvers()
  - DetectTransport helper for URL-prefix based transport detection
  - AddCustomResolvers function for CLI resolver injection
affects: [04-02, 04-03, 04-04, 04-05]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Transport fields for explicit protocol selection on model types"
    - "customResolvers accumulator pattern for CLI resolver injection"

key-files:
  created: []
  modified:
    - internal/model/model.go
    - internal/targets/targets.go

key-decisions:
  - "Transport field values: empty string (udp default), udp, tcp, https (DoH), tcp-tls (DoT), system"
  - "DetectTransport uses URL prefix matching (https:// for DoH, tls:// for DoT)"
  - "BuiltinResolvers() changed from returning a slice literal to base+append pattern"

patterns-established:
  - "Package-level unexported accumulator (customResolvers) for extensibility via public Add function"

requirements-completed: [F-13, N-01]

# Metrics
duration: 12min
completed: 2026-04-27
---

# Phase 04 DNS Enhancements Plan 01: Model Types & Resolver Configuration

**Resolver.Transport field, 5 DNS RCODE FindingType constants, ScanOptions.DNSRateLimit/CustomResolvers, 4 DoH/DoT builtin resolvers, DetectTransport, and AddCustomResolvers for CLI wiring**

## Performance

- **Duration:** 12 min
- **Started:** 2026-04-27T01:02:00Z
- **Completed:** 2026-04-27T01:14:00Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments

- Added `Transport` string field to `model.Resolver` to support per-resolver protocol selection (udp, tcp, https, tcp-tls, system)
- Added 5 new `FindingType` constants for DNS RCODE-based classification: `dns_nxdomain`, `dns_servfail`, `dns_refused`, `dns_other_rcode`, `dns_transparent_proxy`
- Added `DNSRateLimit` (int) and `CustomResolvers` ([]Resolver) fields to `ScanOptions` for probe configuration from CLI
- Added 4 DoH/DoT builtin resolvers: cloudflare-doh, google-doh, cloudflare-dot, google-dot
- Added explicit `Transport` field to all 7 existing builtin resolvers for backward-compatible explicit protocol selection
- Added `DetectTransport(server string)` function parsing `https://` and `tls://` URL prefixes
- Added `AddCustomResolvers([]model.Resolver)` function for CLI resolver injection via package-level accumulator

## Task Commits

Each task was committed atomically:

1. **Task 1: Add Resolver.Transport, FindingType constants, ScanOptions fields** - `c3cc363` (feat)
2. **Task 2: Add DoH/DoT resolvers, DetectTransport, AddCustomResolvers** - `f1cf00b` (feat)

## Files Created/Modified

- `internal/model/model.go` - Added Transport field to Resolver; 5 FindingType constants; DNSRateLimit and CustomResolvers to ScanOptions
- `internal/targets/targets.go` - Added 4 DoH/DoT resolvers; explicit Transport on all resolvers; DetectTransport; AddCustomResolvers; customResolvers accumulator

## Decisions Made

- Transport field values defined as: empty string (defaults to udp), "udp", "tcp", "https" (DoH), "tcp-tls" (DoT), "system"
- DetectTransport uses simple URL prefix matching: `https://` = DoH, `tls://` = DoT, anything else = udp
- Existing resolutors get explicit `Transport: "udp"` for backward compatibility; system resolver gets `Transport: "system"`
- BuiltinResolvers() changed from direct slice literal to base+append pattern to support custom resolvers

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

- The Edit tool's string matching failed on Go struct field definitions containing backtick JSON tags (`json:"...") |`). Used byte-level Python replacement for the ScanOptions struct fields. All other edits used the Edit tool successfully.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- All downstream plans (DNS probe refactor, classifier, CLI) can now reference these types without cascading compilation errors
- Plan 02 (DNS probe refactor) can use Resolver.Transport for protocol-based probe routing
- Plan 03 (classifier) can use the new FindingType constants for RCODE-based classification

---
*Phase: 04-dns-enhancements*
*Completed: 2026-04-27*
