---
phase: 04-dns-enhancements
plan: 02
subsystem: dns-probe
tags: [dns, doh, dot, tls, miekg-dns, transport-dispatcher]

# Dependency graph
requires:
  - phase: 04-dns-enhancements-01
    provides: Resolver.Transport field on model.Resolver
provides:
  - Transport dispatcher in Probe() switching on resolver.Transport
  - dohQuery() DoH probe via HTTP POST with DNS wire format
  - dotQuery() DoT probe via miekg/dns tcp-tls client
  - systemResolverQuery() using net.DefaultResolver.LookupHost
affects: [04-dns-enhancements-03, 04-dns-enhancements-04, 04-dns-enhancements-05]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - Transport dispatcher pattern (switch on resolver.Transport)
    - DoH via Go stdlib net/http with DNS wire format
    - DoT via miekg/dns Client{Net: "tcp-tls"}

key-files:
  created:
    - internal/probe/dnsprobe/doh.go (DoH query implementation)
    - internal/probe/dnsprobe/doh_test.go (DoH unit tests)
    - internal/probe/dnsprobe/dot.go (DoT query implementation)
    - internal/probe/dnsprobe/dot_test.go (DoT unit tests)
  modified:
    - internal/probe/dnsprobe/dns.go (refactored Probe into dispatcher + udpQuery + systemResolverQuery)

key-decisions:
  - "DoH uses InsecureSkipVerify: true on http.Client Transport — consistent with all other probes (diagnostic tool key decision)"
  - "DoT defaults to port 853 (not 53) — per RFC 7858"
  - "DoH sends application/dns-message via HTTP POST to https://{server}/dns-query — miekg/dns does not support Net:https"

patterns-established:
  - "Transport dispatcher: Probe() delegates to per-transport implementation functions"
  - "systemResolverQuery maps net.DNSError types to RCODEs (NXDOMAIN, SERVFAIL)"
  - "Error prefixing: doh: for DoH errors, dot: for DoT errors"

requirements-completed: [F-13, N-01]

# Metrics
duration: 4min
completed: 2026-04-27
---

# Phase 4 Plan 2: DNS Transport Dispatcher with DoH, DoT, and System Resolver

**Refactored DNS Probe() into a transport dispatcher with udpQuery, dohQuery (DNS over HTTPS via HTTP POST with DNS wire format), dotQuery (DNS over TLS via miekg/dns tcp-tls), and systemResolverQuery (via net.DefaultResolver.LookupHost)**

## Performance

- **Duration:** 4 min 15 sec
- **Started:** 2026-04-27T01:08:20Z
- **Completed:** 2026-04-27T01:12:35Z
- **Tasks:** 3/3
- **Files modified:** 5

## Accomplishments

- Refactored Probe() from a single UDP implementation into a transport dispatcher that switches on resolver.Transport
- Extracted legacy UDP/TCP behavior into udpQuery() — existing tests pass unchanged
- Implemented DoH (DNS over HTTPS) via Go stdlib HTTP POST with DNS wire format (application/dns-message) to https://{server}/dns-query
- Implemented DoT (DNS over TLS) via miekg/dns Client{Net: "tcp-tls"} with InsecureSkipVerify, port 853 default
- Implemented systemResolverQuery using net.DefaultResolver.LookupHost with net.DNSError to RCODE mapping
- Added comprehensive test coverage for all new transports

## Task Commits

Each task was committed atomically:

1. **Task 1: Refactor dns.go — extract udpQuery, add transport dispatcher, add systemResolverQuery** - `aeaff04` (refactor)
2. **Task 2: Create doh.go with dohQuery implementation + doh_test.go** - `5d80f15` (feat)
3. **Task 3: Create dot.go with dotQuery implementation + dot_test.go** - `ec7124e` (feat)

## Files Created/Modified

- `internal/probe/dnsprobe/dns.go` - Refactored: Probe() is now a transport dispatcher; original body moved to udpQuery(); added systemResolverQuery()
- `internal/probe/dnsprobe/doh.go` - New: dohQuery() implementing DNS over HTTPS via HTTP POST with DNS wire format
- `internal/probe/dnsprobe/doh_test.go` - New: TestProbeDoH (httptest.NewTLSServer) and TestProbeDoHError
- `internal/probe/dnsprobe/dot.go` - New: dotQuery() implementing DNS over TLS via miekg/dns Client{Net: "tcp-tls"}
- `internal/probe/dnsprobe/dot_test.go` - New: TestProbeDoT (local TLS DNS server) and TestProbeDoTDefaultPort

## Decisions Made

- DoH uses InsecureSkipVerify: true on the http.Client Transport — consistent with all other probes (diagnostic tool, per PROJECT.md key decision). This was not explicitly stated in the plan but is required for compatibility with self-signed DoH endpoints (Rule 2, N-06).
- DoT defaults to port 853 (not 53) per RFC 7858 (Pitfall 4 from RESEARCH.md).
- systemResolverQuery maps net.DNSError.IsNotFound to NXDOMAIN and net.DNSError.IsTemporary to SERVFAIL for consistent RCODE reporting.
- DoT truncated response handling retries on the same TCP-TLS connection (TCP handles large responses natively).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing Critical] Added InsecureSkipVerify to DoH HTTP client**
- **Found during:** Task 2 (doh.go creation)
- **Issue:** The plan specified `&http.Client{Timeout: timeout}` without TLS config. The test uses `httptest.NewTLSServer` (self-signed cert), which would fail SSL verification. Additionally, iscan is a diagnostic tool that probes endpoints without authenticating — per PROJECT.md key decision "InsecureSkipVerify for probes", all probes should use InsecureSkipVerify.
- **Fix:** Changed `&http.Client{Timeout: timeout}` to include `Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}`. Added `"crypto/tls"` to imports.
- **Files modified:** internal/probe/dnsprobe/doh.go
- **Verification:** TestProbeDoH passes (httptest.NewTLSServer), go build passes, go vet passes
- **Committed in:** 5d80f15 (Task 2 commit)

**2. [Rule 3 - Blocking] Created dot.go stub during Task 2 to enable compilation**
- **Found during:** Task 2 (build fails without dotQuery defined)
- **Issue:** Task 1 created a Probe() dispatcher that references dohQuery() and dotQuery(), but dotQuery() is defined in Task 3. The Go compiler requires all referenced symbols to exist, preventing Task 2 tests from compiling.
- **Fix:** Created a minimal stub dot.go returning an error observation to enable compilation during Task 2. The stub was overwritten with the full implementation in Task 3.
- **Files modified:** internal/probe/dnsprobe/dot.go (temporary stub, then full implementation)
- **Verification:** All tests pass in final verification
- **Committed in:** 5d80f15 (Task 2 commit — stub), ec7124e (Task 3 commit — full implementation)

**Note:** The stub was fully replaced in Task 3 and does not appear in the final codebase. This is expected for sequential auto-tasks within the same autonomous plan.

---

**Total deviations:** 2 auto-fixed (1 missing critical, 1 blocking)
**Impact on plan:** Both auto-fixes necessary for correctness and compilation. No scope creep.

## Issues Encountered

- Sequential compilation dependency: Task 1 creates a dispatcher referencing functions defined in Tasks 2 and 3, preventing individual task builds. Handled by creating a temporary stub for dotQuery during Task 2, replaced in Task 3.
- DoH TLS trust: httptest.NewTLSServer uses self-signed certs, requiring InsecureSkipVerify on the DoH client. Consistent with all other probes in iscan.

## Verification Results

```text
=== go build ./... ===
PASS

=== go test ./internal/probe/dnsprobe/... -v -count=1 ===
=== RUN   TestProbeARecordsFromResolver --- PASS: TestProbeARecordsFromResolver (0.00s)
=== RUN   TestProbeHandlesMissingPort --- PASS: TestProbeHandlesMissingPort (0.00s)
=== RUN   TestProbeRetriesOverTCPWhenTruncated --- PASS: TestProbeRetriesOverTCPWhenTruncated (0.00s)
=== RUN   TestProbeMarksTruncatedTCPFallbackFailureAsFailure --- PASS: TestProbeMarksTruncatedTCPFallbackFailureAsFailure (0.00s)
=== RUN   TestProbeDoH --- PASS: TestProbeDoH (0.01s)
=== RUN   TestProbeDoHError --- PASS: TestProbeDoHError (0.00s)
=== RUN   TestProbeDoT --- PASS: TestProbeDoT (0.00s)
=== RUN   TestProbeDoTDefaultPort --- PASS: TestProbeDoTDefaultPort (0.00s)
PASS

=== go vet ./internal/probe/dnsprobe/... ===
PASS
```

## Next Phase Readiness

- Transport dispatcher foundation complete — all DNS transports (udp, tcp, https, tcp-tls, system) fully implemented
- Ready for Phase 4 Plan 3 (scanner integration and config wiring for DoH/DoT resolvers)

## Self-Check

- [x] `func udpQuery` exists in dns.go (1 match)
- [x] `func systemResolverQuery` exists in dns.go (1 match)
- [x] `func Probe` remains exported in dns.go (1 match — dispatch only)
- [x] Dispatcher cases: https, tcp-tls, system, default (all present)
- [x] DefaultResolver.LookupHost used in systemResolverQuery
- [x] `func dohQuery` exists in doh.go (1 match)
- [x] application/dns-message headers set in doh.go
- [x] http.NewRequestWithContext used for DoH POST
- [x] msg.Pack() and dnsResp.Unpack() used in doh.go
- [x] TestProbeDoH and TestProbeDoHError exist in doh_test.go
- [x] `func dotQuery` exists in dot.go (1 match)
- [x] Net:"tcp-tls" configured in dot.go (1 match)
- [x] InsecureSkipVerify: true configured in dot.go (1 match)
- [x] :853 port default in dot.go (1 match)
- [x] TestProbeDoT and startDoTServer exist in dot_test.go
- [x] go build ./... succeeds
- [x] go test ./internal/probe/dnsprobe/... -count=1 passes (8/8 tests)
- [x] go vet ./internal/probe/dnsprobe/... passes

## Success Criteria Validation

- [x] Probe() is a transport dispatcher switching on resolver.Transport
- [x] Existing UDP/TCP behavior preserved as udpQuery() — existing tests pass
- [x] dohQuery() sends DNS wire-format via HTTP POST to https://{server}/dns-query
- [x] dotQuery() uses miekg/dns Client{Net: "tcp-tls"} with InsecureSkipVerify, port 853
- [x] systemResolverQuery() uses net.DefaultResolver.LookupHost with DNSError mapping
- [x] DoH and DoT tests verify against local test servers
- [x] No new external dependencies

---
*Phase: 04-dns-enhancements*
*Plan: 02*
*Completed: 2026-04-27*
