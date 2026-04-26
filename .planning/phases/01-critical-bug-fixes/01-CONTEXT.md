# Phase 1: Critical Bug Fixes - Context

**Gathered:** 2026-04-26
**Status:** Ready for planning

<domain>
## Phase Boundary

Eliminate all documented data-corruption, timeout-propagation, and cancellation-cascade bugs from the existing probe suite so the tool produces correct results and always terminates within bounds. This covers 8 specific fixes across traceroute, DNS, scanner, and QUIC probes. No new features or probes.

**Required fixes:**
1. ICMP identifier collision in traceroute (F-01)
2. EDNS0 preservation on DNS TCP retry (F-02)
3. Per-hop timeout isolation in traceroute
4. Parent context deadline propagation to all probes (F-03)
5. errgroup cascading cancellation (F-04)
6. QUIC double-timeout
7. DNS TCP latency inflation
8. Shared message object across UDP/TCP retry

</domain>

<decisions>
## Implementation Decisions

### ICMP Identifier Approach
- **D-01:** Use `crypto/rand` to generate a random ICMP Echo identifier per `Probe` call, not per process. Replace `os.Getpid() & 0xffff` with a 16-bit random value generated at probe start.
- **D-02:** When a `TimeExceeded` response arrives with a mismatched inner ICMP body (wrong ID/Seq), accept the hop address at face value but record the mismatch as a hop-level warning flag. Do NOT reject the hop — this provides more complete traceroute data while allowing users/future analysis to filter potentially corrupted hops.
- **D-03:** Add a `Mismatch` boolean field to `TraceHop` to flag potentially corrupted hops from ID collisions.

### errgroup Cancellation Isolation
- **D-04:** Replace shared `errgroup.WithContext` with per-target independent `context.WithCancel` derived from the user's main context. Each target goroutine gets its own cancel function so one target's failure does not cancel others.
- **D-05:** Collect target errors in a slice on the scan result, not via errgroup's `Wait()`. Each failed target returns partial results (whatever probes completed) plus an error field. Successful targets return full results as today.

### Context Propagation Pattern
- **D-06:** For each probe within a target's scan sequence, derive a child context via `context.WithTimeout(ctx, share)` where `share` is an even division of the remaining parent timeout across all remaining probes (simple round-robin: remaining_time / remaining_probes).
- **D-07:** Follow this pattern in the scanner's `scanTarget`, not inside individual probe packages — probes already accept a `context.Context` parameter, they just need a proper deadline set.
- **D-08:** Audit all 6 probes (DNS, TCP, TLS, HTTP, QUIC, trace) to ensure they respect `ctx.Done()` and `ctx.Deadline()` properly. Most already check `<-ctx.Done()`; the gap is that no deadline is set on the context passed to them.

### Testing Strategy
- **D-09:** Verify each fix using live network tests (real DNS resolvers, real target hosts). This is consistent with the existing testing pattern in `scanner_test.go`.
- **D-10:** Add a specific concurrent traceroute test that runs two traceroute instances to the same target in parallel and verifies hops are correctly attributed (no cross-contamination).
- **D-11:** Add a unit-level test for ICMP response validation: send crafted `TimeExceeded` packets with mismatched inner IDs and verify they produce a `Mismatch` flag.

### Claude's Discretion
- Exact timeout division formula (fractional seconds rounding, minimum floor per probe)
- Implementation details of the per-target context isolation in scanner
- EDNS0 preservation: whether to reconstruct the full message or just re-attach OPT record
- Hop warning field naming and integration with existing report output
- Test target selection for live network tests (use existing default targets)

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Bug definitions and fix approaches
- `Users/yiwei/iscan/.planning/research/PITFALLS.md` — Documented root causes and prevention for all 8 bugs (P1: ICMP ID, P2: EDNS0, P3: per-hop timeout, P7/P15: context propagation, P16: errgroup cascade, P8: DNS TCP latency)
- `Users/yiwei/iscan/.planning/ROADMAP.md` §12-43 — Phase 1 task descriptions and delivery criteria
- `Users/yiwei/iscan/.planning/REQUIREMENTS.md` §17-26 — F-01 through F-04 requirement definitions (P0)

### Source code (existing patterns to preserve)
- `Users/yiwei/iscan/internal/probe/traceprobe/trace.go` — Current traceroute implementation that needs ICMP ID fix
- `Users/yiwei/iscan/internal/probe/dnsprobe/dns.go` — DNS probe with EDNS0 and TCP fallback
- `Users/yiwei/iscan/internal/scanner/scanner.go` — Scanner with errgroup and retry logic
- `Users/yiwei/iscan/internal/probe/quicprobe/quic.go` — QUIC probe with double-timeout issue
- `Users/yiwei/iscan/internal/model/model.go` — TraceHop, TraceObservation, ScanReport model types

### Architecture context
- `Users/yiwei/iscan/.planning/codebase/ARCHITECTURE.md` — System architecture, probe-scanner relationship
- `Users/yiwei/iscan/.planning/codebase/CONVENTIONS.md` — Code conventions, error handling patterns
- `Users/yiwei/iscan/.planning/codebase/TESTING.md` — Existing test patterns and infrastructure

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `retryWithBackoff[T]` — Generic retry helper already extracted in `scanner.go` during code review, reusable by all probes
- `model.TraceHop` — Has `TTL`, `Address`, `RTT`, `Error` fields; will need `Mismatch bool` added

### Established Patterns
- Per-probe `context.Context` as first parameter — all 6 probes already accept ctx, just need proper deadlines
- `errgroup` with `SetLimit` for bounded parallelism — keep this pattern, just isolate per-target contexts
- Error classification in TCP probe (`classifyTCPError`) — pattern to follow for other error handling

### Integration Points
- `scanner.Run` → `scanTarget` → each probe — all retry/context changes flow through this chain
- Classifier, profile, and report consume probe results — hop warning fields must propagate up through model types
- Existing tests in `scanner_test.go` use live network targets — new tests follow same pattern

</code_context>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope. All 8 fixes are clearly defined and no scope creep occurred.

</deferred>

---

*Phase: 01-critical-bug-fixes*
*Context gathered: 2026-04-26*
