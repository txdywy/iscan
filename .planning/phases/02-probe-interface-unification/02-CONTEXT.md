# Phase 2: Probe Interface Unification - Context

**Gathered:** 2026-04-26
**Status:** Ready for planning

<domain>
## Phase Boundary

Refactor all 6 existing probes (DNS, TCP, TLS, HTTP, QUIC, traceroute) to implement a unified `Probe` interface with type-erased `ProbeResult` containers and composable middleware (retry, timeout, logging). Replace `init()`-based probe registration and refactor the scanner from imperative per-probe callsites to declarative phase-driven execution. This is a pure refactoring phase — zero behavior change, zero new features.

**Requirements addressed:** F-06 (unified interface), F-07 (middleware), F-08 (init registration)

</domain>

<decisions>
## Implementation Decisions

### Probe Interface Signature
- **D-01:** Use a `Run(ctx, target, opts) Result` signature. Each probe defines its own config struct (`Opts`) containing probe-specific parameters (e.g., SNI for TLS, resolver list for DNS, ALPN for TLS/QUIC). The base `Target` argument provides domain/host/port. The scanner passes the opts struct at registration/configuration time, not per-call.
- **D-02:** The opts struct is passed when constructing the Probe (not per Run), so the interface stays uniform: `Probe.Run(ctx, Target) ProbeResult`. Probe-specific config is set via a separate `WithOpts(opts)` middleware or constructor parameter.

### Type-Erased Result Container
- **D-03:** Use `[]ProbeResult` discriminated union where each element has `Type Layer` + `Data any`. Layer constants from `model.Layer` (dns/tcp/tls/http/quic/trace) identify the result type. The classifier, profile, and report iterate over results by Layer instead of accessing named fields.
- **D-04:** `TargetResult` changes from per-probe named slices to a single `Results []ProbeResult` field plus the existing `Findings []Finding`. This is the core breaking change that enables adding new protocols without struct changes.

### Middleware Composition
- **D-05:** Functional middleware pattern: `type Middleware func(Probe) Probe`. Composability via `middleware.Chain(probe, timeoutMiddleware, retryMiddleware, loggingMiddleware)`.
- **D-06:** Order (outermost to innermost): Timeout → Retry → Logging. The timeout wraps everything, retry wraps the base probe, logging wraps innermost.
- **D-07:** Middleware implementations live in `internal/probe/middleware/` package.

### Scanner Phase-Driven Execution
- **D-08:** Scanner uses a simple `[]Probe` list to drive execution. No structured Phase struct. Probe selection (e.g., trace only if --trace, QUIC only if --quic) is done at registry construction time — the scanner receives only the probes that should run for this scan.
- **D-09:** Probe ordering within a target is sequential (DNS → TCP → TLS → HTTP → QUIC → trace), matching current behavior.

### Probe Registration
- **D-10:** Global registry in `internal/probe/probe.go`: `var Registry = map[Layer]Probe{}`. Each probe package (e.g., `internal/probe/dnsprobe/`) registers via `init()`: `func init() { probe.Registry[model.LayerDNS] = &Adapter{} }`.
- **D-11:** Scanner imports probe packages for side effects to trigger `init()` registration.

### Migration Path
- **D-12:** Big bang refactoring — all changes in one phase execution. This is feasible because: (a) all changes are internal to `internal/` packages, (b) no external API change, (c) existing tests serve as regression checks, (d) the codebase is moderate size (~2000 lines across all probes + scanner).
- **D-13:** Old standalone probe functions (`dnsprobe.Probe`, `tcp.Probe`, etc.) are replaced by the new interface. They are not kept as helpers — the one-shot migration removes them entirely. The scanner and all consumers switch to the interface at once.

### Claude's Discretion
- Derivation of opts structs for each probe (field names, defaults)
- Middleware implementation details (timeout computation, retry backoff reuse, logging format)
- `ProbeResult` struct field names and JSON tags
- Registry initialization order and error handling
- Test adaptation strategy (which tests need rewriting vs which still pass)

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Probe interface and scanner architecture
- `.planning/codebase/ARCHITECTURE.md` — Current architecture: probes are hardcoded in scanTarget, no interface, no registry
- `.planning/codebase/STACK.md` — Technology stack: interface{} typing, errgroup concurrency pattern
- `.planning/REQUIREMENTS.md` §41-43 — F-06, F-07, F-08 requirement definitions

### Current probe implementations (existing signatures to unify)
- `internal/probe/dnsprobe/dns.go` — DNS probe: Probe(ctx, resolver, domain, qtype, timeout) DNSObservation
- `internal/probe/tcp/tcp.go` — TCP probe: Probe(ctx, host, port, timeout) TCPObservation
- `internal/probe/tlsprobe/tls.go` — TLS probe: Probe(ctx, host, port, sni, nextProtos, timeout, insecureSkipVerify) TLSObservation
- `internal/probe/httpprobe/http.go` — HTTP probe: Probe(ctx, url, timeout) HTTPObservation; ProbeWithAddress(ctx, url, dialAddress, timeout)
- `internal/probe/quicprobe/quic.go` — QUIC probe: Probe(ctx, host, port, sni, alpn, timeout) QUICObservation
- `internal/probe/traceprobe/trace.go` — Trace probe: Probe(ctx, target, timeout) TraceObservation; ProbeHop exported for testing

### Model types (consumer patterns to understand)
- `internal/model/model.go` — TargetResult with per-probe named slices; Layer constants (DNS/TCP/TLS/HTTP/QUIC/Trace); observation types per protocol; ScanReport; Finding
- `internal/scanner/scanner.go` — Current per-probe callsites in scanTarget (lines ~85-210); retryWithBackoff helper; probeContext helper (Phase 1 addition)
- `internal/classifier/classifier.go` — How findings are extracted per observation type
- `internal/profile/profile.go` — How profiles consume TargetResult fields per layer
- `internal/report/report.go` — How reports serialize TargetResult fields
</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `retryWithBackoff[T]` in `internal/scanner/scanner.go` — Generic retry helper, should be reused in retry middleware
- `probeContext(ctx, timeout)` in `internal/scanner/scanner.go` — Context deadline derivation helper, should be reused in timeout middleware
- `model.Layer` constants — Already exist for all 6 probe types, maps directly to registry keys

### Established Patterns
- **Pure functions with data-in/data-out:** Current probes take params + ctx, return observations — the new interface follows this same pattern
- **No dependency injection, no interfaces, no plugin system:** This is precisely the gap Phase 2 fills — introducing interfaces and registration
- **errgroup-based concurrent scanning:** Scanner already fans out per-target; the probe interface just changes how probes are called within a target

### Integration Points
- `internal/scanner/scanner.go:scanTarget()` — Where all 6 probes are called imperatively; this becomes the migration center
- `internal/model/model.go:TargetResult` — Named slices get replaced by Results []ProbeResult
- `internal/profile/profile.go` — Accesses TargetResult.DNS, TargetResult.TCP, etc. by name; needs migration to Layer-based iteration
- `internal/classifier/classifier.go` — Same pattern; accesses per-probe fields
- `internal/report/report.go` — Same pattern; serializes per-probe fields

### Creative Options
- The probe interface could be a single function type (`type Probe func(context.Context, Target) ProbeResult`) rather than an interface, simplifying the middleware signature. This is an implementation detail left to Claude's discretion.
</code_context>

<specifics>
## Specific Ideas

- Middleware package: `internal/probe/middleware/` with separate files per concern (`timeout.go`, `retry.go`, `logging.go`) plus `chain.go` for composition
- Probe adapters: Each probe package gets an `adapter.go` that wraps the existing Probe function into the new interface, plus init() registration
- Scanner refactoring: scanTarget takes a `[]Probe` list and iterates sequentially, collecting results into `TargetResult.Results`

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope.

</deferred>

---

*Phase: 02-Probe Interface Unification*
*Context gathered: 2026-04-26*
