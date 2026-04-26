<!-- refreshed: 2026-04-26 -->
# Architecture

**Analysis Date:** 2026-04-26

## System Overview

```text
┌─────────────────────────────────────────────────────────────────────┐
│                     CLI Layer (cmd/iscan/)                           │
│  cobra.Command root + "scan" subcommand                             │
│  Parses flags, constructs ScanOptions, invokes scanner.Run           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│                          ORCHESTRATION LAYER                         │
│  ┌────────────────────────────────────────────────────────────┐      │
│  │  Scanner  internal/scanner/scanner.go                       │      │
│  │  - errgroup-based concurrent target scanning                │      │
│  │  - Plugs probes together per-target, then runs Classify     │      │
│  └───────────────────────────┬────────────────────────────────┘      │
│                              │                                       │
│               ┌──────────────┼──────────────┐                        │
│               ▼              ▼              ▼                        │
│  ┌─────────────────┐  ┌────────────┐  ┌────────────┐               │
│  │   Probes         │  │ Classifier │  │  Targets   │               │
│  │  internal/probe/ │  │ classifier/│  │  targets/  │               │
│  │  - dnsprobe      │  │ .Classify  │  │ Built-in   │               │
│  │  - tcp           │  │            │  │ targets &  │               │
│  │  - tlsprobe      │  │            │  │ resolvers  │               │
│  │  - httpprobe     │  │            │  │            │               │
│  │  - quicprobe     │  │            │  │            │               │
│  │  - traceprobe    │  │            │  │            │               │
│  └─────────────────┘  └────────────┘  └────────────┘               │
│                              │                                       │
│                              ▼                                       │
│  ┌────────────────────────────────────────────────────────────┐      │
│  │   Profile & Recommend (internal/profile/, recommend/)       │      │
│  │   - profile.BuildProfile(report) -> Profile with tiered     │      │
│  │     health metrics per OSI layer                             │      │
│  │   - recommend.Rank(report, profile) -> weighted protocol    │      │
│  │     rankings (long-lived TCP, UDP-friendly, conservative,   │      │
│  │     high-redundancy)                                         │      │
│  └───────────────────────────┬────────────────────────────────┘      │
│                              │                                       │
│                              ▼                                       │
│  ┌────────────────────────────────────────────────────────────┐      │
│  │   Report   internal/report/report.go                        │      │
│  │   - JSON / JSONExtended serialization                       │      │
│  │   - Summary / SummaryExtended terminal output               │      │
│  └────────────────────────────────────────────────────────────┘      │
│                                                                      │
├─────────────────────────────────────────────────────────────────────┤
│                      MODEL LAYER (internal/model/)                    │
│  ScanOptions, ScanReport, Target, TargetResult, Finding,             │
│  DNS/TCP/TLS/HTTP/QUIC/TraceObservation structs, error sentinels    │
└─────────────────────────────────────────────────────────────────────┘
```

## Component Responsibilities

| Component | Responsibility | File |
|-----------|----------------|------|
| CLI (cmd/iscan) | Parse flags, wire dependencies, invoke scanner.Run | `cmd/iscan/main.go` |
| Scanner | Orchestrate concurrent multi-protocol scan per target, manage retries/parallelism | `internal/scanner/scanner.go` |
| Targets | Provide builtin target list and resolver list | `internal/targets/targets.go` |
| DNS Probe | Perform DNS A/AAAA queries via UDP (with TCP fallback on truncation) | `internal/probe/dnsprobe/dns.go` |
| TCP Probe | Dial raw TCP connections and classify error kinds | `internal/probe/tcp/tcp.go` |
| TLS Probe | Negotiate TLS handshake with configurable SNI and ALPN | `internal/probe/tlsprobe/tls.go` |
| HTTP Probe | Perform HTTP GET with httptrace timing instrumentation | `internal/probe/httpprobe/http.go` |
| QUIC Probe | Perform QUIC handshake via quic-go | `internal/probe/quicprobe/quic.go` |
| Trace Probe | ICMP traceroute (needs privilege) | `internal/probe/traceprobe/trace.go` |
| Classifier | Examine TargetResult observations and emit Finding structs | `internal/classifier/classifier.go` |
| Profile | Compute health tiers for DNS/TCP/TLS/QUIC/Path from ScanReport | `internal/profile/profile.go` |
| Recommend | Rank protocol strategies against profile via weighted scoring | `internal/recommend/recommend.go` |
| Report | Serialize to JSON and format terminal summaries | `internal/report/report.go` |
| Model | Central type definitions, error sentinels, validation | `internal/model/model.go`, `internal/model/errors.go` |

## Pattern Overview

**Overall:** Pipeline with concurrent fan-out.

The architecture is a linear pipeline: CLI collects options -> Scanner fans out per-target scans concurrently via `errgroup` -> scanner.Classify enriches each TargetResult -> (optionally) profile and recommend analyze the aggregate -> report renders. Each stage of the pipeline communicates through `model.*` structs.

**Key Characteristics:**
- **Shared-memory concurrency:** Uses `golang.org/x/sync/errgroup` with `SetLimit` for bounded parallelism (default 4 workers)
- **Pure functions with data-in/data-out:** Every stage except probes takes a model struct and returns a model struct; no shared mutable state between stages
- **No dependency injection:** Probes are called directly by package-qualified function calls from `scanner.Run` and `scanner.scanTarget`; no interface abstraction between scanner and probes
- **No inversion of control:** No interfaces, no registries, no plugin system — probes are hardcoded into `scanTarget()`

## Layers

**CLI Layer (`cmd/iscan/main.go`):**
- Purpose: Parse CLI flags, construct `model.ScanOptions`, invoke scanner, optionally invoke profile+recommend, invoke report
- Contains: Cobra command tree, flag definitions, top-level orchestration of the pipeline stages
- Depends on: `model`, `scanner`, `profile`, `recommend`, `report`
- Used by: End user via `go run ./cmd/iscan scan`

**Scanner Layer (`internal/scanner/`):**
- Purpose: Fan-out concurrent scans across targets, sequence probes per target, wrap results with classifier
- Contains: `scanner.Run` (entry), `scanTarget` (per-target probe sequence), helper functions for TLS retries, DNS resolution, URL construction
- Depends on: `model`, `classifier`, all probe packages under `internal/probe/`, `targets`
- Used by: CLI layer only

**Probe Layer (`internal/probe/*/`):**
- Purpose: Each probe package implements one protocol's probe as a single exported function `Probe(ctx, ...) -> model.XObservation`
- Contains: 6 probe packages (dnsprobe, tcp, tlsprobe, httpprobe, quicprobe, traceprobe)
- Depends on: `model`, external SDKs (`github.com/miekg/dns`, `github.com/quic-go/quic-go`, `golang.org/x/net/icmp`)
- Used by: Scanner layer

**Classifier (`internal/classifier/`):**
- Purpose: Examine a single TargetResult and emit Finding structs for anomalies detected across layers
- Contains: `Classify` function, private helpers for DNS inconsistency, suspicious DNS, TLS SNI-correlated failures, aggregate failure detection via generic `aggregateFailures[T any]`
- Depends on: `model`
- Used by: Scanner layer (called per-target after probe results)

**Profile Layer (`internal/profile/`):**
- Purpose: Aggregate a ScanReport into per-layer health profiles with quality tiers (Excellent/Good/Fair/Poor)
- Contains: `Profile` struct, `BuildProfile` function, layer-specific profile builders
- Depends on: `model`
- Used by: CLI layer (optional, only with `--analyze`)

**Recommend Layer (`internal/recommend/`):**
- Purpose: Compute weighted protocol strategy rankings from Profile, with bilingual Chinese/English category labels and human-readable reasons
- Contains: `Recommendation` struct, `Rank` function, per-strategy scoring with weighted constants, reason generators
- Depends on: `model`, `profile`
- Used by: CLI layer (optional, only with `--analyze`)

**Report Layer (`internal/report/`):**
- Purpose: Format scan results for human (terminal) and machine (JSON) consumption
- Contains: `JSON`, `JSONExtended`, `Summary`, `SummaryExtended`
- Depends on: `model`, `profile`, `recommend`
- Used by: CLI layer

**Model Layer (`internal/model/`):**
- Purpose: Define all shared data types and error sentinels
- Contains: `Target`, `ScanOptions`, `ScanReport`, `TargetResult`, 6 observation types, `Finding`, `FindingType`, `Layer`, `Confidence`, validation, error helpers
- Depends on: Nothing outside the package
- Used by: Every other package

## Data Flow

### Primary Request Path (default: `iscan scan`)

1. CLI parses flags, builds `model.ScanOptions` (`cmd/iscan/main.go:54`)
2. `scanner.Run(ctx, options)` starts the pipeline (`internal/scanner/scanner.go:24`)
   - Validates/defaults options, loads builtin targets and resolvers from `targets/`
   - Creates an `errgroup` with concurrency limit (default 4) (`scanner.go:49-53`)
3. For each target, `scanTarget()` runs sequentially on a goroutine (`scanner.go:82`)
   - Resolver DNS A and AAAA queries (`scanner.go:85-90`)
   - TCP connect to resolved addresses on each port with retries (`scanner.go:96-106`)
   - TLS handshake on TCP successes with configurable SNI and compare-SNI (`scanner.go:108-115`)
   - HTTP GET if scheme is http or TLS succeeded for that SNI (`scanner.go:118-125`)
   - QUIC handshake if `--quic` and target has quic_port (`scanner.go:127-152`)
   - ICMP traceroute if `--trace` (`scanner.go:154-157`)
4. `classifier.Classify(result)` runs on each completed TargetResult (`scanner.go:60`)
5. `group.Wait()` blocks until all targets done or cancelled (`scanner.go:65`)
6. Results are flattened into `ScanReport.Findings` and `ScanReport.Targets` (`scanner.go:68-77`)
7. CLI writes JSON report if `--json` flag set (`main.go:68-81`)
8. CLI prints terminal summary if `--summary` flag set (`main.go:83-88`)

### Analysis Path (with `--analyze`)

1. After `scanner.Run` completes, `profile.BuildProfile(scan)` aggregates report into per-layer health metrics (`main.go:63`)
2. `recommend.Rank(scan, profile)` computes weighted strategy rankings (`main.go:65`)
3. Profile and recommendations are included in extended JSON (`report.JSONExtended`) and extended summary (`report.SummaryExtended`)

### Probe Layer Data Flow

Each probe follows the same pattern:
1. Accept `ctx context.Context` for cancellation
2. Accept parameters + `timeout time.Duration`
3. Record `time.Now()` as start
4. Perform network operation with context-aware dialer/client
5. On error: return observation with `Success: false` and `Error` string
6. On success: return observation with `Success: true` and protocol-specific fields

**State Management:**
- No global state; all data flows through function parameters and return values
- `ScanReport` is the single aggregated state container
- Concurrency is managed by `errgroup`; individual goroutines share no state beyond the result slice

## Key Abstractions

**Observation Types:**
- Purpose: Each probe produces a specific observation struct (`DNSObservation`, `TCPObservation`, `TLSObservation`, `HTTPObservation`, `QUICObservation`, `TraceObservation`)
- Location: `internal/model/model.go`
- Pattern: All observation structs share the same contract — they embed `Success bool`, `Error string`, `Latency time.Duration`, and protocol-specific fields
- No common interface or trait: observation types are standalone structs with no shared abstraction

**Finding Type:**
- Purpose: A typed signal with evidence backing, layer attribution, and confidence level
- Location: `internal/model/model.go:170-176`
- Fields: `Type FindingType`, `Layer Layer`, `Confidence Confidence`, `Evidence []string`, `ObservedAt time.Time`
- Generators: `classifier.Classify` examines each layer's observations and produces findings

**Generic aggregateFailures[T any]:**
- Purpose: Used by classifier to detect per-layer failure patterns across different observation types
- Location: `internal/classifier/classifier.go:114-142`
- Pattern: Generic function parameterized on observation type T, with key/success/message extractor callbacks passed as function arguments

**QualityTier:**
- Purpose: Four-level ordinal quality rating (Excellent/Good/Fair/Poor) used across DNS, TCP, TLS, QUIC, and Path health profiles
- Location: `internal/profile/profile.go:10-17`
- Conversion: `qualityTier(score float64)` maps a 0-1 score to a tier; `StabilityScore(tier) float64` reverses it

**Strategy Rankings:**
- Purpose: Four ranked protocol recommendations with weighted scores and bilingual reasons
- Location: `internal/recommend/recommend.go:35-44`
- Weight constants are defined per-strategy as package-level consts (lines 15-32), not configurable at runtime

## Entry Points

**Main Entry Point:**
- Location: `cmd/iscan/main.go:20`
- Triggers: User runs `iscan scan [flags]`
- Responsibilities: Build root cobra command, register scan subcommand, parse all flags, invoke pipeline stages in sequence, handle errors

**Scanner Entry Point:**
- Location: `internal/scanner/scanner.go:24`
- Triggers: Called from CLI
- Responsibilities: Default options, load targets, concurrent scan, result collection

## Architectural Constraints

- **Concurrency:** Bounded goroutine pool via `errgroup` with `SetLimit` (default 4). All goroutines share a result slice indexed by target position — concurrent writes to `results[i]` are safe since each goroutine owns a unique index.
- **Global state:** None. All packages are stateless; state lives in `model.ScanReport` returned from `scanner.Run`.
- **Circular imports:** Not detected. The dependency graph is a DAG: model at root, probes and targets depend on model, scanner depends on probes+targets+classifier+model, classifier depends on model, profile/recommend depend on model, report depends on model+profile+recommend, CLI depends on scanner+profile+recommend+report.
- **External tooling requires `--trace` for privileged ICMP sockets:** The trace probe needs `CAP_NET_RAW` (or root on Linux, or `SOCK_RAW` entitlement on macOS); permission errors are caught and reported as warnings, not failures.
- **QUIC probing is opt-in:** Requires `--quic` flag and `QUICPort > 0` on target.
- **No interface abstraction for probes:** Probes are called directly by package function, not through an interface. Adding a new protocol requires editing `scanTarget()` in `scanner.go`.
- **No hot-reload or plugin system:** All targets, resolvers, and behavior are compile-time constants.

## Anti-Patterns

### Direct Function Call Probe Invocation

**What happens:** Probes are invoked by their package-qualified function name directly in `scanTarget()` (`scanner.go:99, 112, 120, 134, 155`). There is no `Probe` interface.
**Why it's wrong:** Adding a new protocol probe requires modifying `scanTarget()` (a 77-line function) to add the import and call. There is no way to swap probe implementations for testing.
**Do this instead:** Define a `Probe` interface in `internal/probe/` and use a registry or strategy pattern. Note: for a small single-purpose CLI with a known finite set of protocols, the current approach is acceptable and practical.

### Stringly-Typed Error Classification in TCP Probe

**What happens:** `tcp.classifyError` falls back to string matching on `err.Error()` (`tcp.go:56-68`) after checking standard sentinels.
**Why it's wrong:** String matching on error messages is fragile across OS and Go versions. The error helper `model.IsLocalPermissionError` also uses string matching (`errors.go:15-17`).
**Do this instead:** Use `errors.Is` or `errors.As` with exported sentinel values. String matching should be a last resort.

### Single-Layer Finding Generation

**What happens:** Each `Finding` is generated within `classifier.Classify` based on a single `TargetResult` — cross-target correlation does not happen at the classifier level.
**Why it's wrong:** Some findings (e.g., local network issues) require cross-target correlation but are currently generated per-target.
**Do this instead:** Add a second pass in `scanner.Run` that examines all results together, as already partially done for trace permission warnings (`scanner.go:72-74`).

## Error Handling

**Strategy:** Go error values for programming errors; error strings in observation structs for network failures; `report.Warnings` for non-fatal diagnostics.

**Patterns:**
1. **Defensive defaults:** `scanner.Run` sets default Timeout (5s), Retries (3), Parallelism (4) if zero (`scanner.go:25-33`)
2. **Context propagation:** All probes accept `context.Context` for cancellation; `errgroup` propagates cancellation through `gCtx`
3. **Error classification by kind:** TCP probe classifies errors into `timeout`, `refused`, `reset`, `unreachable`, `other` (`tcp.go:43-69`)
4. **Permission check:** `model.IsLocalPermissionError()` identifies ICMP privilege errors to avoid false path-quality findings (`model/errors.go:15-17`)
5. **Non-fatal warnings:** Permission errors for trace are collected in `report.Warnings` while the scan continues (`scanner.go:72-74`)
6. **No panics in normal operation:** All error paths are handled; the only fatal path is `os.Exit(1)` after cobra returns an error in main
7. **Context cancellation handling:** `scanner.scanTarget` checks `ctx.Err()` before each probe step (`scanner.go:86, 130`); errgroup `gCtx` cancellation stops incomplete targets

## Cross-Cutting Concerns

**Logging:** No logging framework. The tool uses stdout terminal output (via `report.Summary`) and optional JSON file output. Warnings are embedded in the `model.ScanReport.Warnings` slice and surfaced in both outputs.

**Validation:** `model.Target.Validate()` checks Name, Domain, Scheme (must be http/https), and Ports before scanning; invalid targets are recorded as warnings, not hard errors (`scanner.go:42-46`).

**Configuration:** All configuration is via CLI flags (cobra). No config files. The `targets.BuiltinTargets()` and `targets.BuiltinResolvers()` are compile-time constants in `internal/targets/targets.go`.

**Instrumentation:** No metrics, tracing, or structured logging. The httpprobe records `httptrace.ClientTrace` timing breakdowns for diagnostics.

---

*Architecture analysis: 2026-04-26*
