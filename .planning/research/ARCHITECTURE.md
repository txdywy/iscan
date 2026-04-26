# Architecture Research: iscan -- Layered Network Diagnostics for Censorship Detection

**Domain:** Network censorship detection tool (Go CLI)
**Researched:** 2026-04-26
**Confidence:** HIGH (source code analysis + reference architectures verified against OONI Probe, Measurement Kit, and Go plugin patterns)

---

## 1. Reference Architectures

### 1.1 OONI Probe (State of the Art)

OONI Probe is the leading open-source censorship measurement tool. Its evolved architecture (post-2022, after merging `probe-engine` into `probe-cli`) reveals several key patterns relevant to iscan:

**Core Architecture Pattern: Interface-Based Network Abstraction (netxlite)**

OONI's `netxlite` package defines Go interfaces that mirror standard library capabilities but allow instrumentation at every layer:

```
Dialer            → Raw TCP connection
Resolver          → DNS resolution (system, UDP, DoT, DoH)
TLSDialer         → TCP + TLS handshake
QUICDialer        → UDP + QUIC handshake
HTTPTransport     → HTTP/1.1, HTTP/2, HTTP/3 round trips
TLSHandshaker     → TLS handshake on existing connection
DNSTransport      → Raw DNS wire format transport
```

**Key insight:** Each interface has a "saver" wrapper (decorator pattern) that records events without changing the interface contract. This separates measurement from instrumentation.

**Step-by-Step Measurement (measurex)**

OONI shifted from monolithic "experiments" to composable building blocks:

```
LookupHost → TCPConnect → TLSHandshake → HTTPRoundTrip
     |            |             |              |
  DNS event   TCP event     TLS event      HTTP event
```

Each step produces an observation event. Events are classified into OONI archival format (`df-002-dnst`, `df-005-tcp`, etc.) and associated with `failure` (raw error) + `oddity` (contextual classification).

**Error Classification**

OONI wraps all errors into `*netxlite.ErrWrapper` with:
- OONI failure code (e.g., `dns_nxdomain_error`, `tls_handshake_failed`)
- Failed operation name (e.g., `resolve`, `connect`, `tls_handshake`)
- Underlying wrapped error

This is critical for censorship detection -- the *type* of failure at each layer reveals the blocking mechanism.

### 1.2 Measurement Kit (Historical, Deprecated)

Measurement Kit was a C++14 library with FFI bindings for mobile. Its key structural insight was a **Test Template** pattern that separated measurement logic from protocol-specific code. iscan should not replicate MK's C++ complexity, but its decoupling of test specification from execution is worth noting.

### 1.3 What iscan Does Differently

Unlike OONI (which ships dozens of experiments targeting specific apps/protocols), iscan focuses on:
- **Network profiling** rather than individual endpoint testing
- **Comparative analysis** (control vs. test resolvers, control vs. test SNI values)
- **Protocol rankings** for circumvention strategy recommendations
- **Single CLI shot** rather than ongoing scheduled measurements

This narrower scope means iscan can afford a simpler architecture than OONI, but must be designed for extensibility since censorship landscapes evolve rapidly.

---

## 2. Current iscan Architecture Analysis

### 2.1 Package Dependency Graph

```
cmd/iscan/main.go
    |
    v
scanner.Run()
    |--- targets.BuiltinTargets()
    |--- targets.BuiltinResolvers()
    |--- target loop (errgroup, parallelism-limited)
    |       |
    |       v
    |   scanTarget()
    |       |--- dnsprobe.Probe()        (per resolver, A + AAAA)
    |       |--- tcp.Probe()              (per address:port)
    |       |--- tlsprobe.Probe()         (per TCP success, all SNI variants)
    |       |--- httpprobe.Probe()        (if TLS or HTTP scheme)
    |       |--- quicprobe.Probe()        (if QUIC enabled + target has QUIC port)
    |       |--- traceprobe.Probe()       (if trace enabled)
    |       |--- classifier.Classify()    (per-target findings)
    |       |
    |       v
    |   result.TargetResult
    |
    v
report.Report (JSON / Summary)
    |
    v (if --analyze)
profile.BuildProfile()
    |
    v
recommend.Rank()
    |
    v
report.JSONExtended / SummaryExtended
```

### 2.2 Current Interface Anti-Patterns

**Problem 1: No unified probe interface.** Each probe package exports a standalone function with a different signature:

```
dnsprobe.Probe(ctx, resolver, domain, qtype, timeout)              → model.DNSObservation
tcp.Probe(ctx, host, port, timeout)                                → model.TCPObservation
tlsprobe.Probe(ctx, host, port, sni, protos, timeout, skipVerify)  → model.TLSObservation
httpprobe.Probe(ctx, url, timeout)                                  → model.HTTPObservation
httpprobe.ProbeWithAddress(ctx, url, dialAddr, timeout)            → model.HTTPObservation
quicprobe.Probe(ctx, host, port, sni, alpn, timeout)               → model.QUICObservation
traceprobe.Probe(ctx, target, timeout)                             → model.TraceObservation
```

This means `scanner.go` must know the specific signature of every probe and manage the orchestration logic inline. Adding a new protocol probe requires:
1. Creating a new package with a `Probe(...)` function
2. Importing it in `scanner.go`
3. Adding inline orchestration logic in `scanTarget()`
4. Adding new fields to `TargetResult` and `Target`
5. Adding a new `Layer` constant
6. Adding classification logic in `classifier.Classify()`

Each of these steps touches a different file, making the system fragile.

**Problem 2: Per-probe retry logic is duplicated.** `retryWithBackoff` is generic, but every call site in `scanTarget()` manually wraps each probe call. With a unified interface, retry could be a middleware wrapper.

**Problem 3: TargetResult is a flat struct with per-protocol slices.** Adding a new protocol means adding a new slice field (`model.SomeNewObservation`). This creates coupling between the data model and the number of supported protocols.

**Problem 4: Retry with backoff is in scanner.** The `retryWithBackoff` function belongs either on the probe itself or as a wrapper, not in the scanner package.

### 2.3 Current Strengths Worth Preserving

**Error classification in TCP probe** (`classifyError`) maps OS-level errors to semantic kinds (timeout, refused, reset, unreachable). This is exactly the right approach -- it turns `syscall.ECONNREFUSED` into actionable evidence.

**DNS cross-resolver comparison** -- the `dnsInconsistent` function in the classifier detects when different resolvers return different answer sets. This is the foundational censorship detection technique.

**Multi-SNI probing** -- `CompareSNI` on a target allows testing the same IP with different SNI values to detect SNI-based filtering.

**Control target concept** -- `Control: true` marks targets used as baselines, enabling comparative analysis.

**Profile + Recommend pipeline** -- transforms raw observations into actionable recommendations (long-lived TCP, UDP-friendly, conservative TLS, high-redundancy). This is the key differentiator from OONI.

---

## 3. Proposed Architecture: Phase-Built Extensible Probing Framework

### 3.1 Architecture Overview (Target State)

```
┌─────────────────────────────────────────────────────────┐
│                    cmd/iscan/main.go                     │
│  (cobra CLI, option parsing, pipeline orchestration)    │
└──────────┬──────────────────────────────────────────────┘
           │
           v
┌─────────────────────────────────────────────────────────┐
│                    internal/scanner                      │
│  Target resolution → Probe scheduling → Result assembly │
│  (orchestration only: what to probe, in what order)     │
└───┬─────────┬─────────┬─────────┬───────────────────────┘
    │         │         │         │
    v         v         v         v
┌──────┐ ┌──────┐ ┌──────┐ ┌──────────┐
│ DNS  │ │ TCP  │ │ TLS  │ │ HTTP     │ ... (probes)
│probe │ │probe │ │probe │ │probe     │
└──┬───┘ └──┬───┘ └──┬───┘ └──┬───────┘
   │        │        │        │
   └────────┴────────┴────────┘
           │ (all probes implement
           │  same ProbeRunner interface)
           v
┌─────────────────────────────────────────────────────────┐
│               internal/classifier                        │
│  Observation set → Evidence vector → Findings           │
│  (independent of probe implementation details)          │
└──────────────────────────┬──────────────────────────────┘
                           │
                           v
┌─────────────────────────────────────────────────────────┐
│               internal/profile                          │
│  Findings → Aggregated health dimensions per layer     │
└──────────────────────────┬──────────────────────────────┘
                           │
                           v
┌─────────────────────────────────────────────────────────┐
│               internal/recommend                        │
│  Health dimensions → Weighted protocol rankings         │
└──────────────────────────┬──────────────────────────────┘
                           │
                           v
┌─────────────────────────────────────────────────────────┐
│               internal/report                           │
│  Data → JSON / Terminal summary / (future: HTML, YAML) │
└─────────────────────────────────────────────────────────┘
```

**Probe phase execution order (enforced by scanner):**

```
Phase 1: DNS resolution      (always, parallel resolvers)
Phase 2: TCP connectivity     (on resolved addresses)
Phase 3: TLS handshake        (on successful TCP connections)
Phase 4: HTTP request         (on successful TLS or plain HTTP target)
Phase 5: QUIC/UDP handshake   (optional, parallel with HTTP)
Phase 6: ICMP traceroute      (optional, independent)
```

This ordering is essential: each phase depends on the previous. DNS must succeed before TCP can target resolved IPs. TCP must succeed before TLS. But phases 5 (QUIC) and 6 (traceroute) are independent of 3-4 and can run in parallel.

### 3.2 Unified Probe Interface

The core architectural change: define a `ProbeRunner` interface that all probes implement, then use middleware wrappers for cross-cutting concerns.

**Phase 1: Define the interface in `internal/model` or a dedicated `internal/probe/interfaces.go`**

```go
// ProbeResult is a type-erased container any probe can return.
// The scanner uses Type() for routing, scanner-specific code accesses
// the concrete observation via accessor functions.
type ProbeResult interface {
    // TargetKey returns a unique key for deduplication / aggregation.
    // E.g.: "dns:1.1.1.1:example.com:A", "tcp:1.1.1.1:443", "tls:1.1.1.1:443:example.com"
    TargetKey() string

    // Layer identifies which network layer this probe targets.
    Layer() Layer

    // Success reports whether the probe completed without error.
    Success() bool

    // Error returns the error string (empty if successful).
    Error() string

    // Latency returns the probe duration.
    Latency() time.Duration
}

// ProbeConfig carries per-probe options that apply universally.
type ProbeConfig struct {
    Timeout time.Duration
    Retries int
    BaseDelay time.Duration  // for retry backoff
}

// ProbeRunner is the interface every probe implementation satisfies.
type ProbeRunner[T Observation] interface {
    // Run executes a single probe attempt.
    Run(ctx context.Context, target Target, resolver Resolver, cfg ProbeConfig) (T, error)

    // Name returns a human-readable name for this probe type.
    Name() string

    // Dependencies returns the layer keys this probe depends on having results for.
    // Empty slice means it has no dependencies.
    Dependencies() []Layer
}
```

**Alternative (simpler, more Go-idiomatic):** Use a single non-generic interface and return `ProbeResult`:

```go
// Probe is the minimal interface for any probe.
type Probe interface {
    // Name returns the probe type identifier.
    Name() string
    // Run executes the probe. Returns a ProbeResult on success or error.
    Run(ctx context.Context, target Target, resolver Resolver, cfg ProbeConfig) (ProbeResult, error)
    // DependsOn returns the layer types required before this probe can run.
    DependsOn() []Layer
}
```

**Tradeoff (generics vs. interface{}):**
- **Generics approach** (`ProbeRunner[T Observation]`): Type-safe, avoids type assertions when processing results, but makes the registry harder (heterogeneous types must be erased at registry boundaries).
- **Interface approach** (`Probe` returning `ProbeResult`): Easier to register heterogeneous probes, but requires type switches/assertions in result consumers.
- **Recommendation:** Start with the interface approach. Add generics later if the type switching overhead becomes a maintenance burden. OONI chose the interface approach (model.HTTPTransport etc.) and it scales to dozens of experiments.

### 3.3 Probe Middleware (Decorator Pattern)

Once all probes implement `Probe`, cross-cutting concerns become wrappers:

```go
// RetryMiddleware wraps a Probe to add retry-with-backoff.
func RetryMiddleware(inner Probe, cfg ProbeConfig) Probe {
    return retryProbe{inner: inner, cfg: cfg}
}

// TimeoutMiddleware wraps a Probe to enforce per-attempt timeout.
func TimeoutMiddleware(inner Probe, timeout time.Duration) Probe {
    return timeoutProbe{inner: inner, timeout: timeout}
}

// LoggingMiddleware wraps a Probe to log start/completion.
func LoggingMiddleware(inner Probe, logger *slog.Logger) Probe {
    return loggingProbe{inner: inner, logger: logger}
}
```

This pattern (directly from OONI's `Saver.WrapDialer`) means:
- `scanner.go` doesn't need retry logic
- Individual probes don't need timeout logic
- New cross-cutting concerns (metrics, tracing, rate-limiting) don't touch probe code

**iscan currently has retry in scanner.go (`retryWithBackoff`).** Moving it to a middleware simplifies the scanner significantly.

### 3.4 Probe Registry Pattern

```go
// internal/probe/registry.go
package probe

var registry = map[string]func() Probe{}

// Register adds a probe factory. Called from init() in probe packages.
func Register(name string, factory func() Probe) {
    if _, exists := registry[name]; exists {
        panic("probe: duplicate registration: " + name)
    }
    registry[name] = factory
}

// Available returns the names of all registered probes.
func Available() []string {
    names := make([]string, 0, len(registry))
    for n := range registry {
        names = append(names, n)
    }
    sort.Strings(names)
    return names
}

// Get returns a new instance of the named probe, or nil.
func Get(name string) Probe {
    factory, ok := registry[name]
    if !ok {
        return nil
    }
    return factory()
}
```

Each probe package self-registers:

```go
package dnsprobe

func init() {
    probe.Register("dns", func() probe.Probe { return &DNSProbe{} })
}
```

And the scanner imports via blank import:

```go
package scanner

import (
    _ "iscan/internal/probe/dnsprobe"
    _ "iscan/internal/probe/tcp"
    _ "iscan/internal/probe/tlsprobe"
    _ "iscan/internal/probe/httpprobe"
    _ "iscan/internal/probe/quicprobe"
    _ "iscan/internal/probe/traceprobe"
)
```

**Architectural decision: Why not go-plugin (`.so` dynamic loading)?**
- Runtime `.so` loading is experimental, fragile across Go versions, and requires exact build environment matching.
- iscan is a single CLI binary -- no need for hot-pluggable probes at runtime.
- Compile-time registration via `init()` gives zero runtime overhead and full compile-time type safety.

### 3.5 Phase-Aware Probe Execution

The scanner transitions through phases, each phase having its own probes:

```go
// Phase describes a logical step in the probe pipeline.
type Phase struct {
    Name  string
    Probes []probe.Probe
    // Parallel indicates whether probes in this phase can run concurrently.
    Parallel bool
    // Optional is true if the phase can be skipped entirely.
    Optional bool
}

// ScanPlan defines the ordered phases for a scan.
type ScanPlan struct {
    Phases []Phase
}

// StandardScanPlan creates the default ordered phase list for a target.
func StandardScanPlan(options model.ScanOptions) ScanPlan {
    plan := ScanPlan{}
    plan.Phases = append(plan.Phases, Phase{
        Name:     "dns",
        Probes:   []probe.Probe{probe.Get("dns")},
        Parallel: true, // multiple resolvers in parallel
        Optional: false,
    })
    plan.Phases = append(plan.Phases, Phase{
        Name:     "tcp",
        Probes:   []probe.Probe{probe.Get("tcp")},
        Parallel: true,
        Optional: false,
    })
    plan.Phases = append(plan.Phases, Phase{
        Name:     "tls",
        Probes:   []probe.Probe{probe.Get("tls")},
        Parallel: false, // sequential: SNI variants need ordering
        Optional: false,
    })
    plan.Phases = append(plan.Phases, Phase{
        Name:     "http",
        Probes:   []probe.Probe{probe.Get("http")},
        Parallel: false,
        Optional: true, // only if TLS succeeded or target uses HTTP
    })
    if options.QUIC {
        plan.Phases = append(plan.Phases, Phase{
            Name:     "quic",
            Probes:   []probe.Probe{probe.Get("quic")},
            Parallel: true,
            Optional: true,
        })
    }
    if options.Trace {
        plan.Phases = append(plan.Phases, Phase{
            Name:     "trace",
            Probes:   []probe.Probe{probe.Get("trace")},
            Parallel: false,
            Optional: true,
        })
    }
    return plan
}
```

The scanner then iterates phases, passing accumulated results between phases:

```go
func scanTarget(ctx context.Context, plan ScanPlan, target model.Target, resolvers []model.Resolver, cfg model.ScanConfig) model.TargetResult {
    result := model.TargetResult{Target: target}
    accumulated := model.ScanAccumulator{Target: target, Resolvers: resolvers, Config: cfg}

    for _, phase := range plan.Phases {
        for _, p := range phase.Probes {
            // Resolver distribution logic: DNS probes run per-resolver,
            // TCP probes run per-address, TLS probes run per-SNI, etc.
            inputs := expandProbeInputs(p, accumulated)
            for _, input := range inputs {
                p := wrapMiddleware(p, cfg) // apply retry/timeout/logging
                res, err := p.Run(ctx, input.target, input.resolver, cfg.Probe)
                if err != nil { ... }
                accumulated.Record(res)
            }
        }
    }

    result.DNS = accumulated.DNSResults()
    result.TCP = accumulated.TCPResults()
    // etc.
    return result
}
```

The key benefit: **adding a new protocol only requires implementing `Probe.Run()` and registering it.** No changes to `scanTarget()` logic.

---

## 4. Classification Engine Architecture

### 4.1 Current Classification (Single Function, Sequential)

Currently `classifier.Classify(result model.TargetResult)` is a monolithic function that:
1. Takes a single target's observations
2. Runs a sequence of detection heuristics (dnsInconsistent, suspiciousDNS, aggregateFailures, etc.)
3. Returns a flat `[]model.Finding` slice

**Strengths:** Simple, easy to read, all heuristics are tested per-target.
**Weaknesses:** 
- All heuristics run even if not applicable (e.g., QUIC findings when QUIC was not probed)
- No cross-target correlation (SNI correlation is per-address but not per-target across resolvers)
- Adding a heuristic means editing the function body
- Heuristics are tightly coupled to the observation struct shape

### 4.2 Proposed: Evidence Pipeline with Composable Detectors

```go
// Detector is the interface for individual censorship detection heuristics.
type Detector interface {
    // Name returns a unique identifier for this detector.
    Name() string
    // Detect examines observations and returns findings.
    Detect(ctx context.Context, result TargetResult, profile *profile.Profile) []Finding
    // AppliesTo returns true if this detector should run for the given scan config.
    AppliesTo(cfg model.ScanConfig) bool
}
```

**Example detectors:**

| Detector | Layer | Condition | Confidence |
|----------|-------|-----------|------------|
| `dnsInconsistencyDetector` | DNS | Multiple resolvers return different answer sets without overlap | Low |
| `suspiciousAnswerDetector` | DNS | Any resolver returns private/local IP | Medium |
| `tcpFailureDetector` | TCP | TCP connect fails on some addresses but succeeds on others | Low |
| `tlsHandshakeDetector` | TLS | TLS handshake fails | Low |
| `sniCorrelationDetector` | TLS | Same IP: success with control SNI, failure with test SNI | Medium (key signal) |
| `httpApplicationDetector` | HTTP | HTTP request fails or returns unexpected status | Low |
| `quicHandshakeDetector` | QUIC | QUIC handshake fails (compared to TLS success baseline) | Medium |
| `tracePathDetector` | Trace | Traceroute fails or shows anomalous path | Low |
| `tlsQUICDivergenceDetector` | Cross | TLS succeeds but QUIC fails on same host | High (UDP blocking) |

**Cross-target correlation (new):**

```go
// crossTargetDetector compares control targets with test targets to
// isolate network-level blocking from target-specific issues.
type crossTargetDetector struct{}

func (d *crossTargetDetector) Detect(ctx context.Context, allResults []TargetResult) []Finding {
    controls := filterControl(allResults)
    tests := filterTest(allResults)
    // If control targets show the same failure pattern as test targets,
    // the issue is likely network-level, not target-level censorship.
    // Downgrade confidence accordingly.
}
```

This pattern matches the evidence → finding → profile pipeline well:
- **Evidence** = raw observations with context (what was probed, what happened)
- **Finding** = a single detected anomaly with type, layer, confidence, and evidence trail
- **Profile** = aggregated health dimensions across all findings

### 4.3 Confidence Propagation

Current confidence levels are static per finding type. A better model would allow confidence to be modified based on corroborating evidence:

```
Initial confidence (based on detector):
  DNS inconsistent      → LOW
  SNI correlated       → MEDIUM
  TLS/QUIC divergence  → HIGH

Modifiers (additive/subtractive):
  +1 tier: same finding observed on multiple targets
  +1 tier: finding corroborated by independent probe type (e.g., TLS failure + TCP success = SNI filtering)
  -1 tier: control target exhibits same behavior (likely general network issue, not censorship)
  -1 tier: single observation, no corroboration
  -1 tier: high latency or transient error could explain failure
```

This is a medium-complexity addition and should be deferred until basic detectors are stable.

---

## 5. Report Pipeline Architecture

### 5.1 Current Report Design

`report` currently exports two formats:
- `JSON(scan)` → machine-readable structured JSON
- `Summary(scan)` → terminal-optimized table
- `JSONExtended(scan, profile, rec)` → JSON with profile/recommendation
- `SummaryExtended(scan, rec)` → terminal output with rankings

**Limitations:**
- Each format is a standalone function, not a strategy pattern
- Adding a new format (HTML, YAML, CSV) requires adding a new function
- The terminal summary uses `tabwriter` which is Unix-centric
- No streaming output for long scans

### 5.2 Proposed: Formatter Strategy Pattern

```go
// Formatter is the interface for output formats.
type Formatter interface {
    // Format serializes the scan report into bytes.
    Format(scan model.ScanReport, prof *profile.Profile, rec *recommend.Recommendation) ([]byte, error)
    // ContentType returns the MIME type for HTTP-serving scenarios.
    ContentType() string
    // Extension returns the file extension (e.g., ".json", ".html").
    Extension() string
}
```

**Implementation example:**

```go
type JSONFormatter struct {
    pretty bool
}

func (f *JSONFormatter) Format(scan model.ScanReport, prof *profile.Profile, rec *recommend.Recommendation) ([]byte, error) {
    if prof == nil || rec == nil {
        if f.pretty {
            return json.MarshalIndent(scan, "", "  ")
        }
        return json.Marshal(scan)
    }
    out := struct {
        Scan           model.ScanReport          `json:"scan"`
        Profile        *profile.Profile          `json:"profile,omitempty"`
        Recommendation *recommend.Recommendation `json:"recommendation,omitempty"`
    }{Scan: scan, Profile: prof, Recommendation: rec}
    if f.pretty {
        return json.MarshalIndent(out, "", "  ")
    }
    return json.Marshal(out)
}
```

A formatter registry follows the same pattern as the probe registry:

```go
func init() {
    report.Register("json", func() report.Formatter { return &JSONFormatter{pretty: true} })
    report.Register("json-compact", func() report.Formatter { return &JSONFormatter{pretty: false} })
    report.Register("summary", func() report.Formatter { return &SummaryFormatter{} })
}
```

### 5.3 Terminal Output Design Principles

The terminal summary should follow these conventions:

1. **One row per target, columns per protocol layer** (current design -- good)
2. **Color (terminal-capable):** green=success, yellow=partial, red=failure, gray=skip
3. **Findings column** should show counts per confidence level, not just type strings
4. **Warnings** should appear after the table, not inline
5. **Recommendation section** should be visually separated with a rule

Future terminal formats to consider:
- `--summary=short` (compact one-liner with just pass/fail per target)
- `--summary=findings` (finding-focused, detailed evidence per finding)

### 5.4 Structured Report Envelope

Current `ScanReport` is flat. Consider an envelope that separates metadata from results:

```go
type ReportEnvelope struct {
    Version     string                  `json:"version"`     // schema version for forward compat
    Tool        string                  `json:"tool"`        // "iscan"
    GitCommit   string                  `json:"git_commit"`  // for provenance
    StartedAt   time.Time               `json:"started_at"`
    Duration    time.Duration           `json:"duration"`
    Config      ReportConfig            `json:"config"`
    Targets     []model.TargetResult    `json:"targets"`
    Aggregated  *AggregatedResults      `json:"aggregated,omitempty"`
    Profile     *profile.Profile        `json:"profile,omitempty"`
    Rankings    *recommend.Recommendation `json:"recommendation,omitempty"`
}

type ReportConfig struct {
    Options model.ScanOptions `json:"options"`
    Targets []model.Target    `json:"targets"`
    Resolvers []model.Resolver `json:"resolvers,omitempty"`
}
```

This makes the JSON self-describing and forward-compatible.

---

## 6. Target Management Patterns

### 6.1 Current Design

Targets are hardcoded in `targets.BuiltinTargets()` and `targets.BuiltinResolvers()`. The `--target-set` flag validates against `"builtin"` only.

### 6.2 Target Sources Architecture

iscan should support multiple target sources with a common interface:

```go
// TargetSource provides targets and resolvers for a scan.
type TargetSource interface {
    // Name returns a unique identifier for this source.
    Name() string

    // Targets returns the list of targets to probe.
    Targets() ([]model.Target, error)

    // Resolvers returns the list of DNS resolvers to use.
    Resolvers() ([]model.Resolver, error)
}
```

**Built-in source (current behavior):**

```go
type BuiltinSource struct{}

func (s *BuiltinSource) Name() string { return "builtin" }
func (s *BuiltinSource) Targets() ([]model.Target, error) { return BuiltinTargets(), nil }
func (s *BuiltinSource) Resolvers() ([]model.Resolver, error) { return BuiltinResolvers(), nil }
```

**Future sources (phase by phase):**

| Source | Implementation | Phase |
|--------|---------------|-------|
| JSON file | Reads `iscan-targets.json` with `targets` and `resolvers` arrays | Phase 2 |
| YAML file | Same schema, YAML format | Phase 2 |
| CLI flags | `--target example.com --port 443` for ad-hoc scanning | Phase 3 |
| Combined | Merge built-in + file + CLI, deduplicate | Phase 3 |

### 6.3 Target Expansion

The scanner currently expands targets manually inside `scanTarget()`. A cleaner pattern is **target expansion** -- producing the full cartesian product of (target, resolver, qtype) before scanning:

```go
// ExpandedTask is a fully resolved unit of work.
type ExpandedTask struct {
    Target      model.Target
    Resolver    model.Resolver
    QType       uint16      // for DNS
    Addresses   []string    // resolved from DNS (populated after phase 1)
    ProbeOrder  int         // for deterministic execution ordering
}
```

The scanner can then pipeline tasks: DNS tasks resolve first, producing addresses that feed TCP tasks, which feed TLS tasks, etc. This makes the concurrency model explicit and testable.

### 6.4 Configuration File Format (JSON/YAML)

```json
{
  "version": "1",
  "targets": [
    {
      "name": "example-custom",
      "domain": "example.com",
      "scheme": "https",
      "ports": [443],
      "control": false,
      "http_path": "/",
      "quic_port": 443,
      "compare_sni": []
    }
  ],
  "resolvers": [
    {"name": "system", "system": true},
    {"name": "cloudflare", "server": "1.1.1.1:53"},
    {"name": "google", "server": "8.8.8.8:53"},
    {"name": "quad9", "server": "9.9.9.9:53"},
    {"name": "custom", "server": "10.0.0.1:53"}
  ],
  "options": {
    "timeout": "5s",
    "retries": 3,
    "parallelism": 4
  }
}
```

The configuration-driven approach allows users to:
- Add censorship targets without recompiling
- Specify custom resolvers (relevant for testing with specific DNS providers)
- Override probe options per-target (e.g., longer timeout for slow targets)
- Share target sets with other iscan users

---

## 7. Architectural Decision Records

### ADR 1: Unified Probe Interface vs. Standalone Functions

**Decision:** Introduce a `probe.Probe` interface, implemented by all probes. Migrate incrementally -- not a rewrite.

**Context:** Current standalone functions (dnsprobe.Probe, tcp.Probe, etc.) have different signatures. The scanner must know each probe's calling convention.

**Consequences:**
- Positive: Retry, timeout, logging become middleware wrappers
- Positive: New probes only need to implement `Run()` and register
- Positive: The scanner becomes phase-driven, not probe-specific
- Negative: Initial migration touches all probe packages
- Mitigation: Keep the old functions as internal helpers, add a thin adapter struct that wraps the old function

**Migration path:**
1. Define `probe.Probe` interface in `internal/probe/interfaces.go`
2. For each probe package, create a struct implementing `Probe` that wraps the existing `Probe()` function
3. Add `init()` registration in each probe package
4. Update `scanner.go` to use the registry + phase plan
5. Remove old standalone functions after all consumers are migrated

### ADR 2: Type-Erasure at Registry Boundary vs. Generics

**Decision:** Use `ProbeResult` interface (type-erased) at the registry boundary. Consider generics for internal implementations if type switches become burdensome.

**Context:** A registry `map[string]func() Probe` with `Probe` returning a concrete type requires type parameters at the registry level, which Go doesn't support in maps. Type-erasing to `interface{}` or a `ProbeResult` interface is necessary.

**Consequences:**
- Positive: Registry is simple, homogeneous, and testable
- Positive: Consumers can define ProbeResult with just the methods they need (success, latency, layer)
- Negative: Concrete observation extraction requires type assertions/type switches
- Mitigation: Each probe type becomes the sum type. If this grows unwieldy, switch to a tagged union pattern.

### ADR 3: Per-Target Classification vs. Cross-Target Classification

**Decision:** Keep per-target classification as the primary path for findings. Add cross-target correlation as a second pass in the classifier.

**Context:** Current `Classify(result)` operates on a single TargetResult. Some censorship signals (especially SNI correlation with control targets) require comparing results across targets.

**Consequences:**
- Positive: Per-target classification is simple, parallelizable, and easy to test
- Positive: Cross-target correlation is a pure function on `[]TargetResult` -- no state needed
- Negative: Cross-target findings must be deduplicated with per-target findings
- Mitigation: Findings have a `TargetName` field. The report deduplication logic merges findings with the same type+target combination.

### ADR 4: Phase-Driven Execution vs. Single scanTarget Function

**Decision:** Refactor `scanTarget()` into a phase-driven pipeline. Current function orchestrates everything inline.

**Context:** `scanTarget()` currently has 90+ lines of sequential logic that hard-codes the probe ordering and data flow between probes (DNS results feed TCP, TCP results feed TLS, etc.). Adding a new protocol means editing this function.

**Consequences:**
- Positive: Phase plan is declarative -- probe ordering is data, not code
- Positive: Each phase can be tested independently
- Positive: New protocols slot into the phase plan without modifying existing phases
- Negative: Higher initial refactoring cost
- Mitigation: Phase plan can be built in the scanner based on options and registered probes, keeping the scanner as the single point of orchestration

### ADR 5: Configuration Files vs. Embedded Targets Only

**Decision:** Keep embedded targets as default, add file-based target sources for extensibility.

**Context:** Built-in targets ensure iscan works out of the box without configuration. But censorship environments vary regionally -- users need to add their own targets.

**Consequences:**
- Positive: Zero-config for common use cases
- Positive: Power users can customize
- Negative: File format parsing is additional code
- Mitigation: Use `encoding/json` and `gopkg.in/yaml.v3` (stdlib-friendly). Keep the schema minimal.

### ADR 6: Formatter Strategy vs. Standalone Functions

**Decision:** Use a `Formatter` interface with a registry, same pattern as probes.

**Context:** Current report functions are standalone and format-specific. Adding formats requires adding more standalone functions.

**Consequences:**
- Positive: Consistent pattern across the codebase
- Positive: Users can select format via `--format json|summary|html`
- Positive: Third-party formatters (if we ever allow them) follow the same contract
- Negative: Slightly more boilerplate per format

---

## 8. Data Flow Architecture (Per-Scan Lifecycle)

```
┌──────────────────────────────────────────────────────────────────────────┐
│ 1. CONFIGURATION                                                        │
│    CLI flags + config file + built-in defaults                          │
│    → model.ScanOptions, model.Target[], model.Resolver[]                │
└──────────────────────────────────────────────────────────────────────────┘
                            │
                            v
┌──────────────────────────────────────────────────────────────────────────┐
│ 2. TARGET EXPANSION                                                     │
│    For each target:
│      - Validate target definition
│      - Produce ExpandedTask per (target, resolver, qtype)
│    → []ExpandedTask (ordered for deterministic execution)               │
└──────────────────────────────────────────────────────────────────────────┘
                            │
                            v
┌──────────────────────────────────────────────────────────────────────────┐
│ 3. PHASE EXECUTION (sequential by phase, parallel within phase)         │
│                                                                         │
│  Phase 1: DNS                                                           │
│    Run per-resolver A + AAAA                                             │
│    Accumulate resolved IPs per target                                    │
│                                                                         │
│  Phase 2: TCP                                                           │
│    Run per (target_address, port)                                        │
│    Accumulate connectivity results                                       │
│                                                                         │
│  Phase 3: TLS                                                           │
│    Run per (successful_tcp, target_sni, compare_sni)                     │
│    Accumulate handshake results                                          │
│                                                                         │
│  Phase 4: HTTP (optional)                                               │
│    Run once per target (if TLS succeeded or HTTP scheme)                │
│    Accumulate HTTP response                                              │
│                                                                         │
│  Phase 5: QUIC (optional)                                               │
│    Run per (target_address, quic_port, sni)                              │
│    Accumulate QUIC handshake results                                     │
│                                                                         │
│  Phase 6: Trace (optional)                                              │
│    Run once per target                                                   │
│    Accumulate traceroute hops                                            │
│                                                                         │
│  Input: []ExpandedTask, ctx, parallelism limit                          │
│  Output: model.TargetResult (one per target)                            │
│  Concurrency: errgroup with semaphore (as currently implemented)         │
└──────────────────────────────────────────────────────────────────────────┘
                            │
                            v
┌──────────────────────────────────────────────────────────────────────────┐
│ 4. PER-TARGET CLASSIFICATION                                            │
│    For each TargetResult:
│      - Run registered Detectors
│      - Collect []Finding
│    → TargetResult.Findings (populated)                                  │
│    Concurrency: fully parallelizable                                    │
└──────────────────────────────────────────────────────────────────────────┘
                            │
                            v
┌──────────────────────────────────────────────────────────────────────────┐
│ 5. CROSS-TARGET CORRELATION (future)                                    │
│    For all TargetResults:
│      - Compare control vs test targets
│      - Generate cross-target Findings
│      - Merge with per-target findings (deduplicate)                     │
│    → []Finding (full report-level findings)                             │
└──────────────────────────────────────────────────────────────────────────┘
                            │
                            v
┌──────────────────────────────────────────────────────────────────────────┐
│ 6. PROFILE BUILDING (optional, --analyze)                               │
│    From all TargetResults + all Findings:
│      - DNS health: agreement, suspicious answers, latency
│      - TCP health: success rate, error modes
│      - TLS health: success rate, SNI filtering detection
│      - QUIC health: success rate
│      - Path health: hop count, RTT, jitter
│      - Overall stability: average of layer tiers
│    → profile.Profile                                                  │
└──────────────────────────────────────────────────────────────────────────┘
                            │
                            v
┌──────────────────────────────────────────────────────────────────────────┐
│ 7. RECOMMENDATION (optional, --analyze)                                 │
│    From Profile:
│      - Weighted scoring per protocol category
│      - Generate human-readable reasons per scoring
│    → recommend.Recommendation                                          │
└──────────────────────────────────────────────────────────────────────────┘
                            │
                            v
┌──────────────────────────────────────────────────────────────────────────┐
│ 8. REPORT GENERATION                                                    │
│    Select formatter by --format flag:
│      json    → JSONFormatter
│      summary → SummaryFormatter
│      (future) → HTMLFormatter, CSVFormatter                              │
│    → output bytes → stdout or file                                      │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 9. Error Aggregation and Cross-Probe Correlation

### 9.1 Current Error Handling

- TCP probe classifies errors into semantic kinds: timeout, refused, reset, unreachable
- TLS, HTTP, QUIC probes store raw error strings
- No systematic cross-probe error correlation

### 9.2 Proposed Error Taxonomy

Define a shared error classification that all probes emit:

```go
// ErrorClass classifies a network error by its semantics.
type ErrorClass string

const (
    ErrorTimeout          ErrorClass = "timeout"           // operation timed out
    ErrorConnectionRefused ErrorClass = "refused"          // TCP RST on connect
    ErrorConnectionReset  ErrorClass = "reset"             // TCP RST on established
    ErrorUnreachable      ErrorClass = "unreachable"       // ICMP unreachable
    ErrorDNSNXDOMAIN      ErrorClass = "dns_nxdomain"     // domain does not exist
    ErrorDNSSERVFAIL      ErrorClass = "dns_servfail"     // DNS server failure
    ErrorTLSCertInvalid   ErrorClass = "tls_cert_invalid" // certificate validation failure
    ErrorTLSHandshake     ErrorClass = "tls_handshake"    // generic TLS failure
    ErrorTLSVersion       ErrorClass = "tls_version"      // version negotiation failed
    ErrorQUICHandshake    ErrorClass = "quic_handshake"   // QUIC handshake failure
    ErrorHTTPError        ErrorClass = "http_error"       // non-2xx/3xx HTTP status
    ErrorPermission       ErrorClass = "permission"       // local permission denied
    ErrorOther            ErrorClass = "other"            // unclassified
)
```

**Cross-probe analysis patterns:**

| Pattern | Signal | Interpretation |
|---------|--------|---------------|
| TCP success + TLS failure | SNI-specific failure | SNI-based filtering |
| TCP success + TLS success + HTTP failure | Application-layer blocking | HTTP-level censorship |
| TCP success + QUIC failure (on same host) | UDP blocked | QUIC is blocked, not host-level |
| TCP failure + QUIC failure | Host-level blocking | General firewall block |
| DNS inconsistent (per target) | Resolver tampering | DNS-based censorship |
| DNS inconsistent (across targets) | General resolver issues | ISP resolver manipulation |

### 9.3 Error Aggregation

The `aggregateFailures` pattern in the current classifier is useful but limited to a single observation type. A richer aggregation would:

1. Group errors by target across all protocols
2. Identify the most constrained layer (the first one where all probes fail)
3. Flag patterns where higher-layer failure occurs without lower-layer failure (indicating layer-specific blocking)

```go
// ProtocolStackFailure represents a failure analysis across the networking stack.
type ProtocolStackFailure struct {
    Target           model.Target
    Layers           []Layer
    FirstFailure     Layer         // first layer where all probes fail
    // LayerStatus[candidate failure pattern]:
    // Example: "tcp/ok+tls/fail" means all TCP probes succeeded but TLS failed
    LayerPattern     string
    FailureSignature string        // e.g., "snifiltering", "dns_spoofing", "udp_blocking"
}
```

---

## 10. Scalability Considerations

### 10.1 Current Concurrency Model

- `errgroup` with `SetLimit(parallelism)` for target-level parallelism
- Within a target, probes run sequentially in `scanTarget()`
- System DNS resolver uses Go's built-in `net.DefaultResolver`
- No connection pooling or DNS caching across targets

### 10.2 Scaling Recommendations

| Concern | Current Behavior | Recommended for Target State |
|---------|-----------------|------------------------------|
| Target parallelism | 4 goroutines (hardcoded) | Configurable, auto-detect CPU cores |
| Per-target probes | Sequential within target | Phase-parallel: DNS and TCP can overlap partially |
| DNS caching | None | In-memory TTL-aware cache for repeated lookups |
| Connection reuse | None (each probe creates new connection) | TCP/TLS connection pooling for same (host, port, sni) |
| System resolver | Default Go resolver | Configurable between system/custom resolvers per phase |
| Rate limiting | None (concurrency limit only) | Token-bucket per destination to avoid rate limiting |

**Note:** For iscan's typical use case (a handful of targets, run once), these optimizations are unnecessary. They become relevant if iscan evolves to support:
- Continuous monitoring mode
- Large target sets (50+ domains)
- Integration with CI/CD pipelines

---

## 11. Phase-Oriented Implementation Roadmap

### Phase 1 (Current)
- Probe packages: dns, tcp, tls, http, quic, trace
- Standalone probe functions with different signatures
- Scanner orchestrates everything inline
- Classifier is a single function with inline heuristics
- Report: JSON and terminal summary

### Phase 2 (Unified Probe Interface)
- Define `probe.Probe` interface in `internal/probe/interfaces.go`
- Create adapter structs for each existing probe
- Add `init()` registration in each probe package
- Refactor scanner to use phase plan
- Move `retryWithBackoff` to middleware
- Add `ProbeResult` interface for type-erased result handling

### Phase 3 (Detector Architecture)
- Define `Detector` interface
- Extract each heuristic into its own detector struct
- Add detector registry (same pattern as probe registry)
- Add per-target confidence levels
- Add cross-target correlation pass

### Phase 4 (Target Management)
- Define `TargetSource` interface
- Builtin source (extract from current `targets.go`)
- JSON configuration file source
- Merge and validate from multiple sources
- CLI flags for ad-hoc single target

### Phase 5 (Report Pipeline)
- `Formatter` interface with registry
- Configurable output format via CLI flag
- Report envelope with metadata
- Optional streaming for long scans

---

## 12. Key Sources

- OONI Probe CLI architecture: https://github.com/ooni/probe-cli
- OONI netxlite documentation: https://pkg.go.dev/github.com/ooni/probe-cli/v3/internal/netxlite
- OONI step-by-step measurement tutorial: https://github.com/ooni/probe-cli/tree/master/internal/tutorial/measurex
- OONI step-by-step netxlite tutorial: https://github.com/ooni/probe-cli/tree/master/internal/tutorial/netxlite
- Measurement Kit (deprecated): https://github.com/measurement-kit/measurement-kit
- OONI architecture docs: http://docs.openobservatory.net/ooni/probe/architecture.html
- Go plugin architecture patterns (registry + init): https://www.php.cn/faq/1962003.html (Chinese, confirmed pattern)
- Go plugin framework comparison: https://github.com/pombredanne/pluggo
- Go extension points via code generation: https://github.com/progrium/go-extpoints
