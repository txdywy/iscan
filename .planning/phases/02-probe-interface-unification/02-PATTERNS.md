# Phase 2: Probe Interface Unification - Pattern Map

**Mapped:** 2026-04-26
**Files analyzed:** 16 (6 new, 4 new sub-files in middleware, 6 modified)
**Analogs found:** 15 / 16

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `internal/probe/probe.go` (NEW) | model/interface | CRUD | `internal/model/model.go` | partial-match |
| `internal/probe/middleware/timeout.go` (NEW) | middleware | request-response | `internal/scanner/scanner.go:probeContext` | pattern-match |
| `internal/probe/middleware/retry.go` (NEW) | middleware | request-response | `internal/scanner/scanner.go:retryWithBackoff` | pattern-match |
| `internal/probe/middleware/logging.go` (NEW) | middleware | request-response | `internal/report/report.go` | partial-match |
| `internal/probe/middleware/chain.go` (NEW) | utility | none | (no analog) | none |
| `internal/probe/dnsprobe/adapter.go` (NEW) | adapter | request-response | `internal/probe/dnsprobe/dns.go:Probe` | role-match |
| `internal/probe/tcp/adapter.go` (NEW) | adapter | request-response | `internal/probe/tcp/tcp.go:Probe` | role-match |
| `internal/probe/tlsprobe/adapter.go` (NEW) | adapter | request-response | `internal/probe/tlsprobe/tls.go:Probe` | role-match |
| `internal/probe/httpprobe/adapter.go` (NEW) | adapter | request-response | `internal/probe/httpprobe/http.go:Probe` | role-match |
| `internal/probe/quicprobe/adapter.go` (NEW) | adapter | request-response | `internal/probe/quicprobe/quic.go:Probe` | role-match |
| `internal/probe/traceprobe/adapter.go` (NEW) | adapter | request-response | `internal/probe/traceprobe/trace.go:Probe` | role-match |
| `internal/model/model.go` (MODIFY) | model | CRUD | same file (existing TargetResult struct) | exact |
| `internal/scanner/scanner.go` (MODIFY) | service | CRUD | same file (existing scanTarget function) | exact |
| `internal/classifier/classifier.go` (MODIFY) | service | transform | same file (existing Classify function) | exact |
| `internal/profile/profile.go` (MODIFY) | service | transform | same file (existing profile*/BuildProfile functions) | exact |
| `internal/report/report.go` (MODIFY) | service | transform | same file (existing Summary function) | exact |

---

## Pattern Assignments

### `internal/probe/probe.go` (model/interface, CRUD)

**Analog:** `internal/model/model.go` (lines 1-180)

**Purpose:** Define the `Probe` interface, `ProbeResult` discriminated union type, `Registry` map, and `Target` adapter for probes.

**Imports pattern** (model/model.go lines 1-3):
```go
package model

import "time"
```

Follow same pattern for probe.go — minimal imports since most types are in `model`:
```go
package probe

import (
    "context"
    "iscan/internal/model"
)
```

**Type definition pattern with JSON struct tags** (model/model.go lines 88-98):
```go
type TargetResult struct {
    Target   Target            `json:"target"`
    Error    string            `json:"error,omitempty"`
    DNS      []DNSObservation  `json:"dns"`
    TCP      []TCPObservation  `json:"tcp"`
    TLS      []TLSObservation  `json:"tls"`
    HTTP     []HTTPObservation `json:"http"`
    QUIC     []QUICObservation `json:"quic,omitempty"`
    Trace    *TraceObservation `json:"trace,omitempty"`
    Findings []Finding         `json:"findings"`
}
```

New `ProbeResult` type follows same pattern:
```go
type ProbeResult struct {
    Layer model.Layer `json:"layer"`
    Data  any         `json:"data"`
}
```

**Interface definition pattern** (no direct analog in codebase — codebase is pre-interface).

Define interface with single method following Go convention:
```go
type Probe interface {
    Run(ctx context.Context, target model.Target) ProbeResult
}
```

**Registry map pattern** (analog from targets.go lines 5-6 in `targets/`):
```go
var Registry = map[model.Layer]Probe{}
```

**Layer constants already exist** in model/model.go lines 7-14:
```go
const (
    LayerDNS   Layer = "dns"
    LayerTCP   Layer = "tcp"
    LayerTLS   Layer = "tls"
    LayerHTTP  Layer = "http"
    LayerQUIC  Layer = "quic"
    LayerTrace Layer = "trace"
)
```

**New ProbeResult type derivative** — create helper function to construct ProbeResult:
```go
func NewResult(layer model.Layer, data any) ProbeResult {
    return ProbeResult{Layer: layer, Data: data}
}
```

---

### `internal/probe/middleware/timeout.go` (middleware, request-response)

**Analog:** `internal/scanner/scanner.go:probeContext` (lines 220-231)

**Pattern to extract** — the `probeContext` function computes per-probe deadline. The timeout middleware wraps this into the functional middleware pattern.

**Existing code (scanner.go lines 220-231):**
```go
func probeContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
    if deadline, ok := ctx.Deadline(); ok {
        remaining := time.Until(deadline)
        if remaining < timeout {
            timeout = remaining
        }
        if timeout <= 0 {
            timeout = time.Nanosecond
        }
    }
    return context.WithTimeout(ctx, timeout)
}
```

**Middleware pattern** — type alias and function signature:
```go
type Middleware func(Probe) Probe

func Timeout(timeout time.Duration) Middleware {
    return func(next Probe) Probe {
        return ProbeFunc(func(ctx context.Context, target model.Target) ProbeResult {
            pctx, cancel := probeContext(ctx, timeout)
            defer cancel()
            return next.Run(pctx, target)
        })
    }
}
```

---

### `internal/probe/middleware/retry.go` (middleware, request-response)

**Analog:** `internal/scanner/scanner.go:retryWithBackoff` (lines 284-319)

**Existing code (scanner.go lines 284-319):**
```go
func retryWithBackoff[T any](ctx context.Context, maxAttempts int, baseDelay time.Duration, probe func() (T, bool)) T {
    var zero T
    var last T
    var hasLast bool
    for attempt := 0; attempt < maxAttempts; attempt++ {
        if ctx.Err() != nil {
            if hasLast {
                return last
            }
            return zero
        }
        result, ok := probe()
        last = result
        hasLast = true
        if ok {
            return result
        }
        if attempt < maxAttempts-1 {
            delay := baseDelay * (1 << attempt)
            timer := time.NewTimer(delay)
            select {
            case <-ctx.Done():
                timer.Stop()
                if hasLast {
                    return last
                }
                return zero
            case <-timer.C:
            }
        }
    }
    if hasLast {
        return last
    }
    return zero
}
```

**Middleware pattern** — same retry logic but adapted to Probe interface:
```go
func Retry(maxAttempts int, baseDelay time.Duration) Middleware {
    return func(next Probe) Probe {
        return ProbeFunc(func(ctx context.Context, target model.Target) ProbeResult {
            var last ProbeResult
            for attempt := 0; attempt < maxAttempts; attempt++ {
                if ctx.Err() != nil {
                    return last
                }
                last = next.Run(ctx, target)
                // Check success — ProbeResult uses data's .Success field via type switch
                if obs, ok := last.Data.(successIndicator); ok && obs.Success() {
                    return last
                }
                if attempt < maxAttempts-1 {
                    delay := baseDelay * (1 << attempt)
                    timer := time.NewTimer(delay)
                    select {
                    case <-ctx.Done():
                        timer.Stop()
                        return last
                    case <-timer.C:
                    }
                }
            }
            return last
        })
    }
}
```

**Note:** The `successIndicator` pattern uses a type assertion on `ProbeResult.Data`. Each observation type (DNSObservation, TCPObservation, etc.) has a `Success bool` field that can be extracted via a common interface or type switch. This replaces the generic `func() (T, bool)` pattern.

---

### `internal/probe/middleware/logging.go` (middleware, request-response)

**Analog:** `internal/report/report.go:Summary` (lines 27-49) for formatting patterns; no logging middleware exists.

**Existing code — status formatting pattern (report.go lines 103-113):**
```go
func statusBool(count int, success func(int) bool) string {
    if count == 0 {
        return "skip"
    }
    for i := 0; i < count; i++ {
        if success(i) {
            return "ok"
        }
    }
    return "fail"
}
```

**Logging middleware:**
```go
func Logging(logger func(string, ...any)) Middleware {
    return func(next Probe) Probe {
        return ProbeFunc(func(ctx context.Context, target model.Target) ProbeResult {
            start := time.Now()
            result := next.Run(ctx, target)
            latency := time.Since(start)
            layer := result.Layer
            logger("[probe] %s %s %s (%v)", layer, target.Domain, statusFromResult(result), latency)
            return result
        })
    }
}
```

---

### `internal/probe/middleware/chain.go` (utility, none)

**No direct analog in codebase.** This is pure function composition. Minimal boilerplate:

```go
func Chain(probe Probe, middleware ...Middleware) Probe {
    for i := len(middleware) - 1; i >= 0; i-- {
        probe = middleware[i](probe)
    }
    return probe
}
```

---

### `internal/probe/dnsprobe/adapter.go` (adapter, request-response)

**Analog:** `internal/probe/dnsprobe/dns.go:Probe` (lines 14-78)

**Existing Probe signature (dns.go line 14):**
```go
func Probe(ctx context.Context, resolver model.Resolver, domain string, qtype uint16, timeout time.Duration) model.DNSObservation {
```

**Adapter pattern** — wrap the existing function in the Probe interface:
```go
package dnsprobe

import (
    "context"
    mdns "github.com/miekg/dns"
    "iscan/internal/model"
    "iscan/internal/probe"
)

type Opts struct {
    Resolver model.Resolver `json:"resolver,omitempty"`
    QType    uint16         `json:"qtype,omitempty"`
}

type Adapter struct {
    Opts Opts
}

func (a *Adapter) Run(ctx context.Context, target model.Target) probe.ProbeResult {
    obs := Probe(ctx, a.Opts.Resolver, target.Domain, a.Opts.QType, 5*time.Second)
    return probe.NewResult(model.LayerDNS, obs)
}

func init() {
    // A-record probe
    probe.Registry[model.LayerDNS] = &Adapter{
        Opts: Opts{QType: mdns.TypeA, Resolver: model.Resolver{Name: "system", System: true}},
    }
}
```

**The init() registration pattern** (new to codebase; no existing init-based registration):
- Each adapter.go has one `init()` per layer variant it registers
- The scanner imports the probe packages for side effects (D-11)
- Same import-aliasing convention: `mdns "github.com/miekg/dns"` (dns.go line 10)

---

### `internal/probe/tcp/adapter.go` (adapter, request-response)

**Analog:** `internal/probe/tcp/tcp.go:Probe` (line 16)

**Existing Probe signature (tcp.go line 16):**
```go
func Probe(ctx context.Context, host string, port int, timeout time.Duration) model.TCPObservation {
```

**Adapter pattern:**
```go
package tcp

import (
    "context"
    "iscan/internal/model"
    "iscan/internal/probe"
)

type Opts struct {
    Timeout time.Duration `json:"timeout,omitempty"`
}

type Adapter struct {
    Opts Opts
}

func (a *Adapter) Run(ctx context.Context, target model.Target) probe.ProbeResult {
    // Probe against each target port; for single-port case use first port.
    // (Port iteration logic moves out of scanner into adapter or caller.)
    port := 443
    if len(target.Ports) > 0 {
        port = target.Ports[0]
    }
    obs := Probe(ctx, target.Domain, port, a.Opts.Timeout)
    return probe.NewResult(model.LayerTCP, obs)
}

func init() {
    probe.Registry[model.LayerTCP] = &Adapter{
        Opts: Opts{Timeout: 5 * time.Second},
    }
}
```

---

### `internal/probe/tlsprobe/adapter.go` (adapter, request-response)

**Analog:** `internal/probe/tlsprobe/tls.go:Probe` (line 15)

**Existing Probe signature (tls.go line 15):**
```go
func Probe(ctx context.Context, host string, port int, sni string, nextProtos []string, timeout time.Duration, insecureSkipVerify bool) model.TLSObservation {
```

**Adapter pattern:**
```go
package tlsprobe

import (
    "context"
    "iscan/internal/model"
    "iscan/internal/probe"
)

type Opts struct {
    NextProtos         []string `json:"next_protos,omitempty"`
    InsecureSkipVerify bool     `json:"insecure_skip_verify,omitempty"`
}

type Adapter struct {
    Opts Opts
}

func (a *Adapter) Run(ctx context.Context, target model.Target) probe.ProbeResult {
    port := 443
    if len(target.Ports) > 0 {
        port = target.Ports[0]
    }
    address := target.Domain
    obs := Probe(ctx, address, port, target.Domain, a.Opts.NextProtos, 5*time.Second, a.Opts.InsecureSkipVerify)
    return probe.NewResult(model.LayerTLS, obs)
}

func init() {
    probe.Registry[model.LayerTLS] = &Adapter{
        Opts: Opts{NextProtos: []string{"h2", "http/1.1"}, InsecureSkipVerify: true},
    }
}
```

---

### `internal/probe/httpprobe/adapter.go` (adapter, request-response)

**Analog:** `internal/probe/httpprobe/http.go:Probe` and `ProbeWithAddress` (lines 15-21)

**Existing Probe signatures (http.go lines 15-21):**
```go
func Probe(ctx context.Context, url string, timeout time.Duration) model.HTTPObservation {
    return probe(ctx, url, "", timeout)
}

func ProbeWithAddress(ctx context.Context, url string, dialAddress string, timeout time.Duration) model.HTTPObservation {
    return probe(ctx, url, dialAddress, timeout)
}
```

**Adapter pattern:**
```go
package httpprobe

import (
    "context"
    "iscan/internal/model"
    "iscan/internal/probe"
)

type Opts struct {
    DialAddress string `json:"dial_address,omitempty"`
}

type Adapter struct {
    Opts Opts
}

func (a *Adapter) Run(ctx context.Context, target model.Target) probe.ProbeResult {
    url := probe.TargetURL(target) // or construct within adapter
    obs := Probe(ctx, url, 5*time.Second)
    return probe.NewResult(model.LayerHTTP, obs)
}

func init() {
    probe.Registry[model.LayerHTTP] = &Adapter{}
}
```

---

### `internal/probe/quicprobe/adapter.go` (adapter, request-response)

**Analog:** `internal/probe/quicprobe/quic.go:Probe` (line 17)

**Existing Probe signature (quic.go line 17):**
```go
func Probe(ctx context.Context, host string, port int, sni string, alpn []string, timeout time.Duration) model.QUICObservation {
```

**Adapter pattern:**
```go
package quicprobe

import (
    "context"
    "iscan/internal/model"
    "iscan/internal/probe"
)

type Opts struct {
    ALPN []string `json:"alpn,omitempty"`
}

type Adapter struct {
    Opts Opts
}

func (a *Adapter) Run(ctx context.Context, target model.Target) probe.ProbeResult {
    port := target.QUICPort
    if port <= 0 {
        port = 443
    }
    obs := Probe(ctx, target.Domain, port, target.Domain, a.Opts.ALPN, 5*time.Second)
    return probe.NewResult(model.LayerQUIC, obs)
}

func init() {
    probe.Registry[model.LayerQUIC] = &Adapter{
        Opts: Opts{ALPN: []string{"h3"}},
    }
}
```

---

### `internal/probe/traceprobe/adapter.go` (adapter, request-response)

**Analog:** `internal/probe/traceprobe/trace.go:Probe` (line 17) and `ProbeHop` (line 91)

**Existing Probe signature (trace.go line 17):**
```go
func Probe(ctx context.Context, target string, timeout time.Duration) (observation model.TraceObservation) {
```

**Adapter pattern:**
```go
package traceprobe

import (
    "context"
    "iscan/internal/model"
    "iscan/internal/probe"
)

type Opts struct{}

type Adapter struct{}

func (a *Adapter) Run(ctx context.Context, target model.Target) probe.ProbeResult {
    obs := Probe(ctx, target.Domain, 5*time.Second)
    return probe.NewResult(model.LayerTrace, obs)
}

func init() {
    probe.Registry[model.LayerTrace] = &Adapter{}
}
```

Note: Trace probe returns `*TraceObservation` currently (pointer) while others return slices. The adapter normalizes this — TraceObservation goes into `ProbeResult.Data` as a value, not a pointer. The consumer (classifier/profile/report) uses a type switch to handle the struct vs slice distinction.

---

### `internal/model/model.go` (MODIFY, model, CRUD)

**Analog:** Same file, existing `TargetResult` struct (lines 88-98)

**Existing TargetResult (lines 88-98):**
```go
type TargetResult struct {
    Target   Target            `json:"target"`
    Error    string            `json:"error,omitempty"`
    DNS      []DNSObservation  `json:"dns"`
    TCP      []TCPObservation  `json:"tcp"`
    TLS      []TLSObservation  `json:"tls"`
    HTTP     []HTTPObservation `json:"http"`
    QUIC     []QUICObservation `json:"quic,omitempty"`
    Trace    *TraceObservation `json:"trace,omitempty"`
    Findings []Finding         `json:"findings"`
}
```

**Replacement (per D-03, D-04):**
```go
type ProbeResult struct {
    Layer Layer `json:"layer"`
    Data  any   `json:"data"`
}

type TargetResult struct {
    Target   Target       `json:"target"`
    Error    string       `json:"error,omitempty"`
    Results  []ProbeResult `json:"results"`
    Findings []Finding    `json:"findings"`
}
```

**JSON struct tag conventions** (lines 88-98) — `omitempty` on optional fields, lowercase snake_case for keys. This convention is already used throughout model.go.

**Existing Layer constants** (lines 7-14) — remain unchanged, reused as the discriminant in `ProbeResult.Layer`.

**Existing observation types** (DNSObservation lines 100-110, TCPObservation lines 112-120, TLSObservation lines 122-131, HTTPObservation lines 133-144, QUICObservation lines 146-155, TraceObservation lines 157-163) — all remain unchanged. Their types are used as the `Data any` values in ProbeResult.

---

### `internal/scanner/scanner.go` (MODIFY, service, CRUD)

**Analog:** Same file, existing `scanTarget` function (lines 82-166) and `retryWithBackoff` (lines 284-319) and `probeContext` (lines 220-231)

**Existing scanTarget pattern (lines 82-166):** Sequential per-probe callsites — DNS loop, TCP loop, TLS loop, HTTP call, QUIC loop, Trace call. Each has its own retry/context logic duplicated inline.

**Refactored pattern (per D-08, D-09):**
```go
func scanTarget(ctx context.Context, target model.Target, probes []probe.Probe, options model.ScanOptions) model.TargetResult {
    result := model.TargetResult{Target: target, Results: make([]probe.ProbeResult, 0, len(probes))}
    for _, p := range probes {
        if ctx.Err() != nil {
            return result
        }
        pr := p.Run(ctx, target)
        result.Results = append(result.Results, pr)
    }
    return result
}
```

**Existing import pattern (lines 3-21)** — three-group import: stdlib, third-party, internal:
```go
import (
    "context"
    "net"
    "net/url"
    "sort"
    "time"

    mdns "github.com/miekg/dns"
    "golang.org/x/sync/errgroup"

    "iscan/internal/classifier"
    "iscan/internal/model"
    "iscan/internal/probe/dnsprobe"
    "iscan/internal/probe/httpprobe"
    "iscan/internal/probe/quicprobe"
    "iscan/internal/probe/tcp"
    "iscan/internal/probe/tlsprobe"
    "iscan/internal/probe/traceprobe"
    "iscan/internal/targets"
)
```

**Post-refactoring imports:** Individual probe packages replaced by `"iscan/internal/probe"` plus import-for-side-effects on adapter packages:
```go
import (
    "context"
    "time"

    "golang.org/x/sync/errgroup"

    "iscan/internal/classifier"
    "iscan/internal/model"
    "iscan/internal/probe"
    _ "iscan/internal/probe/dnsprobe"
    _ "iscan/internal/probe/httpprobe"
    _ "iscan/internal/probe/quicprobe"
    _ "iscan/internal/probe/tcp"
    _ "iscan/internal/probe/tlsprobe"
    _ "iscan/internal/probe/traceprobe"
    "iscan/internal/targets"
)
```

**Probe construction in Run() (analog: existing logic pattern in lines 24-80):**
```go
var probes []probe.Probe
probes = append(probes,
    probe.Registry[model.LayerDNS],
    probe.Registry[model.LayerTCP],
    probe.Registry[model.LayerTLS],
    probe.Registry[model.LayerHTTP],
)
if options.QUIC {
    probes = append(probes, probe.Registry[model.LayerQUIC])
}
if options.Trace {
    probes = append(probes, probe.Registry[model.LayerTrace])
}
// Wrap with middleware chain
base := probe.Chain(
    probes[0],
    middleware.Timeout(options.Timeout),
    middleware.Retry(options.Retries, 50*time.Millisecond),
    middleware.Logging(log.Printf),
)
```

---

### `internal/classifier/classifier.go` (MODIFY, service, transform)

**Analog:** Same file, existing `Classify` function (lines 13-112)

**Existing per-field access pattern (lines 16-110):**
```go
func Classify(result model.TargetResult) []model.Finding {
    now := time.Now()
    var findings []model.Finding
    if dnsInconsistent(result.DNS) {               // result.DNS -- named field
        findings = append(findings, ...)
    }
    if evidence := suspiciousDNS(result.DNS); ... { // result.DNS
        ...
    }
    if evidence := aggregateFailures(result.TCP,    // result.TCP
        func(o model.TCPObservation) string { return ... },
```

**New pattern — iterate over Results by Layer (per D-03):**
```go
func Classify(result model.TargetResult) []model.Finding {
    now := time.Now()
    var findings []model.Finding

    dnsObs := collectObservations[model.DNSObservation](result.Results, model.LayerDNS)
    tcpObs := collectObservations[model.TCPObservation](result.Results, model.LayerTCP)
    tlsObs := collectObservations[model.TLSObservation](result.Results, model.LayerTLS)
    httpObs := collectObservations[model.HTTPObservation](result.Results, model.LayerHTTP)
    quicObs := collectObservations[model.QUICObservation](result.Results, model.LayerQUIC)
    traceObs := collectObservation[model.TraceObservation](result.Results, model.LayerTrace)

    // Then use local variables instead of result.DNS, result.TCP, etc.
    if dnsInconsistent(dnsObs) { ... }
    ...
}
```

**Generic helper pattern** — following existing `aggregateFailures[T any]` generic pattern (lines 114-142):
```go
func collectObservations[T any](results []probe.ProbeResult, layer model.Layer) []T {
    var out []T
    for _, r := range results {
        if r.Layer == layer {
            if obs, ok := r.Data.(T); ok {
                out = append(out, obs)
            }
        }
    }
    return out
}

func collectObservation[T any](results []probe.ProbeResult, layer model.Layer) *T {
    for _, r := range results {
        if r.Layer == layer {
            if obs, ok := r.Data.(T); ok {
                return &obs
            }
        }
    }
    return nil
}
```

**Existing type parameter function pattern (lines 114-142) from aggregateFailures:**
```go
func aggregateFailures[T any](observations []T, keyFn func(T) string, successFn func(T) bool, msgFn func(T) string) []string {
```

This pattern is the template for `collectObservations[T any]`.

---

### `internal/profile/profile.go` (MODIFY, service, transform)

**Analog:** Same file, existing profile functions (lines 116-340)

**Existing pattern — profileDNS accesses result.DNS (lines 130-166):**
```go
func profileDNS(report model.ScanReport) DNSHealth {
    h := DNSHealth{}
    resolvers := map[string]struct{}{}
    var totalLatency time.Duration
    var latencyCount int
    for _, target := range report.Targets {
        for _, obs := range target.DNS {   // named field access
            resolvers[obs.Resolver] = struct{}{}
            ...
```

**New pattern — extract per-layer observations then process:**
```go
func profileDNS(report model.ScanReport) DNSHealth {
    h := DNSHealth{}
    resolvers := map[string]struct{}{}
    var totalLatency time.Duration
    var latencyCount int
    for _, target := range report.Targets {
        dnsObs := collectObservations[model.DNSObservation](target.Results, model.LayerDNS)
        for _, obs := range dnsObs {
            resolvers[obs.Resolver] = struct{}{}
            ...
```

**Existing `extractISP` (lines 116-128) accesses `target.Trace` as a pointer:**
```go
func extractISP(report model.ScanReport) ISPInfo {
    info := ISPInfo{}
    for _, target := range report.Targets {
        if target.Trace == nil || len(target.Trace.Hops) == 0 {
            continue
        }
```

**New pattern — collect trace observation:**
```go
func extractISP(report model.ScanReport) ISPInfo {
    info := ISPInfo{}
    for _, target := range report.Targets {
        traceObs := collectObservation[model.TraceObservation](target.Results, model.LayerTrace)
        if traceObs == nil || len(traceObs.Hops) == 0 {
            continue
        }
        if info.FirstHop == "" {
            hop := traceObs.Hops[0]
            info.FirstHop = hop.Address
        }
    }
    return info
}
```

---

### `internal/report/report.go` (MODIFY, service, transform)

**Analog:** Same file, existing `Summary` function (lines 27-49)

**Existing pattern (lines 27-49):**
```go
func Summary(scan model.ScanReport) string {
    var b strings.Builder
    w := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
    _, _ = fmt.Fprintln(w, "TARGET\tDNS\tTCP\tTLS\tQUIC\tHTTP\tTRACE\tFINDINGS")
    for _, target := range scan.Targets {
        _, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
            target.Target.Domain,
            statusBool(len(target.DNS), func(i int) bool { return target.DNS[i].Success }),
            statusBool(len(target.TCP), func(i int) bool { return target.TCP[i].Success }),
            statusBool(len(target.TLS), func(i int) bool { return target.TLS[i].Success }),
            statusBool(len(target.QUIC), func(i int) bool { return target.QUIC[i].Success }),
            statusBool(len(target.HTTP), func(i int) bool { return target.HTTP[i].Success }),
            statusTrace(target.Trace),
            findingTypes(target.Findings),
        )
    }
```

**New pattern — iterate over Results per layer:**
```go
func Summary(scan model.ScanReport) string {
    var b strings.Builder
    w := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
    _, _ = fmt.Fprintln(w, "TARGET\tDNS\tTCP\tTLS\tQUIC\tHTTP\tTRACE\tFINDINGS")
    for _, target := range scan.Targets {
        _, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
            target.Target.Domain,
            statusFromResults(target.Results, model.LayerDNS),
            statusFromResults(target.Results, model.LayerTCP),
            statusFromResults(target.Results, model.LayerTLS),
            statusFromResults(target.Results, model.LayerQUIC),
            statusFromResults(target.Results, model.LayerHTTP),
            statusFromResults(target.Results, model.LayerTrace),
            findingTypes(target.Findings),
        )
    }
```

**New helper for status from Results (following statusBool and statusTrace patterns from same file lines 93-113):**
```go
func statusFromResults(results []probe.ProbeResult, layer model.Layer) string {
    for _, r := range results {
        if r.Layer != layer {
            continue
        }
        if hasSuccess(r.Data) {
            return "ok"
        }
        return "fail"
    }
    return "skip"
}

func hasSuccess(data any) bool {
    switch v := data.(type) {
    case model.DNSObservation:  return v.Success
    case model.TCPObservation:  return v.Success
    case model.TLSObservation:  return v.Success
    case model.HTTPObservation: return v.Success
    case model.QUICObservation: return v.Success
    case model.TraceObservation: return v.Success
    }
    return false
}
```

**Existing `statusTrace` (lines 93-101)** is no longer needed as a separate function:
```go
func statusTrace(observation *model.TraceObservation) string {
    if observation == nil {
        return "skip"
    }
    if observation.Success {
        return "ok"
    }
    return "warn"
}
```

**Existing `findingTypes` (lines 115-130)** — remains unchanged, operates on `target.Findings` which is not affected by the refactoring.

---

## Shared Patterns

### import Organization
**Source:** All existing files follow three-group convention (stdlib / third-party / internal). Example from `scanner/scanner.go` lines 3-21.
**Apply to:** All new and modified files.

### JSON Struct Tags
**Source:** `internal/model/model.go` lines 88-98 — lowercase snake_case, `omitempty` on optional fields.
**Apply to:** `model/model.go` new `ProbeResult` type, adapter `Opts` structs in all adapter.go files.

### Generic Function Pattern with Type Parameters
**Source:** `internal/classifier/classifier.go` lines 114-142 (`aggregateFailures[T any]`)
**Apply to:** `classifier.go` (new `collectObservations[T any]`), `scanner.go` (already has `retryWithBackoff[T any]` lines 284-319)

### Error Handling — String-Based Error in Observations
**Source:** All observation types in `model/model.go` use `Error string` (not `error` type) for JSON serialization (convention from CONVENTIONS.md).
**Apply to:** Any new observation types or fields in `ProbeResult`.

### Package-Level Test Pattern (external test packages)
**Source:** All test files use `packagename_test` convention (e.g., `package classifier_test`, `package model_test`) and import internal packages. Example from `classifier_test.go` lines 1-8.
**Apply to:** Test files for adapters and middleware.

### Test Table Pattern
**Source:** `model/errors_test.go` lines 10-27 — table-driven tests with `cases := []struct{...}`.
**Apply to:** All test files.

### init() Registration for Adapters
**New pattern (no existing analog):** Each adapter package registers itself in `probe.Registry` via `init()`. The scanner imports adapter packages with `_ "iscan/internal/probe/dnsprobe"` for side effects (D-10, D-11).

### Probe Interface / ProbeFunc Pattern
**New pattern (no existing analog):** The interface + functional adapter follows standard Go patterns:
```go
// Probe interface
type Probe interface {
    Run(ctx context.Context, target model.Target) ProbeResult
}

// ProbeFunc adapter — converts a function to Probe
type ProbeFunc func(context.Context, model.Target) ProbeResult

func (f ProbeFunc) Run(ctx context.Context, target model.Target) ProbeResult {
    return f(ctx, target)
}
```

---

## No Analog Found

| File | Role | Data Flow | Reason |
|------|------|-----------|--------|
| `internal/probe/middleware/chain.go` | utility | none | Pure function composition; no comparable code exists in the codebase |

---

## Metadata

**Analog search scope:** `internal/model/`, `internal/scanner/`, `internal/classifier/`, `internal/profile/`, `internal/report/`, `internal/probe/*/`, `cmd/iscan/`
**Files scanned:** 20 Go source files, 10 Go test files, 1 reference doc
**Pattern extraction date:** 2026-04-26
