# Coding Conventions

**Analysis Date:** 2026-04-26

## Language and Toolchain

**Language:** Go 1.24.0

**Formatters/Linters:** No explicit linter configuration detected. The project relies on the Go toolchain defaults (`gofmt`, `go vet`) with no `.golangci.yml`, `Makefile`, or custom lint rules.

## Naming Patterns

**Files:**
- Go source files: lowercase with underscores when multi-word (e.g., `dnsprobe/dns.go`, `httpprobe/http.go`, `tlsprobe/tls.go`)
- Test files: `_test.go` suffix appended to source file name (e.g., `dns_test.go`, `tls_test.go`, `classifier_test.go`)
- Package directories: single-word, lowercase (e.g., `scanner/`, `classifier/`, `profile/`, `recommend/`)
- Entry point: `cmd/iscan/main.go`

**Functions:**
- Exported: `PascalCase` (e.g., `Classify`, `BuildProfile`, `Rank`, `UniqueAnswers`, `HasSuccessfulTLSForSNI` in `scanner/scanner.go:220`, `IsLocalPermissionError` in `model/errors.go:15`)
- Unexported: `camelCase` (e.g., `dnsInconsistent`, `suspiciousDNS`, `aggregateFailures`, `sniCorrelatedFailures` in `classifier/classifier.go`)
- Test functions: `PascalCase` prefixed with `Test` (e.g., `TestClassifyReportsDNSInconsistencyWithoutPoisoning` in `classifier/classifier_test.go:10`)

**Variables:**
- `camelCase` throughout (e.g., `targetList`, `resolvers`, `observationGroup` in `scanner/scanner.go`)
- Loop variable shadow pattern: `i, target := i, target` in `scanner/scanner.go:52`
- Error variables: `Err` prefix (e.g., `ErrTargetNameRequired`, `ErrTargetDomainRequired` in `model/errors.go:6-10`)
- Test function parameters: `t *testing.T` always

**Types:**
- Exported types: `PascalCase` (e.g., `model.Target`, `model.ScanReport`, `model.Finding`, `model.TCPObservation`, `profile.Profile`, `profile.TCPHealth`)
- Unexported types: `camelCase` (e.g., `state` in `classifier/classifier.go:115`, `byKey` map in `aggregateFailures`)
- Const string types: typed constants with `PascalCase` names (e.g., `model.LayerDNS`, `model.ConfidenceLow`, `model.FindingDNSInconsistent` in `model/model.go`)

## Code Style

**Formatting:**
- Standard Go formatting (`gofmt` implied). Indentation uses tabs.
- JSON struct tags used consistently on all model types (e.g., ``json:"started_at"`, ``json:"targets"`)
- `omitempty` used on optional fields (e.g., `Errors []string \`json:"errors,omitempty"\``, `TLSObservation.CertSHA256`)

**Linting:**
- No linter config detected. The project passes `go vet ./...` without issues.

## Import Organization

The codebase follows a consistent three-group import order with blank-line separators:

1. **Standard library** (e.g., `context`, `net`, `sort`, `time`, `testing`)
2. **Third-party packages** (e.g., `github.com/spf13/cobra`, `github.com/miekg/dns`, `golang.org/x/sync/errgroup`, `github.com/quic-go/quic-go`)
3. **Internal packages** (e.g., `iscan/internal/model`, `iscan/internal/classifier`)

Example from `scanner/scanner.go:3-21`:
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
)
```

**Aliasing:**
- `mdns` alias used for `github.com/miekg/dns` (in `scanner/scanner.go:10`, `dnsprobe/dns.go:10`)
- No other import aliases used

## Error Handling

**Pattern:**
- Sentinel errors with `var` + `errors.New` pattern in `model/errors.go:5-11`:
  ```go
  var (
      ErrTargetNameRequired    = errors.New("target name is required")
      ErrTargetDomainRequired  = errors.New("target domain is required")
      ErrTargetSchemeInvalid   = errors.New("target scheme must be http or https")
      ErrTargetPortsRequired   = errors.New("target ports cannot be empty")
      ErrResolverServerInvalid = errors.New("resolver server address is invalid")
  )
  ```
- Error message string helpers for non-sentinel checks: `IsLocalPermissionError(msg string) bool` in `model/errors.go:15`
- Error classification via string matching in `tcp/classifyError` (`classifier/classifier.go:43`) using `errors.Is`, `os.IsTimeout`, and `strings.Contains` for platform portability
- Probe errors stored as `Error string` in observation structs -- not `error` types -- to enable JSON serialization

**Return convention:**
- Functions returning `error` use `fmt.Errorf` for formatted errors (e.g., `cmd/iscan/main.go:50`)
- Probe functions return typed observation structs containing `.Success bool` and `.Error string` instead of `(observation, error)` tuples
- `aggregateFailures` in `classifier/classifier.go:114` is a generic function using Go 1.18+ type parameters: `func aggregateFailures[T any]`

**Sentinel error usage:**
- `model.Target.Validate()` returns sentinel errors (`model/errors.go:49-62`)
- `errgroup.Wait()` errors are checked with `err != context.Canceled` pattern in `scanner/scanner.go:65`

## Logging

**No structured logging library detected.** Output uses:

- `fmt.Fprintln(os.Stderr, err)` for errors in `cmd/iscan/main.go:22`
- `fmt.Print(report.Summary(...))` for standard output in `cmd/iscan/main.go:85-88`
- `report.Summary()` uses `strings.Builder` + `text/tabwriter` for formatted terminal output (`report/report.go:27-50`)
- `report.SummaryExtended()` appends protocol ranking section to summary (`report/report.go:52-70`)
- Test diagnostics use `t.Fatalf` / `t.Errorf` / `t.Log`

## Comments

**When to Comment:**
- Exported functions with nontrivial behavior get a brief godoc comment
- Complex logic gets inline explanatory comments (e.g., `classifier/classifier.go:166-168` explains the GeoDNS false-positive avoidance)
- Test functions describe scenarios in their names (e.g., `TestClassifyDoesNotCompareAAndAAAAAsInconsistent`)

**Godoc style:**
- Short, descriptive sentences starting with the function name (e.g., `profile/profile.go:87`: "StabilityScore maps a quality tier to a numeric stability score.")
- Inline comments for non-obvious decisions:
  ```go
  // Primary rankings sorted by descending score.
  primary := []Ranking{long, udp, conservative}
  // recommend/recommend.go:103
  ```
  ```go
  // Use median absolute deviation (MAD) for jitter instead of
  // standard deviation to be robust against outlier hops.
  // profile/profile.go:259-261
  ```

## Function Design

**Size:**
- Probe functions: compact (15-80 lines), single responsibility
- `scanner.Run()` at 80 lines is the largest function (orchestrates the full scan)
- `classifier.Classify()` at 112 lines is the second largest (delegates to helper functions)

**Parameters:**
- Probes accept `(ctx context.Context, target-specific params..., timeout time.Duration) -> typed observation`
- Helper functions accept targeted parameters rather than broad structs
- `aggregateFailures` uses functional options pattern via callbacks: `keyFn`, `successFn`, `msgFn`

**Return Values:**
- Probes return typed observation structs (e.g., `model.TCPObservation`, `model.DNSObservation`, `model.TLSObservation`) -- never tuples
- Classifier and profile functions return computed results (e.g., `[]model.Finding`, `profile.Profile`)
- JSON serialization functions return `([]byte, error)`

## Module Design

**Exports:**
- Internal packages export minimal surface -- typically one or two public functions per package plus their types
- `probe/dnsprobe`: exports `Probe` function
- `probe/tcp`: exports `Probe` function
- `classifier`: exports `Classify` function
- `scanner`: exports `Run`, `UniqueAnswers`, `HasSuccessfulTLSForSNI`, `TargetURL`
- `report`: exports `JSON`, `JSONExtended`, `Summary`, `SummaryExtended`
- All model types are exported from `model` package

**Zero `init()` functions:** No `init()` functions detected anywhere in the codebase.

**No cyclic dependencies:** Package dependency chain is acyclic:

```
cmd/iscan
  -> model
  -> profile
  -> recommend
  -> report
  -> scanner
       -> classifier
       -> targets
       -> probe/dnsprobe
       -> probe/httpprobe
       -> probe/tcp
       -> probe/tlsprobe
       -> probe/quicprobe
       -> probe/traceprobe
```

## Concurrency Patterns

**errgroup usage:**
- `golang.org/x/sync/errgroup` used in `scanner/scanner.go:49` for concurrent target scanning
- `group.SetLimit(parallelism)` limits concurrency to `options.Parallelism`
- Go routine loop variables are captured with `i, target := i, target` (the classic Go loop variable copy pattern in `scanner/scanner.go:52`)
- Context cancellation: each goroutine checks `select { case <-gCtx.Done(): return gCtx.Err() default: }`

**No `sync.WaitGroup` or `sync.Mutex` used** (errgroup handles synchronization).

## Context Usage

- `context.Background()` as root in `cmd/iscan/main.go:52` with `signal.NotifyContext` for OS signals
- `context.WithTimeout` in `quicprobe/quic_test.go:12` for test context
- `t.Context()` used in `scanner/scanner_test.go:62` (Go 1.24)
- All probe functions accept `ctx context.Context` as first parameter
- `errgroup.WithContext(ctx)` wraps the context for cancellation propagation

## JSON Model Design

- All observation structs have full `json:"..."` tags
- Optional fields use `omitempty` (e.g., `model.Target.CompareSNI`, `model.TLSHandshakeFailure.Error`)
- Time fields use `time.Duration` (JSON serialized as nanoseconds via `time.Duration.MarshalJSON`)
- Enums are typed string constants (e.g., `model.Layer`, `model.Confidence`, `model.FindingType`)

## Anti-Patterns Observed

### Error as String in Structs

**What happens:** Probe observation structs store errors as `Error string` rather than `error` type values (e.g., `model.TCPObservation.Error`, `model.DNSObservation.Error`).

**Why this matters:** This prevents callers from using `errors.Is()` / `errors.As()` on probe errors. The `classifyError` function in `tcp.go` uses `errors.Is` internally, but the callers can only do string matching on the observation's `.Error` field.

**Where used:** All observation types in `model/model.go` -- `DNSObservation`, `TCPObservation`, `TLSObservation`, `HTTPObservation`, `QUICObservation`, `TraceObservation`

### Missing helper redundancy

**What happens:** `model/errors.go` defines its own `toLowerASCII` and `contains`/`indexString` helper functions instead of using `strings.ToLower` and `strings.Contains`.

**Why this matters:** The comment says "to avoid the full Unicode tables in this hot path" but this path is only called on probe result errors which is not a genuine hot path. This is premature optimization.

---

*Convention analysis: 2026-04-26*
