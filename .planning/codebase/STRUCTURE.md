# Codebase Structure

**Analysis Date:** 2026-04-26

## Directory Layout

```
iscan/
├── cmd/
│   └── iscan/
│       └── main.go                  # CLI entry point, flag parsing, pipeline orchestration
├── internal/
│   ├── classifier/
│   │   ├── classifier.go            # Finding generation from per-target observations
│   │   └── classifier_test.go       # Unit tests for finding generation
│   ├── model/
│   │   ├── model.go                 # All shared types: ScanReport, Target, Observations, Findings
│   │   ├── errors.go                # Error sentinels and permission-error helper
│   │   ├── errors_test.go           # Tests for error helpers and target validation
│   │   └── model.go implicitly tested by other packages
│   ├── probe/
│   │   ├── dnsprobe/
│   │   │   ├── dns.go               # DNS A/AAAA query probe with TCP truncation fallback
│   │   │   └── dns_test.go          # Integration tests with in-process DNS server
│   │   ├── httpprobe/
│   │   │   ├── http.go              # HTTP GET probe with httptrace timing
│   │   │   └── http_test.go         # Integration tests with httptest server
│   │   ├── quicprobe/
│   │   │   ├── quic.go              # QUIC handshake probe via quic-go
│   │   │   └── quic_test.go         # Integration test against non-QUIC endpoint
│   │   ├── tcp/
│   │   │   ├── tcp.go               # Raw TCP dial probe with error classification
│   │   │   └── tcp_test.go          # Integration tests with local TCP listener
│   │   ├── tlsprobe/
│   │   │   ├── tls.go               # TLS handshake probe with configurable SNI/ALPN
│   │   │   └── tls_test.go          # Integration tests with httptest TLS server
│   │   └── traceprobe/
│   │       └── trace.go             # ICMP traceroute probe (privileged)
│   ├── profile/
│   │   ├── profile.go               # Per-layer health profile builder
│   │   └── profile_test.go          # Unit tests for profile computation
│   ├── recommend/
│   │   ├── recommend.go             # Protocol strategy ranking engine
│   │   └── recommend_test.go        # Unit tests for ranking logic
│   ├── report/
│   │   ├── report.go                # JSON and terminal summary formatters
│   │   └── report_test.go           # Unit test for summary formatting
│   ├── scanner/
│   │   ├── scanner.go               # Concurrent scan orchestrator
│   │   └── scanner_test.go          # Unit tests + smoke test for Run()
│   └── targets/
│       └── targets.go               # Builtin target definitions and resolver list
├── .planning/
│   └── codebase/                    # Codebase analysis documents (this file)
├── go.mod
├── go.sum
└── README.md
```

## Directory Purposes

**`cmd/iscan/`:**
- Purpose: Application entry point — parses CLI flags using cobra, wires dependencies, invokes the pipeline
- Contains: `main.go` only (single binary output `iscan`)
- Key files: `cmd/iscan/main.go` — all flag definitions and the full `scan` command `RunE` closure

**`internal/model/`:**
- Purpose: Central type system for the entire codebase — defines all data structures, error sentinels, and permission-error helper
- Contains: Model types (`model.go`), error definitions (`errors.go`), corresponding tests
- Key files: `model.go` (177 lines, largest single source of type definitions), `errors.go` (utility error helpers)
- Imported by: Every other package in the codebase

**`internal/probe/` (6 subpackages):**
- Purpose: Each subpackage implements one protocol's network probe as a single exported `Probe()` function
- Subpackage conventions:
  - `dnsprobe/`, `httpprobe/`, `tlsprobe/`, `quicprobe/` — use `-probe` suffix
  - `tcp/`, `traceprobe/` — no suffix for tcp, `-probe` suffix for trace
- Each probe returns a `model.*Observation` struct
- 5 of 6 probe packages have `_test.go` files; `traceprobe/` does not (requires privileges)

**`internal/classifier/`:**
- Purpose: Examine per-target probe results and generate evidence-backed `Finding` structs
- Contains: `classifier.go` (255 lines) with `Classify` and generic helpers

**`internal/profile/`:**
- Purpose: Aggregate a full `ScanReport` into per-layer health profiles with quality tiers
- Contains: `profile.go` (334 lines) with `BuildProfile`, layer-specific profilers, quality tier mapping

**`internal/recommend/`:**
- Purpose: Compute weighted protocol strategy rankings based on profile data
- Contains: `recommend.go` (242 lines) with `Rank`, weight constants, scoring functions, bilingual reason generators

**`internal/report/`:**
- Purpose: Format results for human and machine consumption
- Contains: `report.go` (126 lines) with JSON serialization and terminal tabwriter output

**`internal/scanner/`:**
- Purpose: Orchestrate concurrent multi-protocol scanning across all targets, manage retries
- Contains: `scanner.go` (236 lines) with `Run` (entry point), `scanTarget` (probe sequence), helper functions

**`internal/targets/`:**
- Purpose: Define builtin target and resolver lists
- Contains: `targets.go` (54 lines) — compile-time data only

## Key File Locations

**Entry Points:**
- `cmd/iscan/main.go`: CLI entry point, cobra command tree, main() function

**Configuration:**
- `cmd/iscan/main.go` line 28-103: All CLI flag definitions and defaults
- No config files; all configuration is via flags

**Core Logic (by pipeline stage):**
- `internal/scanner/scanner.go`: Concurrent scan orchestration (pipeline stage 1)
- `internal/classifier/classifier.go`: Finding generation (pipeline stage 2)
- `internal/profile/profile.go`: Health profile computation (optional stage 3)
- `internal/recommend/recommend.go`: Protocol ranking (optional stage 4)
- `internal/report/report.go`: Output formatting (final stage)

**Probes:**
- `internal/probe/dnsprobe/dns.go`: DNS probe
- `internal/probe/tcp/tcp.go`: TCP probe
- `internal/probe/tlsprobe/tls.go`: TLS probe
- `internal/probe/httpprobe/http.go`: HTTP probe
- `internal/probe/quicprobe/quic.go`: QUIC probe
- `internal/probe/traceprobe/trace.go`: ICMP traceroute probe

**Testing:**
- All test files are co-located with their source package: `*_test.go` in the same directory
- Test files use external test packages (`package xxx_test`) — see `testing_pattern` below
- Unit tests: `classifier_test.go`, `recommend_test.go`, `report_test.go`, `model/errors_test.go`, `profile_test.go`, `scanner_test.go`
- Integration tests: `dnsprobe/dns_test.go`, `tcp/tcp_test.go`, `tlsprobe/tls_test.go`, `httpprobe/http_test.go`, `quicprobe/quic_test.go`

## Naming Conventions

**Files:**
- Go source: `*.go` — lowercase, no hyphens or underscores except for `_test.go`
- Package directories: Single lowercase word or abbreviated (`tcp`, `dnsprobe`, `httpprobe`, `tlsprobe`, `quicprobe`, `traceprobe`)
- Exception: `tlsprobe` uses `tls` abbreviation rather than full `tlsprobe`, but is named `tlsprobe` as a package directory (consistent with `dnsprobe`, `httpprobe`, `quicprobe`, `traceprobe`)

**Directories:**
- Package names match directory names (Go convention)
- `internal/` packages follow Go-standard `internal/` visibility restriction
- Probe subpackages use either `{protocol}probe/` or `{protocol}/` naming

**Go Naming Conventions Used:**
- Exported functions: PascalCase `Probe()`, `Classify()`, `Run()`, `BuildProfile()`, `Rank()`
- Unexported functions: camelCase `scanTarget()`, `probeDNS()`, `probeTLSWithRetries()`
- Constants: PascalCase with descriptive names: `FindingDNSInconsistent`, `ConfidenceHigh`, `QualityExcellent`
- Type aliases: PascalCase `type Layer string`, `type FindingType string`, `type Confidence string`
- Struct fields: PascalCase JSON-tagged fields
- Error values: `ErrTargetNameRequired`, `ErrTargetDomainRequired` (Err prefix + description)
- Test helpers: lowercase with `t.Helper()` convention (e.g., `startDNSServer`, `mustPort`, `splitServerAddr`)
- Documented exported functions with Go-style doc comments (single-line comments above most functions)

**Imports:**
- External packages aliased: `mdns "github.com/miekg/dns"` (to avoid collision with `net` or standard `dns` package)
- Internal packages imported by their module path: `"iscan/internal/probe/dnsprobe"`
- Standard library imports listed first, then external, then internal, separated by blank lines (Go convention)

## Where to Add New Code

**New Feature (e.g., a new probe type):**
1. Create a new probe subpackage: `internal/probe/{name}probe/{name}.go`
2. Follow the existing probe pattern: a single exported `Probe(ctx, ...) model.{Name}Observation` function
3. Add the observation struct to `internal/model/model.go`
4. Add a new `FindingType` and `Layer` constant in `internal/model/model.go`
5. Add finding generation logic in `internal/classifier/classifier.go`
6. Wire the probe call into `scanner.scanTarget()` in `internal/scanner/scanner.go`
7. Add a new flag in `cmd/iscan/main.go` if the probe needs opt-in
8. Add integration tests in `internal/probe/{name}probe/{name}_test.go`
9. Add classifier test cases in `internal/classifier/classifier_test.go`

**New Target/Domain:**
- Edit `internal/targets/targets.go`, `BuiltinTargets()` function
- Follow the existing struct pattern with Name, Domain, Scheme, Ports, Control, HTTPPath, CompareSNI, QUICPort

**New Resolver:**
- Edit `internal/targets/targets.go`, `BuiltinResolvers()` function
- Follow the existing pattern: Name, Server (optional, system resolver if Server empty), System flag

**New CLI Command or Flag:**
- Edit `cmd/iscan/main.go` — add flag in `scanCmd.Flags().<Type>Var()` block and wire into `ScanOptions` or pipeline logic

**New Profile Metric:**
- Add field to relevant `*Health` struct in `internal/profile/profile.go`
- Add logic in the corresponding `profile*()` private function
- Update `qualityTier` threshold or `StabilityScore` mapping if needed

**New Report Format:**
- Add a new exported function in `internal/report/report.go`
- Wire into `cmd/iscan/main.go` with a new flag if needed

**Test Location:**
- Always co-located: `internal/{package}/{package}_test.go`
- External test package pattern: `package xxx_test`
- Smoke/integration tests that need real network: use short-env guard or document as integration test (currently none guarded)

## Special Directories

**`.planning/codebase/`:**
- Purpose: Codebase analysis documents produced by `/gsd-map-codebase` and consumed by `/gsd-plan-phase` and `/gsd-execute-phase`
- Generated: Yes (by Claude Code / GSD commands)
- Committed: Yes

**`internal/`:**
- Purpose: Go-standard internal package visibility — restricts import to modules sharing the `iscan` root
- Generated: No
- Committed: Yes

---

*Structure analysis: 2026-04-26*
