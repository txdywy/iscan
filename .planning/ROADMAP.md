# iscan — Roadmap

## Overview

**Granularity:** Standard (8 phases)
**Total requirements mapped:** 22 functional (5 P0, 9 P1, 8 P2) + 10 non-functional (cross-cutting)

Eight sequenced phases that fix critical data-integrity bugs first, build a unified probe architecture second, then layer on features in dependency order. Each phase delivers a coherent, verifiable capability.

---

## Phase 1: Critical Bug Fixes

**Status:** planned
**Plans:** 5 plans
**Goal:** Eliminate all documented data-corruption, timeout-propagation, and cancellation-cascade bugs so the tool produces correct results and always terminates within bounds.
**Dependencies:** None (brownfield — existing codebase)
**Delivery criteria:**
  - Traceroute is correct under concurrent multi-target scans (no ICMP ID collisions, no hop misattribution).
  - DNS TCP fallback produces the same EDNS0 options as the initial UDP query.
  - No probe hangs beyond the parent context deadline — all context deadlines are propagated to per-probe timeouts.
  - One target's failure does not cancel remaining targets.
  - QUIC probe uses a single timeout value, not independent timeouts for handshake and idle.
  - DNS TCP retry does not inflate latency measurements.

### Tasks

- [ ] T-001: Fix ICMP identifier collision in traceroute — replace `os.Getpid() & 0xffff` with per-instance atomic counter; validate inner ICMP in TimeExceeded responses (P1). Effort: M
- [ ] T-002: Fix EDNS0 preservation on DNS TCP retry — replace `Msg.Copy()` with a fresh message that copies OPT pseudo-record explicitly (P2). Effort: S
- [ ] T-003: Fix per-hop timeout isolation — ensure each traceroute hop has an independent deadline, not a shared one that accumulates across hops (P3). Effort: S
- [ ] T-004: Propagate parent context deadline to every probe call — audit DNS, TCP, TLS, HTTP, QUIC, trace probes to ensure `ctx.Deadline()` feeds per-probe timeouts (P7, P15). Effort: M
- [ ] T-005: Fix errgroup cascading cancellation — return `nil` from errgroup for per-target errors so one failure does not cancel remaining targets (P16). Effort: S
- [ ] T-006: Fix QUIC double-timeout — replace independent handshake + idle timeouts with a single bounded deadline derived from parent context (P15). Effort: S
- [ ] T-007: Fix DNS TCP latency inflation — ensure TCP fallback timer starts before the connection attempt, not after UDP timeout (P8). Effort: S
- [ ] T-008: Fix shared message object across UDP/TCP retry — create a fresh `dns.Msg` for each retry attempt instead of reusing the same pointer (PITFALLS finding). Effort: S


### Plans

- [ ] 02-01-PLAN.md -- Probe Interface & Unified Model (Wave 1): Define Probe interface, ProbeFunc adapter, Registry map, ProbeResult type-erased container, replace TargetResult named slices with Results []ProbeResult
- [ ] 02-02-PLAN.md -- Middleware Decorators (Wave 2): Create composable middleware (Timeout, Retry, Logging, Chain) in internal/probe/middleware/
- [ ] 02-03-PLAN.md -- Probe Adapters & Registration (Wave 2): Create adapter.go in all 6 probe packages with Opts + Adapter + init() registration via probe.Registry
- [ ] 02-04-PLAN.md -- Scanner Declarative Execution (Wave 3): Refactor scanner to build []Probe from Registry, apply middleware, iterate declaratively, remove old helpers
- [ ] 02-05-PLAN.md -- Consumer Migration (Wave 4): Migrate classifier/profile/report to collectObservations[T] helpers, update all tests, verify go test ./... passes

### Alignment

- F-01: Traceroute ICMP ID collision fix (P0)
- F-02: DNS TCP fallback EDNS0 preservation (P0)
- F-03: All probes respect parent context deadline (P0)
- F-04: errgroup per-target cancellation only (P0)
- N-07: Bounded completion time (cross-cutting)

---

## Phase 2: Probe Interface Unification

**Status:** planned
**Plans:** 5 plans
**Goal:** All probes implement a single `Probe` interface with `ProbeResult` type-erased containers, middleware decorators for retry/timeout/logging, and `init()`-based registration. The scanner becomes a phase-driven executor that no longer needs per-probe callsites.
**Dependencies:** Phase 1 (bug fixes stable before refactoring)
**Delivery criteria:**
  - Each probe package exports a `Probe` implementation registered via `init()`.
  - `ProbeResult` is a type-erased container — adding a new protocol does not require adding a new slice field to `TargetResult`.
  - Middleware wrappers for retry, timeout, and logging exist and are composable.
  - Scanner drives probes declaratively (list of phases with ordered probe IDs) instead of imperative per-probe calls.
  - Old probe functions remain as package-level helpers for the duration of migration, then are removed.
  - All existing tests pass with zero behavior change.

### Tasks

- [ ] T-009: Define `Probe` interface and `ProbeResult` type-erased container in `internal/probe/probe.go`. Effort: M
- [ ] T-010: Build middleware wrappers (retry, timeout, logging) following decorator pattern. Effort: M
- [ ] T-011: Implement adapter struct for each existing probe (DNS, TCP, TLS, HTTP, QUIC, trace) — wraps old functions into `Probe.Run()`, registers via `init()`. Effort: L
- [ ] T-012: Refactor scanner to phase-driven execution — accept a `[]Phase` (or `[]Probe`) list, iterate declaratively, remove per-probe callsites. Effort: M
- [ ] T-013: Migrate all callers (classifier, profile, report) to consume `ProbeResult` slices instead of named fields. Effort: M
- [ ] T-014: Remove old standalone probe function signatures and flattened fields from `TargetResult`. Effort: S
- [ ] T-015: Update MODEL.md and types to reflect unified result model. Effort: S


### Plans

- [ ] 02-01-PLAN.md -- Probe Interface & Unified Model (Wave 1): Define Probe interface, ProbeFunc adapter, Registry map, ProbeResult type-erased container, replace TargetResult named slices with Results []ProbeResult
- [ ] 02-02-PLAN.md -- Middleware Decorators (Wave 2): Create composable middleware (Timeout, Retry, Logging, Chain) in internal/probe/middleware/
- [ ] 02-03-PLAN.md -- Probe Adapters & Registration (Wave 2): Create adapter.go in all 6 probe packages with Opts + Adapter + init() registration via probe.Registry
- [ ] 02-04-PLAN.md -- Scanner Declarative Execution (Wave 3): Refactor scanner to build []Probe from Registry, apply middleware, iterate declaratively, remove old helpers
- [ ] 02-05-PLAN.md -- Consumer Migration (Wave 4): Migrate classifier/profile/report to collectObservations[T] helpers, update all tests, verify go test ./... passes

### Alignment

- F-06: Unified `Probe` interface with `ProbeResult` type-erased container (P1)
- F-07: Middleware wrappers for retry, timeout, logging (P1)
- F-08: `init()`-based probe registration (P1)
- N-03: Sequential probes per target (scanner refactor enforces ordering)
- N-07: Bounded completion time (middleware enforces context deadlines)

---

## Phase 3: Missing Table Stakes

**Status:** planned
**Plans:** 3 plans
**Goal:** Users can run ICMP ping as an independent reachability check, use custom target sets from a JSON file, and scan IPv6 targets across all applicable probes.
**Dependencies:** Phase 2 (new probes use unified interface; scanner declarative)
**Delivery criteria:**
  - `iscan ping <target>` runs an ICMP echo probe and prints RTT (works without root on systems with ping capabilities, uses privileged ICMP socket otherwise).
  - `iscan scan --target-set path/to/targets.json` loads custom targets from JSON and runs the full probe suite.
  - All probes (DNS, TCP, TLS, HTTP, QUIC, trace) accept IPv6 addresses and produce correct results.
  - Traceroute supports ICMPv6 for IPv6 targets.
  - No regression on IPv4-only scans.

### Tasks

- [ ] T-016: Implement ICMP Ping probe — create `internal/probe/icmpping/` with raw ICMP socket (or synthetic ping on systems that support it), register as `ping` probe. Effort: M
- [ ] T-017: Add `--target-set` flag and target source abstraction — create `TargetSource` interface with built-in + JSON file implementations. Effort: M
- [ ] T-018: Add IPv6 support to DNS probe — IPv6 address handling, AAAA vs A queries, EDNS0 over IPv6. Effort: M
- [ ] T-019: Add IPv6 support to TCP/TLS probes — `net.Dialer` with `tcp6` network, proper address resolution. Effort: M
- [ ] T-020: Add IPv6 support to traceroute — implement ICMPv6 variant for IPv6 targets (different protocol number, different header structure). Effort: M
- [ ] T-021: Add IPv6 support to QUIC probe — verify quic-go handles IPv6 correctly, add dual-stack dialing. Effort: S
- [ ] T-022: Update CLI flag validation for IPv6 addresses — ensure `--target` and `--target-set` accept raw IPv6 addresses. Effort: S


### Plans

- [x] 03-01-PLAN.md -- ICMP Ping Probe (Wave 1): Model types (LayerPing, PingObservation), probe + adapter in internal/probe/icmpping/, ping subcommand + --icmp-ping flag, scanner wiring
- [x] 03-02-PLAN.md -- Custom Target Sets (Wave 2): TargetSource interface, BuiltinSource + FileSource, ScanOptions.TargetSet, --target-set flag, scanner integration
- [ ] 03-03-PLAN.md -- IPv6 Support (Wave 3): Target.AddressFamily, IPv6 resolvers, DNS AAAA queries, traceroute ICMPv6, adapter dual-stack wiring, CLI IPv6 validation

### Alignment

- F-10: ICMP Ping probe (P1)
- F-11: Custom target sets via `--target-set` (P1)
- F-12: IPv6 support for traceroute, DNS, TCP/TLS (P1)
- N-02: Cross-platform (ICMP permissions vary by OS)

---

## Phase 4: DNS Enhancements

**Status:** planned
**Plans:** 5 plans
**Goal:** DNS probing produces richer diagnostic signal with RCODE-specific findings, encrypted transport options (DoH, DoT), system resolver RCODE extraction, and per-resolver rate limiting.
**Dependencies:** Phase 2 (new DNS transports use unified interface); independent of Phase 3
**Delivery criteria:**
  - NXDOMAIN, SERVFAIL, REFUSED RCODEs each produce distinct findings with appropriate confidence.
  - DoH (`https://` resolver URLs) and DoT (`tls://` resolver URLs) work via `miekg/dns` transport selector — no new dependencies.
  - System resolver RCODE responses are extracted and reported for all configured resolvers.
  - Per-resolver rate limiting (20 queries/second default) prevents accidental DoS.
  - Transparent DNS proxy detection via whoami.akamai.net or equivalent.

### Tasks

- [ ] T-023: Refactor DNS RCODE handling — replace blanket "DNS failure" with per-RCODE findings (NXDOMAIN → clear "domain does not exist", SERVFAIL → "resolver failure", REFUSED → "query refused"). Effort: M
- [ ] T-024: Add DoH transport — implement `miekg/dns.Client` with `Net: "https"`, update resolver config parsing. Effort: M
- [ ] T-025: Add DoT transport — implement `miekg/dns.Client` with `Net: "tcp-tls"`, update resolver config parsing. Effort: M
- [ ] T-026: Extract system resolver RCODE responses — capture `dns.Msg.Rcode` from every resolver response, expose in findings. Effort: M
- [ ] T-027: Implement per-resolver rate limiter — token bucket per resolver (default 20 qps), configurable via CLI or config. Effort: M
- [ ] T-028: Detect transparent DNS proxies — query whoami.akamai.net (or similar) and compare resolved address against configured resolver address. Effort: M


### Plans

- [ ] 02-01-PLAN.md -- Probe Interface & Unified Model (Wave 1): Define Probe interface, ProbeFunc adapter, Registry map, ProbeResult type-erased container, replace TargetResult named slices with Results []ProbeResult
- [ ] 02-02-PLAN.md -- Middleware Decorators (Wave 2): Create composable middleware (Timeout, Retry, Logging, Chain) in internal/probe/middleware/
- [ ] 02-03-PLAN.md -- Probe Adapters & Registration (Wave 2): Create adapter.go in all 6 probe packages with Opts + Adapter + init() registration via probe.Registry
- [ ] 02-04-PLAN.md -- Scanner Declarative Execution (Wave 3): Refactor scanner to build []Probe from Registry, apply middleware, iterate declaratively, remove old helpers
- [ ] 02-05-PLAN.md -- Consumer Migration (Wave 4): Migrate classifier/profile/report to collectObservations[T] helpers, update all tests, verify go test ./... passes

### Alignment

- F-05: DNS RCODEs surfaced separately — NXDOMAIN, SERVFAIL, REFUSED (P0)
- F-13: DoH and DoT probe support via miekg/dns (P1)
- N-01: No new external dependencies (miekg/dns already present)
- N-10: EDNS0 enabled on all DNS queries (ensured by Phase 1 fix)

---

## Phase 5: Classification and Profile Improvements

**Status:** planned
**Plans:** 5 plans
**Goal:** Classification produces evidence-weighted, composable findings. Profile computation separates control targets from diagnostic targets, enabling accurate cross-target correlation.
**Dependencies:** Phase 3 (IPv6 findings) and Phase 4 (RCODE-specific findings produce richer input for classifiers)
**Delivery criteria:**
  - `Detector` interface exists with registered implementations per finding type — heuristics are decoupled from the monolithic `Classify()` function.
  - Dynamic confidence scoring replaces static LOW/MEDIUM/HIGH — confidence is proportional to evidence count, corroboration, and cross-target agreement.
  - Profile computes separate health dimensions for control targets (network baseline) and diagnostic targets (censorship signals).
  - Cross-target correlation pass compares control vs diagnostic findings and flags divergences.
  - TLS/QUIC divergence detection surfaces UDP blocking (QUIC fails but TCP/TLS succeeds).

### Tasks

- [ ] T-029: Define `Detector` interface and registry — each detector implements `Detect(results []ProbeResult) []Finding`, registered via `init()`. Effort: M
- [ ] T-030: Refactor `classifier.Classify()` into individual detectors — extract inline heuristics into registered detectors, one per finding type. Effort: L
- [ ] T-031: Implement dynamic confidence scoring — base confidence per evidence item, modifiers for corroboration (same finding across probes), cross-target agreement, and evidence count. Effort: L
- [ ] T-032: Separate control vs diagnostic targets in profile — tag targets as control or diagnostic, compute separate profile dimensions for each group. Effort: M
- [ ] T-033: Build cross-target correlation pass — compare control-target findings against diagnostic-target findings, generate divergence findings. Effort: M
- [ ] T-034: Add TLS/QUIC divergence detector — if TLS succeeds but QUIC fails (or vice versa), generate "UDP blocked" or "QUIC filtered" finding. Effort: M


### Plans

- [ ] 02-01-PLAN.md -- Probe Interface & Unified Model (Wave 1): Define Probe interface, ProbeFunc adapter, Registry map, ProbeResult type-erased container, replace TargetResult named slices with Results []ProbeResult
- [ ] 02-02-PLAN.md -- Middleware Decorators (Wave 2): Create composable middleware (Timeout, Retry, Logging, Chain) in internal/probe/middleware/
- [ ] 02-03-PLAN.md -- Probe Adapters & Registration (Wave 2): Create adapter.go in all 6 probe packages with Opts + Adapter + init() registration via probe.Registry
- [ ] 02-04-PLAN.md -- Scanner Declarative Execution (Wave 3): Refactor scanner to build []Probe from Registry, apply middleware, iterate declaratively, remove old helpers
- [ ] 02-05-PLAN.md -- Consumer Migration (Wave 4): Migrate classifier/profile/report to collectObservations[T] helpers, update all tests, verify go test ./... passes

### Alignment

- F-09: Control vs diagnostic target separation in profile (P1)
- F-15: Dynamic confidence scoring — evidence-weighted (P2)
- F-16: `Detector` interface with composable heuristics (P2)
- F-17: Cross-target correlation pass (P2)
- N-03: Sequential probes per target (ordering ensures TLS-before-QUIC analysis)

---

## Phase 6: Report Format Extensibility

**Status:** planned
**Plans:** 5 plans
**Goal:** Reports use a `Formatter` interface with registry so new output formats can be added without touching report internals. HTML self-contained report and CSV/YAML exports ship alongside existing JSON/tabwriter output. A `--format` flag replaces `--json` / `--summary`.
**Dependencies:** Phase 2 (formatter interface mirrors probe interface pattern); can proceed in parallel with Phases 4-5
**Delivery criteria:**
  - `Formatter` interface exists with `Format(Result) ([]byte, error)` signature.
  - HTML self-contained report renders a color-coded protocol status table with probe-level detail.
  - CSV export produces structured rows per target-finding pair.
  - YAML export produces structured document matching JSON schema.
  - `--format` CLI flag accepts `terminal`, `json`, `html`, `csv`, `yaml` — deprecates `--json` / `--summary` with backward compat.
  - No regressions on existing JSON or terminal output.

### Tasks

- [ ] T-035: Define `Formatter` interface and registry in `internal/report/`. Effort: S
- [ ] T-036: Refactor existing JSON and terminal output into registered formatters. Effort: M
- [ ] T-037: Build HTML formatter with Go template — self-contained file (inline CSS), color-coded protocol status table. Effort: M
- [ ] T-038: Build CSV formatter — rows per target-finding pair with headers. Effort: S
- [ ] T-039: Build YAML formatter via `gopkg.in/yaml.v3` or JSON-based YAML output. Effort: S
- [ ] T-040: Add `--format` CLI flag, deprecate `--json`/`--summary`, maintain backward compatibility. Effort: M


### Plans

- [ ] 02-01-PLAN.md -- Probe Interface & Unified Model (Wave 1): Define Probe interface, ProbeFunc adapter, Registry map, ProbeResult type-erased container, replace TargetResult named slices with Results []ProbeResult
- [ ] 02-02-PLAN.md -- Middleware Decorators (Wave 2): Create composable middleware (Timeout, Retry, Logging, Chain) in internal/probe/middleware/
- [ ] 02-03-PLAN.md -- Probe Adapters & Registration (Wave 2): Create adapter.go in all 6 probe packages with Opts + Adapter + init() registration via probe.Registry
- [ ] 02-04-PLAN.md -- Scanner Declarative Execution (Wave 3): Refactor scanner to build []Probe from Registry, apply middleware, iterate declaratively, remove old helpers
- [ ] 02-05-PLAN.md -- Consumer Migration (Wave 4): Migrate classifier/profile/report to collectObservations[T] helpers, update all tests, verify go test ./... passes

### Alignment

- F-14: Self-contained HTML report with color-coded protocol status table (P1)
- F-18: CSV and YAML report export (P2)
- N-05: JSON always produced; HTML/CSV/YAML as `--format` flag
- N-01: No new deps for core (yaml.v3 is the only addition, optional format)

---

## Phase 7: Advanced Probes

**Status:** planned
**Plans:** 5 plans
**Goal:** Users can probe WebSocket endpoints for WS/WSS connectivity and test SOCKS5/HTTP CONNECT proxy reachability — addressing niche but differentiating diagnostic scenarios that no competitor CLI covers.
**Dependencies:** Phase 2 (new probes register via unified interface)
**Delivery criteria:**
  - `iscan scan --probe ws,wss://example.com/ws` performs WebSocket handshake and reports success or failure details.
  - `iscan scan --probe socks5://proxy:1080 example.com` tests SOCKS5 proxy connectivity.
  - `iscan scan --probe http-connect://proxy:3128 example.com` tests HTTP CONNECT proxy connectivity.
  - Findings include handshake duration, TLS version (for WSS), and proxy error details.

### Tasks

- [ ] T-041: Implement WebSocket probe — `github.com/coder/websocket` for WS/WSS handshake, reports upgrade status and timing. Effort: M
- [ ] T-042: Implement SOCKS5 probe — `golang.org/x/net/proxy` for SOCKS5 dial, reports connectivity and latency. Effort: M
- [ ] T-043: Implement HTTP CONNECT proxy probe — manual HTTP CONNECT handshake via `net/http`, reports tunnel establishment status. Effort: M
- [ ] T-044: Register all three probes via `init()` and add probe IDs to CLI help text. Effort: S


### Plans

- [ ] 02-01-PLAN.md -- Probe Interface & Unified Model (Wave 1): Define Probe interface, ProbeFunc adapter, Registry map, ProbeResult type-erased container, replace TargetResult named slices with Results []ProbeResult
- [ ] 02-02-PLAN.md -- Middleware Decorators (Wave 2): Create composable middleware (Timeout, Retry, Logging, Chain) in internal/probe/middleware/
- [ ] 02-03-PLAN.md -- Probe Adapters & Registration (Wave 2): Create adapter.go in all 6 probe packages with Opts + Adapter + init() registration via probe.Registry
- [ ] 02-04-PLAN.md -- Scanner Declarative Execution (Wave 3): Refactor scanner to build []Probe from Registry, apply middleware, iterate declaratively, remove old helpers
- [ ] 02-05-PLAN.md -- Consumer Migration (Wave 4): Migrate classifier/profile/report to collectObservations[T] helpers, update all tests, verify go test ./... passes

### Alignment

- F-19: WebSocket (WS/WSS) handshake probe (P2)
- F-20: SOCKS/HTTP proxy protocol probe (P2)
- N-01: No new deps for core (WebSocket adds `github.com/coder/websocket` — acknowledged trade-off)
- N-08: Dependency budget <= 10 (WebSocket dep adds one; monitor count)

---

## Phase 8: Analysis and Comparison

**Status:** planned
**Plans:** 5 plans
**Goal:** Users can compare two scan results to identify changes over time and track historical trends with stored scan snapshots.
**Dependencies:** Phase 6 (stable report output for comparison rendering); Phase 5 (consistent findings for diff)
**Delivery criteria:**
  - `iscan diff <result-a.json> <result-b.json>` produces a structured diff of findings, categorized as new, resolved, or changed.
  - `iscan diff --report html` produces an HTML diff report with visual indicators for regressions and improvements.
  - `iscan history --store` saves scan results to a local directory with timestamps.
  - `iscan history --trend <days>` displays finding trends over time.
  - All comparison logic works against the `ProbeResult` model — no new serialization work needed.

### Tasks

- [ ] T-045: Build scan comparison/diff engine — compare two `Result` structs, categorize finding diffs (new/resolved/changed). Effort: L
- [ ] T-046: Add CLI command `iscan diff` — accept two JSON result files, emit terminal diff output. Effort: M
- [ ] T-047: Build HTML diff formatter — render diff results with visual indicators (green for resolved, red for new, yellow for changed). Effort: M
- [ ] T-048: Implement historical trend storage — save scan results to `~/.iscan/history/` with ISO-8601 timestamps. Effort: M
- [ ] T-049: Build trend analysis — load historical results, compute finding frequency over time, display as text table. Effort: M
- [ ] T-050: Add `iscan history` CLI command with `--store` and `--trend` subcommands. Effort: M


### Plans

- [ ] 02-01-PLAN.md -- Probe Interface & Unified Model (Wave 1): Define Probe interface, ProbeFunc adapter, Registry map, ProbeResult type-erased container, replace TargetResult named slices with Results []ProbeResult
- [ ] 02-02-PLAN.md -- Middleware Decorators (Wave 2): Create composable middleware (Timeout, Retry, Logging, Chain) in internal/probe/middleware/
- [ ] 02-03-PLAN.md -- Probe Adapters & Registration (Wave 2): Create adapter.go in all 6 probe packages with Opts + Adapter + init() registration via probe.Registry
- [ ] 02-04-PLAN.md -- Scanner Declarative Execution (Wave 3): Refactor scanner to build []Probe from Registry, apply middleware, iterate declaratively, remove old helpers
- [ ] 02-05-PLAN.md -- Consumer Migration (Wave 4): Migrate classifier/profile/report to collectObservations[T] helpers, update all tests, verify go test ./... passes

### Alignment

- F-21: Scan comparison/diff mode (P2)
- F-22: Long-term trend tracking (P2)
- N-02: Cross-platform (file-based storage works on macOS/Linux)

---

## Dependency Graph

```
Phase 1 (Bug Fixes)              — foundation, no deps
  |
  v
Phase 2 (Probe Interface)        — architectural foundation
  |         \
  v          v
Phase 3 (Table Stakes)    Phase 4 (DNS Enhancements)
  |                        |
  |                        v
  +-----> Phase 5 (Classification/Profile)
                |
                v
          Phase 6 (Report Formats)    Phase 7 (Advanced Probes) — independent of Phases 3-6
                |
                v
          Phase 8 (Analysis/Comparison)
```

Phases 3 and 4 can proceed in parallel after Phase 2. Phase 6 can proceed in parallel with Phases 4-5. Phase 7 is independent of Phases 3-6 and can be scheduled anytime after Phase 2.

---

## Non-Functional Requirement Coverage

| NFR ID | Description | Primary Phase(s) |
|--------|-------------|------------------|
| N-01 | No new deps for core probe functionality | Phase 4 (DoH/DoT via miekg/dns), Phase 7 (WebSocket adds dep — noted trade-off) |
| N-02 | Cross-platform (macOS + Linux) | All phases (ICMP handling in Phase 1, Phase 3) |
| N-03 | Sequential probes per target | Phase 2 (scanner refactor enforces ordering) |
| N-04 | Graceful SIGINT/SIGTERM shutdown | Already implemented |
| N-05 | JSON always; --format flag | Phase 6 |
| N-06 | InsecureSkipVerify for TLS/QUIC | Already implemented |
| N-07 | Bounded completion time | Phase 1 (context propagation), Phase 2 (middleware) |
| N-08 | <= 10 direct dependencies | Phase 7 (monitor when adding coder/websocket) |
| N-09 | Root for traceroute only | Already handled |
| N-10 | EDNS0 enabled by default | Phase 1 (TCP retry fix restores EDNS0 on fallback) |

---

## Effort Summary

| Phase | Effort | Key Risk |
|-------|--------|----------|
| 1 — Bug Fixes | Low-Medium | Traceroute ICMP fix may need platform-specific testing |
| 2 — Probe Interface | Medium | Migration touches all probe packages + scanner + consumers |
| 3 — Table Stakes | Medium | IPv6 cross-probe scope; ICMPv6 differs from ICMPv4 |
| 4 — DNS Enhancements | Medium | DoH/DoT integration testing with real resolvers |
| 5 — Classification | Medium-High | Dynamic confidence weights need empirical validation |
| 6 — Report Formats | Low-Medium | HTML template design effort |
| 7 — Advanced Probes | Medium | WebSocket adds a new dependency |
| 8 — Analysis | Medium-High | Diff logic complexity; trend storage design |

---

*Roadmap generated: 2026-04-26*
*Based on research-informed requirements (P0-P2) and current codebase analysis*
