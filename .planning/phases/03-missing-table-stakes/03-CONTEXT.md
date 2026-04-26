# Phase 3: Missing Table Stakes - Context

**Gathered:** 2026-04-26
**Status:** Ready for planning

<domain>
## Phase Boundary

Add three missing capabilities: ICMP Ping as an independent probe, custom target set loading from JSON, and IPv6 support across all existing probes. This fills user-facing gaps before moving to deeper diagnostic enhancements.

**Requirements addressed:** F-10 (ICMP Ping), F-11 (custom target sets), F-12 (IPv6 support)

</domain>

<decisions>
## Implementation Decisions

### ICMP Ping Probe (F-10)
- **D-01:** Use `golang.org/x/net/icmp` (same library as traceroute) for ICMP echo. Create `internal/probe/icmpping/` package. Register via init() as `model.LayerPing` probe. Gracefully handle permission errors with a clear warning.
- **D-02:** Add `LayerPing Layer = "ping"` constant to model. Add `PingObservation` struct with `Target`, `RTT`, `TTL`, `Success`, `Error` fields (similar to TraceHop but simpler — single echo, no path).
- **D-03:** `iscan ping <target>` as a standalone CLI subcommand (not a flag on `scan`). Outputs RTT + TTL + status line. Also include ping in the scan suite when `--icmp-ping` flag is enabled, adding it to the probe list before the trace probe.

### Custom Target Sets (F-11)
- **D-04:** Add `Target` field for the JSON file path in `ScanOptions`. JSON format is a simple array of `model.Target` structs matching the existing type. `--target-set path/to/targets.json` loads and validates targets via `model.Target.Validate()`.
- **D-05:** Create `TargetSource` interface in `internal/targets/` with `Load() ([]model.Target, error)` and two implementations: `BuiltinSource` (returns existing builtin targets) and `FileSource` (reads JSON from file). Scanner selects source based on options.

### IPv6 Support (F-12)
- **D-06:** Dual-stack approach: probe both IPv4 and IPv6 addresses when available. For DNS, query AAAA in addition to A. For TCP/TLS, dial both address families. For traceroute, use ICMPv6 for IPv6 targets (golang.org/x/net/icmp supports ipv6.ICMPType). For QUIC, verify quic-go handles IPv6 natively.
- **D-07:** Add IPv6 resolver addresses: `2606:4700:4700::1111` (Cloudflare), `2001:4860:4860::8888` (Google), `2620:fe::fe` (Quad9) as additional resolvers. DNS probe queries AAAA records over IPv6 resolvers when configured.
- **D-08:** Target struct gains an optional `AddressFamily` field (`"ipv4"`, `"ipv6"`, or empty for both). Builtin targets remain dual-stack (empty). Custom targets can specify family.

### Claude's Discretion
- Exact TTL default for ping (standard 64/128 or configurable)
- Ping timeout derivation and retry strategy
- IPv6 resolver port assignment (53 by convention, same as IPv4)
- JSON target file validation details (error messages, partial load)
- Whether ping is added to scanTarget's probe list or handled separately
- CLI flag names (`--icmp-ping` vs `--ping` vs adding to probe list automatically)

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase 2 interface patterns (reuse for new Ping probe)
- `internal/probe/probe.go` — Probe interface, ProbeFunc, Registry
- `internal/model/model.go` — ProbeResult, Target, Layer constants
- `internal/probe/traceprobe/trace.go` — ICMP socket pattern (reference for Ping)
- `internal/scanner/scanner.go` — buildProbes(), scanTarget() patterns
- `internal/targets/targets.go` — Current builtin target list, resolver list

### Requirements
- `.planning/REQUIREMENTS.md` §34-38 — F-10, F-11, F-12 requirement definitions
- `.planning/ROADMAP.md` §57-82 — Phase 3 tasks and delivery criteria

### Architecture
- `.planning/codebase/ARCHITECTURE.md` — Pipeline structure, probe-scanner relationship
- `.planning/codebase/CONVENTIONS.md` — Code patterns, error handling
</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `golang.org/x/net/icmp` — Already used by traceroute, can create raw ICMP echo sockets and parse replies
- `Probe` interface + Registry — Phase 2 pattern, ping probe registers as LayerPing
- `middleware.Chain`, `middleware.Timeout`, `middleware.Retry` — Reusable for ping probe
- `model.Target` — Already has Domain, Ports, etc.; AddressFamily can be added
- `targets.BuiltinTargets()` / `targets.BuiltinResolvers()` — Extend with IPv6 resolvers

### Established Patterns
- **Probe interface with adapter:** Every probe follows Opts + Adapter + init() from Phase 2
- **JSON serialization:** Existing model types use json tags; target-set JSON follows same pattern
- **Graceful permission degradation:** Traceroute warns on ICMP permission errors; ping follows same pattern

### Integration Points
- `internal/scanner/scanner.go:buildProbes()` — Add LayerPing registration when `--icmp-ping` is set
- `cmd/iscan/main.go` — Add `ping` subcommand and `--icmp-ping` flag on scan
- `internal/targets/targets.go` — Add TargetSource interface, FileSource implementation, IPv6 resolvers
- `internal/model/model.go` — Add LayerPing, PingObservation, Target.AddressFamily
- `internal/probe/traceprobe/trace.go` — Add ICMPv6 path for IPv6 targets
</code_context>

<specifics>
## Specific Ideas

- PingCLI subcommand: `iscan ping example.com` outputs `PING example.com (93.184.216.34): rtt=12.3ms ttl=57`
- Target-set JSON format: `[{"name":"custom","domain":"example.org","scheme":"https","ports":[443]}]`
- IPv6 resolver addresses: `[2001:4860:4860::8888]:53` for Google DNS over IPv6
- Traceroute ICMPv6 uses `ipv6.ICMPTypeTimeExceeded` instead of `ipv4.ICMPTypeTimeExceeded`
- `net.Resolver` with `PreferGo: true` for dual-stack DNS resolution in probe context

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope.

</deferred>

---

*Phase: 03-Missing Table Stakes*
*Context gathered: 2026-04-26 via --auto*
