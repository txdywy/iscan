# Phase 5: Classification and Profile Improvements - Research

**Researched:** 2026-04-27
**Domain:** Detector-driven classification, confidence calibration, control-baseline profiling, and cross-target correlation for a Go CLI network diagnostics pipeline. [VERIFIED: codebase read]
**Confidence:** HIGH

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

### Detector Architecture
- **D-01:** Replace the monolithic `classifier.Classify()` body with a detector registry that runs a sequence of small detector functions against each `model.TargetResult`. Each detector returns zero or more `model.Finding` values and may inspect any probe observations already attached to the result.
- **D-02:** Keep detector registration simple and local to the classifier package. A package-level registry populated via `init()` is acceptable if it mirrors the probe registry pattern and keeps the call site stable. The classifier entrypoint should remain `Classify(result model.TargetResult) []model.Finding` so the scanner and report pipeline do not need to change.
- **D-03:** Detectors should own one concern each: DNS inconsistency / RCODEs, TCP failure aggregation, TLS handshake failure, HTTP failure, QUIC failure, path quality, transparent DNS proxy signals, and the new cross-target correlation and divergence heuristics.

### Confidence Scoring
- **D-04:** Confidence should be derived from evidence quality and corroboration, not hardcoded uniformly by finding type. Use a small helper in classifier/profile code to map stronger evidence to higher confidence when multiple resolvers, multiple targets, or cross-layer agreement support the same claim.
- **D-05:** Preserve the current `model.Confidence*` enum and emit those existing values; do not introduce a new scoring type. Dynamic confidence should still collapse to the existing confidence levels so rendering and report formatting remain unchanged.
- **D-06:** Prefer higher confidence only when corroboration is real and specific. For example, a single failed probe stays low confidence, while multiple consistent failures across control vs diagnostic targets, or TLS/QUIC divergence that aligns with the same target family, can move the finding to medium or high.

### Control vs Diagnostic Targets
- **D-07:** Use `model.Target.Control` as the source of truth for whether a target contributes to the control baseline. Control targets are excluded from diagnostic aggregation but remain visible in the raw scan output and can themselves produce findings.
- **D-08:** Profile functions should split target-derived evidence into control and diagnostic groups before computing health summaries. The profile baseline should prefer control-target success rates when available; diagnostic targets should be evaluated against that baseline rather than averaged into it.
- **D-09:** If no control targets are present, profile computation falls back to the existing all-target aggregation behavior rather than failing or inventing synthetic baselines.

### Cross-Target Correlation
- **D-10:** Add a dedicated correlation pass after per-target classification that compares findings across targets and layers. This pass should look for consistent divergence patterns, especially cases where control targets succeed and diagnostic targets fail on the same protocol.
- **D-11:** Cross-target correlation belongs in profile computation or a profile-adjacent helper, not inside the low-level per-target classifier loop. The classifier should still emit findings per target first; correlation then enriches the report with higher-level conclusions.

### TLS/QUIC Divergence Detection
- **D-12:** Add a detector that compares TLS and QUIC outcomes for the same target family. When TLS succeeds but QUIC consistently fails for the same host pattern, emit a divergence finding that suggests UDP/QUIC filtering or protocol-specific interference.
- **D-13:** Keep the divergence detector conservative. It should require at least one successful TLS observation and one failed QUIC observation for a comparable target, and should not fire on missing QUIC support, permission errors, or obviously unrelated failures.

### Claude's Discretion
- Exact detector type shape and registry mechanics
- Whether correlation emits new findings or only augments profile health fields
- The final confidence thresholds for corroborated evidence
- Whether control/diagnostic separation is implemented in profile only or shared with classifier helpers

### Deferred Ideas (OUT OF SCOPE)
- Reworking report rendering to expose the new correlation logic directly in the terminal layout.
- Introducing a new type hierarchy for findings beyond the existing `model.Finding` enum.
- Adding transport-specific profile sub-scores beyond TLS/QUIC divergence.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| F-09 | Control vs diagnostic target separation in profile computation — profile excludes control targets. [VERIFIED: REQUIREMENTS.md] | Use `model.Target.Control` as the only baseline flag; partition `report.Targets` before layer scoring; keep fallback to all-target aggregation when no control targets exist. [VERIFIED: model.go, profile.go, targets.go, 05-CONTEXT.md] |
| F-15 | Dynamic confidence scoring — evidence-weighted, not static per finding type. [VERIFIED: REQUIREMENTS.md] | Add one shared confidence helper used by per-target detectors and report-level correlation so promotion to MEDIUM/HIGH comes from corroboration counts, baseline success, and cross-layer agreement rather than detector-local constants. [VERIFIED: classifier.go, 05-CONTEXT.md] |
| F-16 | `Detector` interface with composable registered heuristics — decoupled from classifier. [VERIFIED: REQUIREMENTS.md] | Keep `Classify(result model.TargetResult) []model.Finding` stable, but move monolithic logic behind a local classifier registry fed with normalized target evidence. [VERIFIED: classifier.go, scanner.go, 05-CONTEXT.md] |
| F-17 | Cross-target correlation pass — compares control vs diagnostic findings. [VERIFIED: REQUIREMENTS.md] | Add a second pass after `scanner.Run` has all target results, append report-level findings there, and keep terminal-layout changes deferred. [VERIFIED: scanner.go, report.go, cmd/iscan/main.go, 05-CONTEXT.md] |
</phase_requirements>

## Summary

Phase 5 should stay additive to the current Phase 2 architecture: per-target probes already produce `[]model.ProbeResult`, `scanner.Run` already classifies each target with `classifier.Classify`, and `profile.BuildProfile` already performs report-wide aggregation. The planner should preserve those seams and insert two focused changes: a detector registry inside `internal/classifier`, and a report-level correlation/baseline pass alongside `internal/profile`. [VERIFIED: scanner.go, classifier.go, profile.go]

The biggest architectural trap is that Phase 2’s type-erased result model already leaks into consumers unevenly: `classifier.collectAllDNSObservations` explicitly handles `[]model.DNSObservation`, but `profile.profileDNS` and `report.hasSuccess` still assume single `DNSObservation` payloads. Phase 5 planning should normalize observation access once and reuse that logic, otherwise detector extraction and baseline scoring will silently miss multi-resolver DNS evidence or misreport DNS layer status. [VERIFIED: classifier.go, profile.go, report.go]

**Primary recommendation:** Keep per-target classification in `internal/classifier`, add a normalized evidence view plus local detector registry there, then add a separate report-level `control-vs-diagnostic` correlation pass that appends report findings before `BuildProfile` and `recommend.Rank` consume the scan. [VERIFIED: scanner.go, classifier.go, profile.go, recommend.go, cmd/iscan/main.go]

## Project Constraints (from CLAUDE.md)

- No project-specific `/Users/yiwei/iscan/CLAUDE.md` file exists, so there are no additional repo-local constraints to override the phase context. [VERIFIED: file lookup]

## Current Architecture Facts Relevant to the Phase

- `classifier.Classify(result model.TargetResult) []model.Finding` is already the only public per-target classification entrypoint, and `scanner.Run` calls it once per target inside the target goroutine. [VERIFIED: classifier.go, scanner.go]
- The current classifier is monolithic but already organized by normalized observation groups: DNS, TCP, TLS, HTTP, QUIC, and trace are collected at the top of `Classify()` and then fed into inline heuristics. [VERIFIED: classifier.go]
- `profile.BuildProfile(report)` is a pure report-wide aggregation step returning `profile.Profile`; it does not mutate the report or emit findings. [VERIFIED: profile.go]
- `cmd/iscan/main.go` only builds profile/recommendation when `--analyze` is set, so any correlation finding that must exist in ordinary scan JSON needs to be added before CLI analysis, not only inside `BuildProfile`. [VERIFIED: cmd/iscan/main.go]
- `model.Target.Control` already exists, and the built-in target set already mixes control and diagnostic targets, including one control target with `QUICPort: 0` and one diagnostic target with `CompareSNI`. Those are ready-made fixtures for baseline and divergence tests. [VERIFIED: model.go, targets.go]
- `profile.profileDNS` currently uses `collectObservations[model.DNSObservation]`, which cannot read the `[]model.DNSObservation` payload shape handled by the classifier’s DNS helper. [VERIFIED: profile.go, classifier.go]
- `report.statusFromResults` calls `hasSuccess(r.Data)` and `hasSuccess` does not handle `[]model.DNSObservation`, so DNS summary status can be wrong for slice-backed DNS results. Phase 5 should avoid deepening that inconsistency. [VERIFIED: report.go, classifier.go]
- `recommend.Rank` depends on the existing top-level `profile.Profile` fields (`DNSHealth`, `TCPHealth`, `TLSHealth`, `QUICHealth`, `PathHealth`, `OverallStability`), so Phase 5 should extend profile additively rather than replacing those fields. [VERIFIED: recommend.go]

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Per-target detector execution | API / Backend | — | Classification is core application logic invoked from `scanner.Run`, not probe code and not report formatting. [VERIFIED: scanner.go, classifier.go] |
| Confidence calibration for target findings | API / Backend | — | Confidence is stored on `model.Finding` and currently decided in classifier helpers, so the shared calibrator belongs with classification logic. [VERIFIED: model.go, classifier.go] |
| Control/diagnostic partitioning | API / Backend | — | The partition is computed from `model.Target.Control` over in-memory `report.Targets`; no storage or UI tier owns it. [VERIFIED: model.go, profile.go, targets.go] |
| Cross-target correlation | API / Backend | — | Correlation needs full-report visibility after all target results exist, which happens in scanner/profile orchestration rather than per-probe code. [VERIFIED: scanner.go, profile.go] |
| TLS/QUIC divergence detection | API / Backend | — | Divergence compares observations and target metadata inside the scan result model; it is not a transport implementation concern. [VERIFIED: model.go, classifier.go, targets.go] |
| JSON/summary exposure of findings | API / Backend | — | Report formatting already consumes `model.ScanReport` and target findings without changing execution flow. [VERIFIED: report.go] |

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| Go | 1.25.0 module target; local toolchain 1.26.2 | Phase 5 stays within existing language/runtime constraints. [VERIFIED: go.mod, go version] | The repo already targets Go 1.25.0 and Phase 5 needs no newer-language dependency. [VERIFIED: go.mod] |
| `internal/classifier` | repo-local | Per-target finding generation. [VERIFIED: classifier.go] | It already owns finding construction and is the stable seam the context requires planners to preserve. [VERIFIED: classifier.go, 05-CONTEXT.md] |
| `internal/profile` | repo-local | Report-wide health aggregation and the best home for control-baseline logic. [VERIFIED: profile.go, 05-CONTEXT.md] | It already computes network-wide summaries from `model.ScanReport`. [VERIFIED: profile.go] |
| `internal/model` | repo-local | Source of truth for `Target.Control`, `Finding`, `Confidence`, and observation shapes. [VERIFIED: model.go] | Phase 5 decisions explicitly preserve existing `model.Confidence*` values and target metadata. [VERIFIED: model.go, 05-CONTEXT.md] |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `internal/scanner` | repo-local | Orchestrates per-target classification and final report assembly. [VERIFIED: scanner.go] | Use it as the insertion point for a report-level correlation pass that must populate `report.Findings` before return. [VERIFIED: scanner.go, cmd/iscan/main.go] |
| `internal/targets` | repo-local | Built-in control/diagnostic fixtures and QUIC/SNI metadata. [VERIFIED: targets.go] | Use for test fixtures and comparability rules; do not invent a second control-flag source. [VERIFIED: targets.go, model.go] |
| `internal/report` | repo-local | JSON and summary consumers of findings. [VERIFIED: report.go] | Touch only if new report-level findings need serialization or if helper reuse fixes the DNS-slice status bug. [VERIFIED: report.go] |
| `internal/recommend` | repo-local | Consumer of profile top-level fields. [VERIFIED: recommend.go] | Use as a compatibility check when changing `profile.Profile`. [VERIFIED: recommend.go] |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Local detector registry in `internal/classifier` | Cross-package registry or external rules engine | Rejected because the context locks registration to the classifier package and the repo already uses package-local registries for probes. [VERIFIED: 05-CONTEXT.md, scanner.go] |
| Report-level correlation helper | Folding correlation into `BuildProfile` only | Rejected because `BuildProfile` returns only a `Profile` and runs only under `--analyze`, so ordinary scan JSON would miss correlation findings. [VERIFIED: profile.go, cmd/iscan/main.go] |
| Re-scanning raw `[]ProbeResult` in every detector | One normalized target evidence view | Rejected because the code already has divergent slice-handling between classifier/profile/report; repeated raw scanning would repeat that bug class. [VERIFIED: classifier.go, profile.go, report.go] |

**Installation:** No new third-party dependency is required for the recommended Phase 5 shape. [VERIFIED: REQUIREMENTS.md, go.mod]

**Version verification:** Existing direct module versions are `github.com/miekg/dns v1.1.72`, `github.com/quic-go/quic-go v0.59.0`, `github.com/spf13/cobra v1.10.2`, `golang.org/x/net v0.48.0`, `golang.org/x/sync v0.19.0`, and `golang.org/x/time v0.15.0`. Phase 5 should reuse them as-is. [VERIFIED: go.mod]

## File Touchpoints

| File | Why the planner should touch it | Expected change shape |
|------|---------------------------------|-----------------------|
| `/Users/yiwei/iscan/internal/classifier/classifier.go` | Current monolith, current observation collection, current fixed confidence values. [VERIFIED: classifier.go] | Extract normalized evidence builder, detector registry, and shared confidence helper while preserving `Classify(result)` signature. [VERIFIED: classifier.go, 05-CONTEXT.md] |
| `/Users/yiwei/iscan/internal/classifier/classifier_test.go` | Existing finding-shape and confidence tests already anchor classifier behavior. [VERIFIED: classifier_test.go] | Add detector-registry coverage, confidence-promotion coverage, QUIC/TLS divergence coverage, and no-false-positive cases. [VERIFIED: classifier_test.go, targets.go, 05-CONTEXT.md] |
| `/Users/yiwei/iscan/internal/profile/profile.go` | Current all-target aggregation happens here and is the natural home for control-baseline logic. [VERIFIED: profile.go, 05-CONTEXT.md] | Add target partition helpers, baseline-aware health computation, and a profile-adjacent correlation helper. [VERIFIED: profile.go, 05-CONTEXT.md] |
| `/Users/yiwei/iscan/internal/profile/profile_test.go` | Existing profile tests cover tiering and SNI flags but not control-vs-diagnostic baselines. [VERIFIED: profile_test.go] | Add tests for control fallback, diagnostic exclusion from baseline, and correlation-driven health outcomes. [VERIFIED: profile_test.go, 05-CONTEXT.md] |
| `/Users/yiwei/iscan/internal/scanner/scanner.go` | This is where report-wide findings are assembled after per-target classification. [VERIFIED: scanner.go] | Insert the correlation pass after `results` are materialized and before returning `report`. [VERIFIED: scanner.go, cmd/iscan/main.go] |
| `/Users/yiwei/iscan/internal/model/model.go` | Existing finding types stop at DNS transparent proxy, and `Target.Control` / `QUICPort` already live here. [VERIFIED: model.go] | Only touch if Phase 5 adds new finding types or additive profile-facing model fields; do not change `Confidence` enum. [VERIFIED: model.go, 05-CONTEXT.md] |
| `/Users/yiwei/iscan/internal/targets/targets.go` | Built-in fixtures encode control targets, diagnostic targets, disabled QUIC, and compare-SNI hints. [VERIFIED: targets.go] | Reuse in tests and comparability rules; do not duplicate these semantics elsewhere. [VERIFIED: targets.go] |
| `/Users/yiwei/iscan/internal/report/report.go` | Summary rendering is target-scoped and currently blind to DNS slice payloads. [VERIFIED: report.go] | Keep out of core Phase 5 unless needed for helper reuse or bug containment; terminal redesign is deferred. [VERIFIED: report.go, 05-CONTEXT.md] |
| `/Users/yiwei/iscan/internal/recommend/recommend.go` | Downstream consumer of `profile.Profile` stability and layer health. [VERIFIED: recommend.go] | Use as a regression check if `Profile` gains additive fields or baseline-aware semantics change existing scores. [VERIFIED: recommend.go] |

## Architecture Patterns

### System Architecture Diagram

```text
Probe adapters
    |
    v
TargetResult.Results ([]ProbeResult)
    |
    v
classifier.Classify(target)
    |
    +--> normalize target evidence once
    |
    +--> detector registry (DNS / TCP / TLS / HTTP / QUIC / trace)
    |         |
    |         v
    |     per-target findings
    |
    v
scanner assembles ScanReport
    |
    +--> report-level correlation pass
    |         |
    |         +--> control vs diagnostic partition
    |         +--> TLS vs QUIC divergence
    |         +--> confidence promotion from corroboration
    |         v
    |     report-wide findings
    |
    v
profile.BuildProfile(report)
    |
    +--> baseline-aware health metrics
    v
report / recommend / CLI JSON+summary
```

### Recommended Project Structure
```text
internal/
├── classifier/
│   ├── classifier.go      # Classify entrypoint + registry orchestration
│   ├── evidence.go        # normalized target evidence helpers
│   ├── confidence.go      # shared confidence calibration
│   └── *_test.go          # detector and confidence tests
├── profile/
│   ├── profile.go         # BuildProfile + baseline-aware layer scoring
│   ├── correlate.go       # report-level control/diagnostic correlation
│   └── *_test.go          # baseline and correlation tests
└── scanner/
    └── scanner.go         # invoke per-target classify, then report correlation
```

### Pattern 1: Normalized Evidence + Local Detector Registry
**What:** Build a package-private `targetEvidence` view once from `model.TargetResult`, then run a package-local detector registry over that normalized data instead of rescanning raw `[]ProbeResult` in each detector. [VERIFIED: classifier.go, 05-CONTEXT.md]
**When to use:** For every per-target detector in Phase 5, including the current DNS/TCP/TLS/HTTP/QUIC/trace heuristics. [VERIFIED: classifier.go]
**Example:**
```go
// Recommended shape only; preserve the public entrypoint.
type targetEvidence struct {
    Target model.Target
    Now    time.Time
    DNS    []model.DNSObservation
    TCP    []model.TCPObservation
    TLS    []model.TLSObservation
    HTTP   []model.HTTPObservation
    QUIC   []model.QUICObservation
    Trace  *model.TraceObservation
}

type Detector interface {
    Detect(ev targetEvidence) []model.Finding
}
```
Source: current public seam in `/Users/yiwei/iscan/internal/classifier/classifier.go`. [VERIFIED: classifier.go]

### Pattern 2: Shared Confidence Calibration Helper
**What:** Replace scattered `ConfidenceLow/Medium/High` literals with one helper that consumes corroboration signals and returns the existing enum. [VERIFIED: classifier.go, model.go, 05-CONTEXT.md]
**When to use:** Any detector or correlation rule that promotes confidence above LOW based on real corroboration. [VERIFIED: 05-CONTEXT.md]
**Example:**
```go
// Recommended shape only; keep output in the existing enum.
type ConfidenceSignals struct {
    EvidenceCount      int
    UniqueResolvers    int
    DiagnosticFailures int
    ControlSuccesses   int
    CrossLayerMatch    bool
}

func CalibrateConfidence(signals ConfidenceSignals) model.Confidence
```
Source: existing `model.Confidence` enum in `/Users/yiwei/iscan/internal/model/model.go`. [VERIFIED: model.go]

### Pattern 3: Report-Level Correlation Pass
**What:** Add a second pass after all target results exist, using `Target.Control` to partition evidence and emit higher-order findings without changing per-target probe execution. [VERIFIED: scanner.go, model.go, 05-CONTEXT.md]
**When to use:** Control-vs-diagnostic comparisons, multi-target corroboration, and TLS/QUIC divergence summaries that need whole-report context. [VERIFIED: 05-CONTEXT.md]
**Example:**
```go
// Recommended shape only; called from scanner after target findings exist.
func Correlate(report model.ScanReport) []model.Finding
```
Source: scan assembly flow in `/Users/yiwei/iscan/internal/scanner/scanner.go`. [VERIFIED: scanner.go]

### Anti-Patterns to Avoid
- **Detector-by-raw-scan:** Re-reading `[]ProbeResult` independently in every detector recreates the DNS slice-handling inconsistency already visible between classifier, profile, and report. [VERIFIED: classifier.go, profile.go, report.go]
- **Profile-only correlation findings:** Putting all correlation in `BuildProfile` hides those findings unless `--analyze` is used. [VERIFIED: cmd/iscan/main.go, profile.go]
- **Baseline pollution:** Averaging control and diagnostic targets together defeats the point of `Target.Control` and makes divergence harder to see. [VERIFIED: profile.go, model.go, 05-CONTEXT.md]
- **QUIC absence == QUIC failure:** Targets with `QUICPort == 0` or scans without `--quic` are not evidence of UDP filtering. [VERIFIED: targets.go, cmd/iscan/main.go]

## Recommended Implementation Shape

### Detector Registry
- Keep `Classify(result model.TargetResult) []model.Finding` unchanged and move the current inline heuristics into one detector per concern. [VERIFIED: classifier.go, 05-CONTEXT.md]
- Register detectors only inside `internal/classifier`; mirror the Phase 2 registry style, but keep all detector files in the same package so call sites stay stable. [VERIFIED: 05-CONTEXT.md, scanner.go]
- Use one normalized evidence builder so every detector sees the same DNS slice flattening, trace pointer handling, and timestamps. [VERIFIED: classifier.go, profile.go]

### Confidence Calibration
- Use a single calibrator that starts from a detector-specific base confidence and only promotes on corroboration that is independent enough to matter: multiple resolvers, multiple diagnostic targets, control-success baseline, or cross-layer agreement. [VERIFIED: 05-CONTEXT.md, classifier.go]
- Keep single isolated failures LOW; promote to MEDIUM for repeated same-claim evidence within a target or for same-layer divergence against a control baseline; promote to HIGH only for multi-target or cross-layer corroboration with an intact control baseline. [VERIFIED: 05-CONTEXT.md]
- Preserve current strong Phase 4 semantics unless stronger evidence raises them further: NXDOMAIN and REFUSED already map to HIGH, SERVFAIL to MEDIUM, other RCODEs to LOW. [VERIFIED: classifier.go, classifier_test.go]

### Control-vs-Diagnostic Split
- Partition `report.Targets` into `controlTargets` and `diagnosticTargets` once inside profile/correlation helpers using only `target.Target.Control`. [VERIFIED: model.go, targets.go, 05-CONTEXT.md]
- Compute baseline health from controls when any exist; score diagnostic anomalies against that baseline rather than averaging them into it. Fall back to all targets only when the control set is empty. [VERIFIED: 05-CONTEXT.md, profile.go]
- Keep the existing top-level `Profile` fields usable by `recommend.Rank`; if new split-specific fields are added, make them additive. [VERIFIED: recommend.go, profile.go]

### Correlation
- Run correlation after `scanner.Run` has materialized all `TargetResult` values and after per-target findings already exist. [VERIFIED: scanner.go, 05-CONTEXT.md]
- Emit report-level findings for patterns like `controls succeed on TLS, diagnostics fail on TLS` or `controls succeed on DNS, diagnostics show suspicious/private answers`, because those conclusions require multi-target comparison. [VERIFIED: 05-CONTEXT.md, classifier.go, targets.go]
- Do not move terminal-summary rendering into this phase; JSON/report findings and profile outputs are enough for Phase 5. [VERIFIED: 05-CONTEXT.md, report.go]

### TLS/QUIC Divergence Detection
- Detect divergence only for comparable targets that actually intended both probes: same target family, at least one successful TLS observation, at least one failed QUIC observation, and QUIC enabled for that target. [VERIFIED: 05-CONTEXT.md, model.go, targets.go, cmd/iscan/main.go]
- Ignore cases where QUIC was disabled (`QUICPort == 0`), globally skipped (`--quic=false`), or absent because the target set does not support it. [VERIFIED: targets.go, cmd/iscan/main.go]
- Keep this detector conservative by excluding obvious local/permission/missing-support failures from promotion logic. The current code already treats local permission errors as non-diagnostic for traceroute; Phase 5 should apply the same caution to divergence logic. [VERIFIED: classifier.go, classifier_test.go, 05-CONTEXT.md]

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Per-detector result parsing | Each detector manually traversing `[]ProbeResult` | One shared evidence-normalization helper | The repo already shows this causes drift for DNS slice payloads. [VERIFIED: classifier.go, profile.go, report.go] |
| Confidence math | Floating-point scoring type or new enum | Existing `model.Confidence` enum + shared rule-based calibrator | The context locks the enum shape and report formatting already depends on it. [VERIFIED: model.go, 05-CONTEXT.md] |
| Control-baseline source | A second flag, name convention, or inferred host category | `model.Target.Control` only | The model and built-in targets already encode the baseline source of truth. [VERIFIED: model.go, targets.go, 05-CONTEXT.md] |
| Report-wide divergence storage | New parallel report object | `model.ScanReport.Findings` plus additive `profile.Profile` fields if needed | Existing JSON/report/recommendation flows already consume these structures. [VERIFIED: model.go, report.go, recommend.go, cmd/iscan/main.go] |

**Key insight:** Phase 5 is not a new data model project; it is a better interpretation layer over the Phase 2 `ProbeResult` pipeline. [VERIFIED: scanner.go, model.go, classifier.go]

## Common Pitfalls

### Pitfall 1: Missing Multi-Resolver DNS Evidence
**What goes wrong:** Control baselines or detector logic silently ignore DNS results stored as `[]model.DNSObservation`. [VERIFIED: classifier.go, profile.go]
**Why it happens:** The classifier already has `collectAllDNSObservations`, but profile and report still use generic single-value helpers. [VERIFIED: classifier.go, profile.go, report.go]
**How to avoid:** Centralize DNS flattening and reuse it anywhere Phase 5 touches DNS evidence. [VERIFIED: classifier.go]
**Warning signs:** DNS findings exist in per-target classification, but profile DNS metrics or summary layer status look empty or degraded unexpectedly. [VERIFIED: classifier.go, profile.go, report.go]

### Pitfall 2: Correlation Hidden Behind `--analyze`
**What goes wrong:** Report-wide divergences appear only when analysis mode is enabled. [VERIFIED: cmd/iscan/main.go, profile.go]
**Why it happens:** `BuildProfile` only runs under `--analyze`, but ordinary scan JSON is always emitted from `scanner.Run`. [VERIFIED: cmd/iscan/main.go, scanner.go]
**How to avoid:** Put correlation findings in a scanner-invoked report-level helper before the report is returned. [VERIFIED: scanner.go]
**Warning signs:** `report.Findings` contains only per-target findings and no control-vs-diagnostic conclusions unless profile/recommendation was built. [VERIFIED: scanner.go, profile.go]

### Pitfall 3: Baseline Pollution by Control Targets
**What goes wrong:** Diagnostics look healthier than they are because control targets are averaged into the same success rate. [VERIFIED: profile.go, 05-CONTEXT.md]
**Why it happens:** Current profile functions iterate all targets without partitioning. [VERIFIED: profile.go]
**How to avoid:** Partition once, compute control baseline first, and only compare diagnostics against it. [VERIFIED: profile.go, 05-CONTEXT.md]
**Warning signs:** Diagnostic failures disappear or overall stability stays high even when only non-control targets are failing. [VERIFIED: profile.go]

### Pitfall 4: False QUIC Divergence Positives
**What goes wrong:** The system reports UDP/QUIC filtering for targets that never intended a QUIC probe. [VERIFIED: targets.go, cmd/iscan/main.go]
**Why it happens:** Some built-in targets explicitly disable QUIC with `QUICPort: 0`, and QUIC is globally optional. [VERIFIED: targets.go, cmd/iscan/main.go]
**How to avoid:** Gate divergence on comparable targets with explicit QUIC intent and actual TLS+QUIC evidence. [VERIFIED: 05-CONTEXT.md, targets.go]
**Warning signs:** Divergence fires on `no-quic-control` or on scans where `--quic` was never enabled. [VERIFIED: targets.go, cmd/iscan/main.go]

## Code Examples

Illustrative signatures only; these are planning shapes, not implemented code. [VERIFIED: research synthesis from current code seams]

### Per-Target Classifier Shape
```go
func Classify(result model.TargetResult) []model.Finding
```
Source: `/Users/yiwei/iscan/internal/classifier/classifier.go`. [VERIFIED: classifier.go]

### Report-Level Correlation Shape
```go
func Correlate(report model.ScanReport) []model.Finding
```
Source rationale: `scanner.Run` owns final `ScanReport` assembly before CLI/report consumers execute. [VERIFIED: scanner.go, cmd/iscan/main.go]

### Baseline Partition Helper Shape
```go
func partitionTargets(targets []model.TargetResult) (controls []model.TargetResult, diagnostics []model.TargetResult)
```
Source rationale: `model.Target.Control` is already the source of truth. [VERIFIED: model.go, targets.go, 05-CONTEXT.md]

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| One monolithic `Classify()` body | Detector-oriented registry behind the same public entrypoint | Phase 5 planned | Enables isolated heuristics, confidence reuse, and narrower tests without changing scanner callers. [VERIFIED: classifier.go, 05-CONTEXT.md] |
| Static confidence literals per finding site | Shared rule-based calibration that still emits LOW/MEDIUM/HIGH | Phase 5 planned | Keeps output compatibility while making corroborated findings more trustworthy. [VERIFIED: model.go, classifier.go, 05-CONTEXT.md] |
| All-target profile aggregation | Control-baseline-first aggregation with fallback to all-target when controls are absent | Phase 5 planned | Prevents baseline pollution and enables meaningful divergence detection. [VERIFIED: profile.go, 05-CONTEXT.md] |
| No report-level correlation pass | Post-classification correlation after full report assembly | Phase 5 planned | Allows control-vs-diagnostic and TLS/QUIC conclusions to exist in ordinary scan results. [VERIFIED: scanner.go, cmd/iscan/main.go, 05-CONTEXT.md] |

**Deprecated/outdated:**
- Repeating raw `ProbeResult` traversal logic in each consumer is already outdated inside this repo because the classifier, profile, and report layers no longer agree on DNS payload handling. [VERIFIED: classifier.go, profile.go, report.go]

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|

All claims in this research were verified from the current codebase or phase documents — no user confirmation is needed. [VERIFIED: research inputs]

## Open Questions

None blocking planning. The phase context already locks the important design boundaries, and the recommended shapes above resolve the remaining discretion points without requiring new user decisions. [VERIFIED: 05-CONTEXT.md]

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Go `testing` package on Go 1.25.0 module target; local toolchain `go1.26.2`. [VERIFIED: go.mod, go version, existing `*_test.go` files] |
| Config file | none — standard `go test` package discovery. [VERIFIED: repo search] |
| Quick run command | `go test ./internal/classifier ./internal/profile ./internal/scanner ./internal/report ./internal/recommend -count=1` [VERIFIED: existing package tests] |
| Full suite command | `go test ./... -count=1` [VERIFIED: README.md, repo test layout] |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| F-09 | Control targets do not pollute diagnostic baseline; fallback works when no controls exist. [VERIFIED: REQUIREMENTS.md, 05-CONTEXT.md] | unit | `go test ./internal/profile -count=1` | ✅ `internal/profile/profile_test.go` [VERIFIED: profile_test.go] |
| F-15 | Confidence rises only with corroborated evidence and stays LOW for isolated failures. [VERIFIED: REQUIREMENTS.md, 05-CONTEXT.md] | unit | `go test ./internal/classifier -count=1` | ✅ `internal/classifier/classifier_test.go` [VERIFIED: classifier_test.go] |
| F-16 | Detectors remain composable while `Classify(result)` stays stable. [VERIFIED: REQUIREMENTS.md, 05-CONTEXT.md] | unit | `go test ./internal/classifier -count=1` | ✅ `internal/classifier/classifier_test.go` [VERIFIED: classifier_test.go] |
| F-17 | Report-level correlation compares control vs diagnostic outcomes and emits divergence conclusions. [VERIFIED: REQUIREMENTS.md, 05-CONTEXT.md] | unit/integration | `go test ./internal/profile ./internal/scanner -count=1` | ✅ `internal/profile/profile_test.go`; ✅ `internal/scanner/scanner_test.go` [VERIFIED: profile_test.go, repo search] |
| Phase 5 delivery | TLS success + QUIC failure on comparable targets produces conservative divergence finding without false positives. [VERIFIED: ROADMAP.md, 05-CONTEXT.md] | unit | `go test ./internal/classifier ./internal/profile -count=1` | ✅ existing test files; new cases required. [VERIFIED: classifier_test.go, profile_test.go] |

### Sampling Rate
- **Per task commit:** `go test ./internal/classifier ./internal/profile -count=1` for detector/profile edits, plus touched consumer packages as needed. [VERIFIED: repo test layout]
- **Per wave merge:** `go test ./internal/classifier ./internal/profile ./internal/scanner ./internal/report ./internal/recommend -count=1` [VERIFIED: repo test layout]
- **Phase gate:** `go test ./... -count=1` [VERIFIED: README.md]

### Wave 0 Gaps
- [ ] Add `internal/profile` tests for control-vs-diagnostic partition, control-absent fallback, and cross-target correlation emission. [VERIFIED: profile_test.go, 05-CONTEXT.md]
- [ ] Add `internal/classifier` tests for detector registry orchestration and confidence promotion/demotion rules. [VERIFIED: classifier_test.go, 05-CONTEXT.md]
- [ ] Add QUIC/TLS divergence tests that explicitly cover `QUICPort: 0`, `--quic` disabled, and comparable-target success/failure cases. [VERIFIED: targets.go, cmd/iscan/main.go, 05-CONTEXT.md]
- [ ] Add regression coverage for DNS slice-backed observations in any profile/report helpers touched by this phase. [VERIFIED: classifier.go, profile.go, report.go]

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | no | CLI phase has no auth surface. [VERIFIED: cmd/iscan/main.go, model.go] |
| V3 Session Management | no | CLI phase has no session layer. [VERIFIED: cmd/iscan/main.go] |
| V4 Access Control | no | Phase 5 changes classification/profile logic only. [VERIFIED: ROADMAP.md, 05-CONTEXT.md] |
| V5 Input Validation | yes | Keep relying on typed observation structs and `model.Target.Control` instead of inferred labels; reject detector promotion from missing or incomparable evidence. [VERIFIED: model.go, classifier.go, targets.go, 05-CONTEXT.md] |
| V6 Cryptography | no | Phase 5 does not change TLS/QUIC cryptographic implementation, only result interpretation. [VERIFIED: ROADMAP.md, classifier.go] |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| False-positive confidence escalation from weak evidence | Tampering | Centralize calibration and require corroboration across resolvers, targets, or layers before promoting confidence. [VERIFIED: 05-CONTEXT.md, classifier.go] |
| Baseline manipulation by mixing control and diagnostic targets | Tampering | Partition by `Target.Control` before aggregation and keep control-only baseline semantics. [VERIFIED: model.go, profile.go, 05-CONTEXT.md] |
| Misclassification from missing QUIC intent or DNS slice parsing | Tampering | Normalize evidence once and gate divergence on comparable, actually-probed targets. [VERIFIED: classifier.go, profile.go, targets.go, cmd/iscan/main.go] |

## Sources

### Primary (HIGH confidence)
- `/Users/yiwei/iscan/.planning/phases/05-classification-and-profile-improvements/05-CONTEXT.md` - locked Phase 5 decisions, discretion, and deferrals.
- `/Users/yiwei/iscan/.planning/REQUIREMENTS.md` - Phase 5 requirement IDs F-09, F-15, F-16, F-17 and repo constraints.
- `/Users/yiwei/iscan/.planning/ROADMAP.md` - Phase 5 delivery criteria and task IDs T-029 to T-034.
- `/Users/yiwei/iscan/internal/classifier/classifier.go` - current monolithic classifier, observation helpers, confidence literals.
- `/Users/yiwei/iscan/internal/classifier/classifier_test.go` - current classifier behavior and confidence expectations.
- `/Users/yiwei/iscan/internal/profile/profile.go` - current all-target profile aggregation and top-level profile shape.
- `/Users/yiwei/iscan/internal/profile/profile_test.go` - existing profile coverage and current gaps.
- `/Users/yiwei/iscan/internal/model/model.go` - `Target.Control`, `FindingType`, `Confidence`, `ScanReport`, and observation types.
- `/Users/yiwei/iscan/internal/scanner/scanner.go` - per-target classification call site and report assembly flow.
- `/Users/yiwei/iscan/internal/targets/targets.go` - built-in control/diagnostic targets and QUIC/SNI metadata fixtures.
- `/Users/yiwei/iscan/internal/report/report.go` - current summary/JSON consumers and DNS slice blind spot.
- `/Users/yiwei/iscan/internal/recommend/recommend.go` - downstream dependency on top-level profile fields.
- `/Users/yiwei/iscan/cmd/iscan/main.go` - `--analyze` gating and scan/report consumption flow.
- `/Users/yiwei/iscan/go.mod` - Go version and existing dependency set.

### Secondary (MEDIUM confidence)
- None.

### Tertiary (LOW confidence)
- None.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - derived directly from `go.mod` and current repo package boundaries. [VERIFIED: go.mod, codebase read]
- Architecture: HIGH - based on current scanner/classifier/profile/report call flow and locked phase context. [VERIFIED: scanner.go, classifier.go, profile.go, 05-CONTEXT.md]
- Pitfalls: HIGH - based on concrete code-path mismatches already present in classifier/profile/report and target metadata. [VERIFIED: classifier.go, profile.go, report.go, targets.go]

**Research date:** 2026-04-27
**Valid until:** 2026-05-27
