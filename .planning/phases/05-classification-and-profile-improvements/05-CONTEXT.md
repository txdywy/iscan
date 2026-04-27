# Phase 5: Classification and Profile Improvements - Context

**Gathered:** 2026-04-27
**Status:** Ready for planning

<domain>
## Phase Boundary

Classification becomes detector-driven, evidence-weighted, and easier to extend. Profile computation distinguishes control targets from diagnostic targets so cross-target correlation and protocol divergence can be measured against the right baseline.

**Requirements addressed:** Phase 5 roadmap items T-029 to T-034, especially composable findings, confidence calibration, control-target separation, and cross-target correlation.
</domain>

<decisions>
## Implementation Decisions

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
</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Classification and profile code
- `internal/classifier/classifier.go` — current monolithic classifier and DNS-specific helpers
- `internal/classifier/classifier_test.go` — existing classification tests and expected finding shapes
- `internal/profile/profile.go` — current profile aggregation logic to split control vs diagnostic behavior
- `internal/model/model.go` — `Target.Control`, `Finding`, `Confidence`, `ScanReport`, and observation types
- `internal/scanner/scanner.go` — scan flow that classifies each target and assembles the report

### Requirements and roadmap
- `.planning/REQUIREMENTS.md` — Phase 5 requirement set
- `.planning/ROADMAP.md` § Phase 5 — task breakdown and delivery criteria
- `.planning/STATE.md` — milestone position and phase ordering

### Related phase context
- `.planning/phases/04-dns-enhancements/04-CONTEXT.md` — DNS finding patterns already established in the previous phase
</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `internal/classifier/classifier.go` already gathers observations by layer and emits findings from a single `Classify()` pass.
- `internal/profile/profile.go` already computes layered health summaries from `model.ScanReport`; this is the natural place to distinguish control targets from diagnostic targets.
- `model.Target.Control` already exists, so no new target metadata is needed to identify baseline targets.
- `internal/scanner/scanner.go` already produces per-target results and appends classified findings, which means cross-target logic can be layered on top without changing scan execution.

### Established Patterns
- **Single public entrypoint, internal helpers:** the package exposes one main function and hides implementation detail in unexported helpers.
- **Observation-first classification:** findings are derived from observation structs rather than from probe implementations directly.
- **Report aggregation after scanning:** the scanner produces raw target results first; profile and reporting logic derive higher-order meaning afterward.

### Integration Points
- `internal/classifier/classifier.go` — add detector helpers and orchestration
- `internal/profile/profile.go` — add control/diagnostic split and correlation-aware summary logic
- `internal/classifier/classifier_test.go` — extend coverage for detector-driven classification and divergence signals
- `internal/profile/profile_test.go` — add baseline separation and cross-target aggregation coverage if tests exist or are introduced
</code_context>

<specifics>
## Specific Ideas

- A detector can be a small function like `func(model.TargetResult, time.Time) []model.Finding`, composed through a registry slice.
- Confidence calibration can be centralized in a helper that compares evidence counts, correlated target groups, and cross-layer agreement.
- Cross-target correlation should treat control-target success as the strongest positive signal and control-target failure as a baseline warning.
- TLS/QUIC divergence should compare comparable target families rather than arbitrary hosts to avoid false positives from targets that intentionally expose different transports.
</specifics>

<deferred>
## Deferred Ideas

- Reworking report rendering to expose the new correlation logic directly in the terminal layout.
- Introducing a new type hierarchy for findings beyond the existing `model.Finding` enum.
- Adding transport-specific profile sub-scores beyond TLS/QUIC divergence.
</deferred>

---

*Phase: 05-Classification and Profile Improvements*
*Context gathered: 2026-04-27 via discussion*
