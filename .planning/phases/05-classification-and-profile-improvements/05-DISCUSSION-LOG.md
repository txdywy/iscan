# Phase 5 Discussion Log

**Date:** 2026-04-27
**Outcome:** Decisions locked for planning

## Focus Areas Discussed

1. **Classifier structure**
   - Moved from one large `Classify()` body toward a detector registry.
   - Chosen direction: small detectors with one responsibility each.

2. **Confidence handling**
   - Chosen direction: keep existing `model.Confidence*` values, but compute them from evidence quality and corroboration rather than static per-finding defaults.

3. **Control targets**
   - Chosen direction: treat `model.Target.Control` as the baseline source and keep control targets out of diagnostic aggregation.

4. **Cross-target correlation**
   - Chosen direction: perform correlation after per-target classification so raw findings stay local and higher-level conclusions are layered on top.

5. **TLS/QUIC divergence**
   - Chosen direction: add a conservative detector for cases where TLS succeeds and QUIC fails for the same comparable target family.

## Resulting Guidance for Planning

- Keep the public classifier entrypoint stable.
- Put control/diagnostic separation in profile logic, not probe execution.
- Prefer conservative heuristics that require real corroboration before raising confidence.
- Avoid introducing new enums or type systems unless the existing model cannot express the outcome.
