---
phase: 05
slug: classification-and-profile-improvements
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-04-27
---

# Phase 5 — Classification and Profile Improvements Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Go testing (stdlib) |
| **Config file** | None — `go test ./...` |
| **Quick run command** | `go test ./internal/classifier ./internal/profile ./internal/scanner -count=1` |
| **Full suite command** | `go test ./... -count=1` |
| **Estimated runtime** | ~45 seconds |

---

## Sampling Rate

- **After every task commit:** Run `go test ./internal/classifier ./internal/profile ./internal/scanner -count=1`
- **After every plan wave:** Run `go test ./... -count=1`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 45 seconds

---

## Per-Task Verification Map

| Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|------|------|-------------|-----------|-------------------|-------------|--------|
| 01 | 1 | F-16 | unit | `go test ./internal/classifier -run 'TestClassify(UsesDetectorRegistry|KeepsPublicSignatureStable)' -count=1` | Yes | ⬜ pending |
| 02 | 2 | F-16, F-15 | unit | `go test ./internal/classifier -run 'TestClassify(ExtractsDetectors|PreservesExistingRCODESemantics)' -count=1` | Yes | ⬜ pending |
| 03 | 3 | F-15 | unit | `go test ./internal/classifier -run 'TestCalibrateConfidence|TestClassify(.*Confidence)' -count=1` | Yes | ⬜ pending |
| 04 | 4 | F-09, F-17 | unit/integration | `go test ./internal/profile ./internal/scanner -count=1` | Yes | ⬜ pending |
| 05 | 4 | F-17 | unit | `go test ./internal/classifier -run 'TestClassify(DetectsTLSQUICDivergence|RejectsQUICDisabledTargets|RejectsMissingSupport)' -count=1` | Yes | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] Existing classifier/profile/scanner tests cover the current seams; no new framework is required.

*If none: "Existing infrastructure covers all phase requirements."*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| None | N/A | All phase behaviors have automated verification. | N/A |

*If none: "All phase behaviors have automated verification."*

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 45s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
