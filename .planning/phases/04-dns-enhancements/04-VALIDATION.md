---
phase: 04
slug: dns-enhancements
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-04-27
---

# Phase 4 — DNS Enhancements Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Go testing (stdlib) |
| **Config file** | None — `go test ./...` |
| **Quick run command** | `go test ./internal/probe/dnsprobe/...` |
| **Full suite command** | `go test ./...` |
| **Estimated runtime** | ~30 seconds |

---

## Sampling Rate

- **After every task commit:** Run `go test ./internal/probe/dnsprobe/...`
- **After every plan wave:** Run `go test ./...`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|------|------|-------------|-----------|-------------------|-------------|--------|
| 01 | 1 | F-13, N-01 | unit | `go build ./...` | N/A | ⬜ pending |
| 02-T1 | 2 | F-13 | unit | `go build ./...` | N/A | ⬜ pending |
| 02-T2 | 2 | F-13 (DoH) | unit | `go test ./internal/probe/dnsprobe/... -run TestProbeDoH` | No (W0) | ⬜ pending |
| 02-T3 | 2 | F-13 (DoT) | unit | `go test ./internal/probe/dnsprobe/... -run TestProbeDoT` | No (W0) | ⬜ pending |
| 03-T1 | 3 | F-13 | unit | `go test ./internal/probe/dnsprobe/... -run 'TestGetLimiter\|TestWaitLimiter\|TestSetRateLimit'` | No (W0) | ⬜ pending |
| 03-T2 | 3 | F-13 | build | `go build ./...` | N/A | ⬜ pending |
| 04-T1 | 2 | F-05 | unit | `go test ./internal/classifier/... -run 'TestClassifyReportsRCODE\|TestClassifyNoRCODE\|TestClassifyCollectsDNSObs'` | No (W0) | ⬜ pending |
| 04-T2 | 2 | F-05 | unit | `go test ./internal/classifier/... -run 'TestClassifyDetectsTransparent\|TestClassifyNoTransparent'` | No (W0) | ⬜ pending |
| 05-T1 | 4 | F-13 | build | `go build ./...` | N/A | ⬜ pending |
| 05-T2 | 4 | F-13, F-05 | build | `go build ./... && go vet ./...` | N/A | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `internal/probe/dnsprobe/doh_test.go` — tests DoH probe with local HTTPS server
- [ ] `internal/probe/dnsprobe/dot_test.go` — tests DoT probe with local TLS listener
- [ ] `internal/probe/dnsprobe/ratelimit_test.go` — tests rate limiter behavior
- [ ] `internal/classifier/classifier_test.go` — add per-RCODE finding + transparent proxy tests

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| whoami.akamai.net probing | T-028 | Requires network access to external DNS resolvers | Run `iscan scan --resolver https://1.1.1.1 --target-set minimal` and inspect output for transparent proxy findings |
| CLI flag parsing | F-13 | Cobra flag wiring — build-time validation is sufficient | Run `iscan scan --help` and verify `--resolver` and `--dns-rate-limit` appear in output |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
