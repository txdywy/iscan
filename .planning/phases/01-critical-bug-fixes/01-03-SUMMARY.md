# Plan 01-03 Summary: DNS/QUIC/Context Deadline Fixes

**Status:** Complete
**Date:** 2026-04-26

## Changes

| File | Change |
|------|--------|
| `internal/probe/dnsprobe/dns.go` | Fresh `tcpMsg` with `SetEdns0(1232, false)` for TCP retry; TCP latency measured from `tcpStart` not original `start` |
| `internal/probe/quicprobe/quic.go` | Changed `HandshakeIdleTimeout: timeout` to `timeout / 2` (quic-go doubles internally) |
| `internal/scanner/scanner.go` | Added `probeContext` helper for per-probe deadline derivation; all 6+ probe calls wrapped with derived context |

## Verification

- `go build ./...` — PASS
- `go vet ./...` — PASS
- `go test ./internal/probe/dnsprobe/ -v -timeout 30s` — 4/4 PASS
- `go test ./internal/probe/quicprobe/ -v -timeout 30s` — 1/1 PASS
- `go test ./internal/scanner/ -v -timeout 30s` — 6/6 PASS

## Decisions Applied

- D-06: Child context.WithTimeout per probe with remaining-time division
- D-07: Deadline splitting in scanner's scanTarget, not inside probe packages
- D-08: All 6 probes audited for ctx.Done()/ctx.Deadline() respect
