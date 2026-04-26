# Plan 02-03 Summary: Probe Adapters + init() Registration

**Status:** Complete
**Date:** 2026-04-26

## Changes

| File | Change |
|------|--------|
| `internal/probe/dnsprobe/adapter.go` (NEW) | DNSOpts + Adapter + init() registration |
| `internal/probe/tcp/adapter.go` (NEW) | TCPOpts + Adapter + init() registration |
| `internal/probe/tlsprobe/adapter.go` (NEW) | TLSOpts + Adapter + init() registration |
| `internal/probe/httpprobe/adapter.go` (NEW) | HTTPOpts + Adapter + init() registration |
| `internal/probe/quicprobe/adapter.go` (NEW) | QUICOpts + Adapter + init() registration |
| `internal/probe/traceprobe/adapter.go` (NEW) | TraceOpts + Adapter + init() registration |

## Verification

- `go vet ./internal/probe/...` — PASS
- `go build ./internal/probe/...` — PASS
- `go test ./internal/probe/...` — PASS (all 6 suites)
