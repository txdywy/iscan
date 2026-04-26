# Technology Stack

**Analysis Date:** 2026-04-26

## Languages

**Primary:**
- Go 1.24.0 - All application code, CLI entry point (`cmd/iscan/main.go`), and internal packages (`internal/`)

**Secondary:**
- None detected. No shell scripts, Makefiles, YAML configs, or other languages present in the repository.

## Runtime

**Environment:**
- Go binary (compiled), targeting any OS with Go support
- Module: `iscan` (no vanity import path)
- Go toolchain specified in `go.mod` as `go 1.24.0`

**Package Manager:**
- Go modules (`go mod`)
- Lockfile: `go.sum` present and tracked

## Frameworks

**Core:**
- `github.com/spf13/cobra v1.10.2` - CLI command framework. Used for the `scan` subcommand with flag parsing (`--json`, `--summary`, `--timeout`, `--retries`, `--trace`, `--quic`, `--target-set`, `--analyze`). Defined in `cmd/iscan/main.go`.

**Testing:**
- Standard `testing` package from Go stdlib. No external test framework (no testify, no gomega). Table-driven tests with `t.Run()` sub-tests used in `internal/model/errors_test.go`.

**Build/Dev:**
- No build system or task runner detected (no Makefile, no Taskfile, no Mage)
- No linting configuration detected (no `.golangci.yml`, no `.eslintrc`)
- No CI configuration detected (no `.github/workflows/`, no `Jenkinsfile`)

## Key Dependencies

**Critical:**
- `github.com/miekg/dns v1.1.72` - DNS protocol client. Used in `internal/probe/dnsprobe/dns.go` for direct DNS queries to specified resolvers (A and AAAA records) over UDP and TCP (truncation fallback). Supports EDNS0 with 1232-byte payload.
- `github.com/quic-go/quic-go v0.59.0` - QUIC protocol implementation. Used in `internal/probe/quicprobe/quic.go` for QUIC/UDP handshake probes (QUIC v1 and v2 detection).
- `golang.org/x/net v0.48.0` - Extended networking. Used in `internal/probe/traceprobe/trace.go` for ICMP sockets (`icmp` and `ipv4` sub-packages) for traceroute-style probes.
- `golang.org/x/sync v0.19.0` - Concurrency primitives (`errgroup`). Used in `internal/scanner/scanner.go` for parallel target scanning with bounded concurrency (`Group.SetLimit`).

**Infrastructure:**
- `github.com/spf13/pflag v1.0.9` - Indirect via Cobra for POSIX-compliant flag parsing.
- `golang.org/x/crypto v0.46.0` - Indirect, but required by `quic-go` for TLS 1.3 handshakes.
- `golang.org/x/sys v0.39.0` - Indirect via `golang.org/x/net` for low-level network socket operations.

## Configuration

**Environment:**
- No environment variables used. All configuration is via CLI flags on the `scan` subcommand (`cmd/iscan/main.go` lines 45-101).
- No `.env` file present.

**Build:**
- `go.mod` at root defines the module and dependency versions.
- No build-time configuration files (no `tsconfig.json`, no `webpack.config.js`, no Bazel rules).

## Platform Requirements

**Development:**
- Go 1.24.0 or later
- Root/Administrator privileges optional (required for ICMP trace probes; gracefully degrades with a warning)

**Production:**
- Binary distribution only. Compiled Go binary with no external runtime dependencies.
- No containerization or deployment configuration present.

## Go Module Layout Dependency Flow

```
cmd/iscan/main.go
  ├── internal/scanner         (orchestrates probes)
  │     ├── internal/targets   (builtin target/resolver definitions)
  │     ├── internal/probe/dnsprobe
  │     ├── internal/probe/tcp
  │     ├── internal/probe/tlsprobe
  │     ├── internal/probe/httpprobe
  │     ├── internal/probe/quicprobe
  │     ├── internal/probe/traceprobe
  │     ├── internal/model
  │     └── internal/classifier
  ├── internal/profile
  │     └── internal/model
  ├── internal/recommend
  │     ├── internal/model
  │     └── internal/profile
  └── internal/report
        ├── internal/model
        ├── internal/profile
        └── internal/recommend
```

---

*Stack analysis: 2026-04-26*
