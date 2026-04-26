# Technology Stack

**Project:** iscan - Layered Network Diagnostics CLI
**Researched:** 2026-04-26
**Mode:** Ecosystem

## Recommended Stack

### Core Framework
| Technology | Version | Purpose | Why |
|------------|---------|---------|-----|
| Go | 1.24+ | Runtime and toolchain | Language standard library already provides excellent net, crypto/tls, net/http packages for probing. Go 1.24 adds experimental `testing/synctest` for time-sensitive testing. Concurrent goroutines are the natural execution model for I/O-bound probes. |
| `github.com/spf13/cobra` | v1.10+ | CLI framework | Already in use. Broad ecosystem, composable subcommands, stdout/stderr writer separation. Fits the diagnostic CLI pattern well. |
| `golang.org/x/sync` | v0.19+ | Concurrency control | Already in use. `errgroup` provides structured concurrency with cancellation propagation. `SetLimit` controls parallelism. |

### DNS Probes
| Technology | Version | Purpose | Why |
|------------|---------|---------|-----|
| `github.com/miekg/dns` | v1.1.72 | DNS message construction and exchange | Already in use. Production-grade, used by CoreDNS and Consul. Full EDNS0 support (currently used: `SetEdns0(1232, false)`). Supports UDP, TCP, and TCP-TLS transport. Truncation fallback (UDP -> TCP) already implemented. |
| `golang.org/x/net` | v0.48+ | DNS-over-HTTPS (DoH) | Already a dep. `miekg/dns` v1.x supports DoH via `c.Net = "https"`. For a DNS probe, this is the cleanest path: same message construction, different transport. No additional dependency needed. |
| `golang.org/x/net` (proxy sub-package) | same module | SOCKS5 support for DNS probes | `golang.org/x/net/proxy` provides `SOCKS5()` function and `FromURL()` that implements `ContextDialer`. Can wrap resolvers to route DNS through SOCKS5 proxies. Zero new dependencies. |

**Current implementation assessment:** The DNS probe handles UDP+TCP with truncation fallback. To add DoH/DoT support, the existing `dnsprobe.Probe` needs a transport selector parameter (not a new library). The `miekg/dns` client already supports all three transports.

### TLS Probes
| Technology | Version | Purpose | Why |
|------------|---------|---------|-----|
| `crypto/tls` (stdlib) | Go 1.24+ | TLS handshake probe | Already in use. The `tls.Dialer` pattern is correct and idiomatic. Reports version, ALPN, certificate fingerprint (SHA-256). No additional library needed. |

**Current implementation assessment:** Good. The TLS probe captures: version, negotiated ALPN, leaf cert SHA-256, handshake latency. The `InsecureSkipVerify: true` is correct for probing -- we want the handshake to succeed even if the certificate is invalid (the cert data is still collected for analysis).

**When to add `utls`:** Only if the project needs TLS fingerprint randomization (anti-censorship scenarios where deep packet inspection blocks standard Go TLS ClientHellos). `github.com/refraction-networking/utls` provides this but adds significant complexity. Not recommended for the initial stack.

### TCP Probes
| Technology | Version | Purpose | Why |
|------------|---------|---------|-----|
| `net` (stdlib) | Go 1.24+ | TCP connect probe | Already in use. `net.Dialer.DialContext` with timeout is the correct pattern. Error classification uses `errors.Is` with syscall errors + string matching fallback. |

**Current implementation assessment:** The error classification is reasonable but has a minor risk: string matching on `err.Error()` is fragile across Go versions and OS locales. The recommended upgrade is to use `errors.Is` with `os.ErrDeadlineExceeded`, `context.DeadlineExceeded`, and specific syscall errors (already partially done). Add `net.ErrClosed` for connection-closed-during-handshake detection.

### HTTP Probes
| Technology | Version | Purpose | Why |
|------------|---------|---------|-----|
| `net/http` (stdlib) | Go 1.24+ | HTTP request/response | Already in use. `http.Client` with custom `Transport` and `httptrace` is the standard pattern. The current implementation captures per-phase latency (DNS, connect, TLS, first byte). |

**Current implementation assessment:** Solid. The `httptrace.ClientTrace` captures phase-level timing which is valuable for diagnostics. The `CheckRedirect` returning `http.ErrUseLastResponse` is correct (we want to observe the redirect response, not follow it). One improvement: the `transport.DialContext` override bypasses the HTTP layer's DNS resolution (intentional, since we pass a dial address from prior TLS probe), but the trace shows `dnsStart`/`dnsDone` as zero in that case -- this is fine but could be documented with a comment.

### QUIC / HTTP/3 Probes
| Technology | Version | Purpose | Why |
|------------|---------|---------|-----|
| `github.com/quic-go/quic-go` | v0.59.0 | QUIC handshake probe | Already in use. Production-grade, used by Caddy, Cloudflare, OONI. Requires Go 1.24+. v0.59.0 is very recent. |

**Current implementation assessment:** The QUIC probe uses `quic.DialAddr` with a quic.Config that sets both `HandshakeIdleTimeout` and `MaxIdleTimeout` to the probe timeout. This is correct. The current probe captures version (QUICv1/QUICv2), ALPN, cert SHA-256, and latency.

**Missing: HTTP/3 round-trip probing.** If the goal expands to HTTP/3 application-level probing, add `github.com/quic-go/quic-go/http3` (same module, no new dep). Usage:
```go
rt := &http3.RoundTripper{
    TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    QUICConfig:      &quic.Config{HandshakeIdleTimeout: timeout},
}
defer rt.Close()
client := &http.Client{Transport: rt}
resp, err := client.Get(url)
```
This is optional and should be deferred until HTTP/3 application probing is needed.

### ICMP / Traceroute Probes
| Technology | Version | Purpose | Why |
|------------|---------|---------|-----|
| `golang.org/x/net/icmp` | same module | ICMP message construction and parsing | Already in use. Correct for low-level traceroute implementation. |
| `golang.org/x/net/ipv4` | same module | TTL control on raw sockets | Already in use. `ipv4.NewPacketConn` + `SetTTL` is the standard pattern for traceroute. |

**Current implementation assessment:** The traceroute is hand-rolled and correct: sends ICMP Echo with incrementing TTL, parses TimeExceeded and EchoReply responses, validates ID/Seq matching. The 3-consecutive-timeout break is a reasonable heuristic.

**When to add `prometheus-community/pro-bing`:** If the project needs simple ICMP Echo (ping) as a separate probe (not traceroute), `pro-bing` provides built-in statistics (loss %, min/avg/max RTT). But for traceroute specifically, the current raw approach is appropriate and necessary.

**Permission handling:** The current code detects permission errors via `model.IsLocalPermissionError`. On Linux, recommend `sudo setcap cap_net_raw+ep ./iscan` to avoid running as root. On macOS, `sudo` is required. This is documented correctly in the current `traceprobe`.

### Concurrency Patterns

#### Current State
The scanner uses `errgroup.WithContext` with `SetLimit(options.Parallelism)` -- this is the correct pattern for concurrent target scanning. Each target is scanned sequentially by protocol layer within a single goroutine. This is the right design: parallelism is across targets, not across protocol layers for a single target (which would risk false negatives from rate limiting or IP blacklisting).

#### Recommended refinements

1. **Per-layer timeout vs per-probe timeout.** The current `timeout` applies to each individual probe. This is correct. One improvement: add a per-target total timeout (sum of expected probe durations plus margin) so a single slow target doesn't starve the errgroup's concurrency slot.

2. **Use `select` with `ctx.Done()` in retry loop.** The current `retryWithBackoff` function checks `ctx.Err()` before each attempt and uses `timer.C` in a `select` during backoff. This is correct and prevents goroutine leaks.

3. **Separate probe timeout from context timeout.** The probe timeout is the I/O deadline for a single operation. The context timeout should wrap this with retries factored in. Pattern:
   ```go
   probeCtx, probeCancel := context.WithTimeout(ctx, timeout*time.Duration(retries+1)+backoffBudget)
   defer probeCancel()
   obs := tcp.Probe(probeCtx, address, port, timeout)
   ```

4. **Use `golang.org/x/sync/semaphore` sparingly.** `errgroup.SetLimit` already provides concurrency control. Only add a semaphore if you need a separate pool (e.g., rate-limited DNS queries across all targets).

### Signal Handling

**Current pattern** (in main.go):
```go
ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
defer cancel()
```
This is the correct pattern. SIGINT (Ctrl+C) and SIGTERM gracefully cancel all probes via context propagation. The errgroup's `gCtx` is derived from this context, so all goroutines are cancelled.

### Testing Strategy

#### Unit-level testing

| Strategy | Tool / Package | Use Case |
|----------|---------------|----------|
| In-memory connection pairs | `net.Pipe()` | Test TCP/TLS probe logic without real sockets. Pair with a goroutine server to validate read/write behavior. |
| HTTP test server | `net/http/httptest` | Test HTTP probe against local server. Can inject delays, specific status codes, redirects. |
| DNS test server | `github.com/miekg/dns` (server mode) | `dns.HandleFunc` + `dns.Server` on localhost for testing DNS probe against controlled responses. |
| QUIC test server | `github.com/quic-go/quic-go` (server mode) | Create local QUIC listener for testing QUIC probe. More complex, but feasible for integration tests. |

#### Time-sensitive testing

**Go 1.24 experimental `testing/synctest`** (graduating in Go 1.25):
- Creates a "bubble" with a fake clock that advances only when all goroutines are blocked
- Eliminates flaky `time.Sleep`-based wait patterns
- For network tests: use `net.Pipe()` inside a synctest bubble as a workaround (full `httptest.SynctestServer` is proposed but not yet merged)

Current workaround (recommended for now):
```go
func TestTCPProbeTimeout(t *testing.T) {
    // Create a listener that accepts but never responds
    ln, err := net.Listen("tcp", "127.0.0.1:0")
    if err != nil {
        t.Fatal(err)
    }
    defer ln.Close()
    go func() {
        conn, _ := ln.Accept()
        _ = conn  // never read/write -- client will timeout
    }()

    ctx := context.Background()
    result := tcp.Probe(ctx, "127.0.0.1", ln.Addr().(*net.TCPAddr).Port, 100*time.Millisecond)
    if result.Success {
        t.Error("expected timeout, got success")
    }
    if result.ErrorKind != "timeout" {
        t.Errorf("expected timeout error kind, got %q", result.ErrorKind)
    }
}
```

#### Integration testing

| Scenario | Approach | Notes |
|----------|----------|-------|
| Full scan against known targets | `httptest.NewServer` + local DNS listener | Start local servers, run `scanner.Run`, verify all layers collected |
| DNS truncation | Use `miekg/dns` server that sets TC bit | Validate UDP->TCP fallback |
| TLS failure injection | Configure `crypto/tls` server with expired cert | Verify TLS probe reports success (we use `InsecureSkipVerify`) but captures cert data |
| Permission-gated ICMP | Skip test on non-Linux or check capabilities | `testing.Short()` to skip ICMP tests in CI |
| Context cancellation | Derive cancelled context, verify immediate return | Test that all probes respect ctx.Done() |

#### Mocking pattern: `net.Pipe` for TCP probe tests

```go
func TestTCPProbeWithLatency(t *testing.T) {
    server, client := net.Pipe()
    defer server.Close()
    defer client.Close()

    // Start server goroutine that delays then closes
    go func() {
        time.Sleep(10 * time.Millisecond)
        server.Close()
    }()

    // We need a listener to get an address -- so the pattern is:
    // 1. Start a real listener
    // 2. Accept one connection
    // 3. Wire pipe to simulate latency
    // OR: test the probe function's error handling separately from the dialer
}
```

**Better approach for probe testing:** Abstract the dialer behind an interface so unit tests can inject fake connections without touching the network stack:

```go
type TCPDialer interface {
    DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Real implementation wraps net.Dialer
type realDialer struct{}

func (realDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
    return net.Dialer{Timeout: timeout}.DialContext(ctx, network, address)
}

// Test implementation returns pre-made connections
type testDialer struct {
    conn net.Conn
    err  error
}

func (d testDialer) DialContext(_ context.Context, _, _ string) (net.Conn, error) {
    return d.conn, d.err
}
```

For the current codebase, this abstraction is only warranted if TCP probe testing becomes a bottleneck. Given the current straightforward implementation, acceptance-style tests against local listeners are sufficient.

### CLI UX Patterns for Diagnostic Tools

#### stdout vs stderr discipline

| Stream | Content | Implementation |
|--------|---------|---------------|
| stdout | Structured output (JSON report), summary table | `cmd.OutOrStdout()` |
| stderr | Progress indicators, warnings, errors | `cmd.ErrOrStderr()` |

**Current state:** The CLI uses `fmt.Fprintln(os.Stderr, err)` for errors and `fmt.Print(report.Summary(...))` for output. This is approximately correct: errors go to stderr, primary output to stdout. However, the code directly uses `os.Stderr` and `os.Stdout` instead of the cobra command's writer methods. This makes piped output testing harder.

**Recommended change:** In the `RunE` function, use `cmd.OutOrStdout()` and `cmd.ErrOrStderr()` instead of hard-coded `os.Stdout` / `os.Stderr`. This enables:
- Test capture via `cmd.SetOut(buf)` and `cmd.SetErr(buf)`
- Consistent behavior when cobra is used as a library

#### Output format recommendations

| Format | Flag | When | Content |
|--------|------|------|---------|
| Table (default) | no flag | TTY | Human-readable: target, layer, success/fail, latency |
| JSON | `--json` | Always available | Complete structured data including per-probe details |
| Quiet | `--quiet` | Scripting | Only exit code + errors; no summary |

**Current state:** The `--json` flag writes a JSON report to a file path. The `--summary` flag (defaulting to true) prints a terminal summary. This is reasonable. Future improvements could include:

1. **`--json` with stdout output** (not file path): `--json` writes to stdout, `--json-file path` writes to file. This makes piping to `jq` possible.
2. **`--quiet` flag**: Suppresses all output except errors. Exit code signals success/failure.
3. **`--verbose` flag**: Show per-probe results in real-time (to stderr) during scan.

#### Progress indication

For diagnostic tools, there are two schools:
1. **No progress during scan** (current approach): Run probes silently, print results as a summary table. Clean, predictable, good for scripting.
2. **Live progress to stderr** (verbose mode): Show spinner or per-target status updates.

**Recommendation:** Keep current silent-during-scan approach as default. For a future `--verbose` mode, add simplest-possible progress: write the target name to stderr when scanning starts and a checkmark/X when it completes. A full progress bar is unnecessary for a 30-second scan.

**Key principle from clig.dev:** Progress indicators MUST write to stderr and MUST be suppressed when stderr is not a terminal. Check `isatty.IsTerminal(os.Stderr.Fd())` from `github.com/mattn/go-isatty` (or simpler: check `os.Stderr` file mode).

#### Error presentation

```
# Good (actionable):
Error: target "example.com": DNS query to 8.8.8.8: connection refused

# Bad (cryptic):
Error: dial udp 8.8.8.8:53: connect: connection refused
```

Recommendations:
- Wrap errors with probe context: `fmt.Errorf("target %q: DNS query to %s: %w", target.Domain, resolver.Server, err)`
- Never show Go stack traces to end users

### Cross-Platform Considerations

| Area | macOS | Linux | Notes |
|------|-------|-------|-------|
| ICMP raw socket | Requires `sudo` | `setcap cap_net_raw+ep` or `ping_group_range` | Current traceprobe handles this with permission error detection |
| DNS (stdlib resolver) | Uses `getaddrinfo` via cgo | Uses Go's DNS resolver (no cgo) | `net.DefaultResolver` is consistent; the system DNS path is different |
| Signal handling | SIGINT, SIGTERM | Same | Already handles both |
| File paths | Case-insensitive FS | Case-sensitive | Not a concern for JSON report |
| Traceroute | ICMP Echo works (with sudo) | ICMP Echo works (with caps) | IPv4 only in current impl; IPv6 support possible with `ipv6.ICMPType` and `ip6:icmp` |

### Dependency Audit

**Current dependencies (minimal -- good):**

| Dependency | Purpose | Can remove? |
|------------|---------|-------------|
| `github.com/spf13/cobra` | CLI framework | No (core) |
| `github.com/miekg/dns` | DNS probing | No (core) |
| `github.com/quic-go/quic-go` | QUIC probing | Optional, behind `--quic` flag |
| `golang.org/x/net` | ICMP, IP-level operations | No (core for trace) |
| `golang.org/x/sync` | errgroup | No (core) |
| `golang.org/x/crypto` | (transitive from miekg/dns) | Indirect |
| `golang.org/x/mod` | (transitive from go-sync/tools) | Dev only |
| `golang.org/x/tools` | (transitive) | Dev only |

**Total direct deps: 5.** This is minimal and appropriate for a network diagnostics tool.

**No new dependencies needed for:** DoH, DoT, SOCKS5, proxy support (all available from `golang.org/x/net` or already-present packages).

**Potential future additions:**

| Library | When | Why |
|---------|------|-----|
| `github.com/prometheus-community/pro-bing` | If ICMP ping (not traceroute) becomes a separate probe | Built-in statistics, simpler API than raw x/net/icmp |
| `github.com/refraction-networking/utls` | Only if TLS fingerprinting resistance is needed | Adds significant complexity |
| `github.com/coder/websocket` | If WebSocket probing is added | Minimal dependency, context-aware, `net.Conn` wrapper |
| `github.com/mattn/go-isatty` | If progress indicators / color output are added | Tiny, widely used |

### Key Decisions and Rationale

1. **Keep miekg/dns v1.x, do not migrate to v2.x.** The v2.x (Codeberg) is pre-v1.0, not stable until ~2028. v1.1.72 is production-grade and supports all needed transports.

2. **Do not add DoH/DoT via a separate library.** `miekg/dns` v1.x supports `Net: "https"` for DoH and `Net: "tcp-tls"` for DoT. Add a transport parameter to `dnsprobe.Probe` instead of pulling in a new package.

3. **Keep quic-go at latest stable.** v0.59.0 is current. The project should `go get -u github.com/quic-go/quic-go` periodically. Watch for: v0.60+ breaking changes, and eventual migration to Go's stdlib QUIC once `x/net/quic` stabilizes.

4. **Use `golang.org/x/net/proxy` for SOCKS5 support.** It implements `ContextDialer` (unlike some SOCKS5 libraries), integrates with `net.Dialer`, and is zero new deps for this project (already depends on `golang.org/x/net`).

5. **Abstract dialers only when justified.** The current code's direct use of `net.Dialer` is fine. Adding a `Dialer` interface to each probe package makes testing easier but adds complexity. Do it per-package as tests require it, not preemptively.

## Alternatives Considered

| Category | Recommended | Alternative | Why Not |
|----------|-------------|-------------|---------|
| DNS library | `miekg/dns` v1.x | `github.com/AdguardTeam/dnsproxy` | dnsproxy is a full proxy, too heavy for a probing library. miekg/dns is more flexible and widely used. |
| QUIC library | `quic-go` | `x/net/quic` (stdlib) | x/net/quic is experimental, incomplete, not production-ready. quic-go is battle-tested. |
| ICMP ping | Current raw x/net/icmp | `prometheus-community/pro-bing` | Current implementation is traceroute, not ping. If simple ping is added, pro-bing is a good addition. |
| CLI framework | `cobra` | `charmbracelet/bubbletea` | bubbletea is TUI-focused, not CLI. cobra is the standard for command-line tools. |
| JSON output | Manual encoding | `go-json` or goccy/go-json | Stdlib `encoding/json` is sufficient for this scale. |
| Error classification | errors.Is + syscall | String matching only | errors.Is is more portable. Current code does both (correct). |

## Installation

```bash
# Current dependencies
go get github.com/miekg/dns@latest
go get github.com/quic-go/quic-go@latest
go get github.com/spf13/cobra@latest
go get golang.org/x/net@latest
go get golang.org/x/sync@latest

# For ICMP raw socket capability on Linux (after build)
sudo setcap cap_net_raw+ep ./iscan

# Development only
go install golang.org/x/tools/cmd/goimports@latest
```

## Sources

- miekg/dns documentation: https://pkg.go.dev/github.com/miekg/dns
- quic-go documentation: https://quic-go.net/docs/
- OONI Probe architecture: https://pkg.go.dev/github.com/ooni/probe-cli/v3/internal/netxlite
- clig.dev CLI guidelines: https://clig.dev
- Go testing/synctest proposal: https://go.googlesource.com/proposal/+/master/design/64318-synctest.md
- Go net/http/httptest package: https://pkg.go.dev/net/http/httptest
- Go context timeout patterns: https://go.dev/blog/context
- golang.org/x/net/proxy SOCKS5: https://pkg.go.dev/golang.org/x/net/proxy
- Go-ping library comparison: https://blog.csdn.net/gitblog_00025/article/details/137628039
- testing/nettest proposal: https://github.com/golang/go/issues/77362
