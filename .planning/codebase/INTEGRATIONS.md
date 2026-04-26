# External Integrations

**Analysis Date:** 2026-04-26

## APIs & External Services

**No external HTTP/REST APIs are consumed.** The tool performs direct network probes rather than querying external APIs. There is no SDK-based integration with any third-party cloud service, monitoring platform, or data provider.

**DNS Resolvers (hardcoded in `internal/targets/targets.go`):**
- Cloudflare DNS: `1.1.1.1:53` (UDP/TCP DNS queries via DNS wire protocol)
- Google DNS: `8.8.8.8:53` (UDP/TCP DNS queries via DNS wire protocol)
- Quad9 DNS: `9.9.9.9:53` (UDP/TCP DNS queries via DNS wire protocol)
- System resolver (`net.DefaultResolver`) -- used for reference/system baseline queries, not an external service

**Web Targets (hardcoded in `internal/targets/targets.go`):**
- `example.com` (port 443, QUIC port 443) -- control target
- `cloudflare.com` (port 443, QUIC port 443) -- control target
- `www.google.com` (port 443, QUIC port 443) -- diagnostic target with SNI comparison
- `example.net` (port 443, no QUIC) -- control target for no-QUIC baseline

## Network Protocols

**DNS (Layer 3/7):**
- Protocol: DNS wire format over UDP (default) with automatic TCP fallback on truncation
- Record types: A (IPv4) and AAAA (IPv6) queries
- EDNS0: Enabled with 1232-byte payload (`dnsprobe/dns.go` line 23)
- Library: `github.com/miekg/dns v1.1.72` -- direct resolver communication, not via system resolver (except for the "system" resolver entry which uses `net.DefaultResolver`)

**TCP (Layer 4):**
- Raw TCP dial using `net.Dialer` with configurable timeout
- No external library; uses Go standard library `net` package
- Error classification for: timeout, refused, reset, unreachable (`internal/probe/tcp/tcp.go` lines 43-69)

**TLS (Layer 5):**
- TLS 1.2 and 1.3 handshake detection via `crypto/tls` standard library
- SNI (Server Name Indication) set per-probe
- ALPN negotiation: `["h2", "http/1.1"]`
- Certificate fingerprinting: SHA-256 of leaf certificate
- InsecureSkipVerify=true for all probes (no CA verification)
- Go standard library `crypto/tls`, `crypto/sha256`

**HTTP (Layer 7):**
- HTTP GET requests with redirects disabled (`http.ErrUseLastResponse`)
- Uses `net/http/httptrace` to measure DNS lookup, TCP connect, TLS handshake, and first-byte latencies separately
- Insecure TLS verification (accepts self-signed certs)
- Go standard library `net/http`

**QUIC (Layer 4+):**
- QUIC v1 and v2 handshake detection
- ALPN: `["h3"]`
- Certificate SHA-256 fingerprinting
- Library: `github.com/quic-go/quic-go v0.59.0` -- third-party QUIC implementation in Go

**ICMP/Traceroute (Layer 3):**
- Raw ICMP echo probes with incrementing TTL (1-30)
- Requires elevated privileges (operation not permitted gracefully handled as warning)
- Library: `golang.org/x/net/icmp` and `golang.org/x/net/ipv4`

## Data Storage

**Databases:**
- None. No database connections, ORM, or storage backend.

**File Storage:**
- Local filesystem only. JSON report written to a user-specified file path via `--json` flag.
- Output format: JSON with `json.MarshalIndent` (pretty-printed).

**Caching:**
- None. All probes are real-time with no caching layer.

## Authentication & Identity

**Auth Provider:**
- None. No authentication, API keys, tokens, or identity management.
- The `--json` output file permission is set to `0o644`.

## Monitoring & Observability

**Error Tracking:**
- None. Errors are recorded inline in probe observations and surfaced in CLI output.

**Logs:**
- Standard output only. Terminal summary via `fmt.Fprint`/`fmt.Fprintf`.
- Warnings printed to stderr via `fmt.Fprintln(os.Stderr, err)` for CLI-level failures.
- No structured logging, no log levels, no log files.

## CI/CD & Deployment

**Hosting:**
- No hosting configured. CLI tool distributed as a Go binary.

**CI Pipeline:**
- None detected. No GitHub Actions, no CI configuration files.

## Environment Configuration

**Required env vars:**
- None. All configuration is via CLI flags (`--timeout`, `--retries`, `--json`, `--trace`, `--quic`, `--summary`, `--target-set`, `--analyze`).

**Secrets location:**
- N/A. No secrets, API keys, or tokens are used.

## Webhooks & Callbacks

**Incoming:**
- None. This is a CLI tool with no server component.

**Outgoing:**
- None. The tool does not register or call any webhooks.

## Configuration Summary

All integration configuration is hardcoded at compile time in `internal/targets/targets.go`:
- **Resolver list** (lines 46-53): `1.1.1.1:53`, `8.8.8.8:53`, `9.9.9.9:53`, plus system resolver
- **Target list** (lines 5-43): `example.com`, `cloudflare.com`, `www.google.com`, `example.net`
- These are not configurable at runtime; the `--target-set` flag only accepts `"builtin"` currently

---

*Integration audit: 2026-04-26*
