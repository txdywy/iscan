# iscan

`iscan` is a layered network diagnostics CLI. It runs DNS, TCP, TLS, HTTP,
and optional privileged trace probes against a builtin target set, then emits
both a terminal summary and a structured JSON report.

The tool is intentionally conservative: findings are evidence-backed signals
such as `dns_inconsistent`, `tcp_connect_failure`, or
`sni_correlated_failure`. It does not make absolute censorship claims from a
single failed probe.

## Usage

```bash
go run ./cmd/iscan scan --summary --json /tmp/iscan-report.json
```

Useful flags:

```bash
--timeout 5s          per-probe timeout
--retries 3           retry failed TCP/TLS/HTTP probes
--trace=true          enable privileged ICMP traceroute-style probing
--target-set builtin  use the builtin target and resolver set
```

If trace requires permissions unavailable to the current user, `iscan` records
a warning and continues the scan.

## Development

```bash
go test ./...
```
