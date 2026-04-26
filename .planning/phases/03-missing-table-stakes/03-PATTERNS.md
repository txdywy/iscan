# Phase 3: Missing Table Stakes - Pattern Map

**Mapped:** 2026-04-26
**Files analyzed:** 11 (2 new, 9 modified)
**Analogs found:** 11 / 11

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `internal/probe/icmpping/icmp.go` (NEW) | probe | request-response | `internal/probe/traceprobe/trace.go` | exact |
| `internal/probe/icmpping/adapter.go` (NEW) | adapter | request-response | `internal/probe/traceprobe/adapter.go` | exact |
| `internal/model/model.go` (MODIFY) | model | CRUD | same file (existing types) | exact |
| `internal/targets/targets.go` (MODIFY) | service | CRUD | same file (existing functions) | exact |
| `internal/scanner/scanner.go` (MODIFY) | service | CRUD | same file (existing buildProbes) | exact |
| `cmd/iscan/main.go` (MODIFY) | controller | request-response | same file (existing cobra commands) | exact |
| `internal/probe/traceprobe/trace.go` (MODIFY) | probe | request-response | same file (existing ICMP patterns) | exact |
| `internal/probe/dnsprobe/dns.go` (MODIFY) | probe | request-response | same file (existing DNS query patterns) | exact |
| `internal/probe/tcp/tcp.go` (MODIFY) | probe | request-response | same file (existing TCP dial patterns) | exact |
| `internal/probe/tlsprobe/tls.go` (MODIFY) | probe | request-response | same file (existing TLS dial patterns) | exact |
| `internal/probe/quicprobe/quic.go` (MODIFY) | probe | request-response | same file (existing QUIC dial patterns) | exact |

## Pattern Assignments

### `internal/probe/icmpping/icmp.go` (probe, request-response) [NEW]

**Analog:** `internal/probe/traceprobe/trace.go` (lines 1-165)

**Purpose:** Single ICMP echo probe akin to a single-hop traceroute. Send one ICMP Echo request, wait for reply, measure RTT and TTL.

**Imports pattern** (traceprobe/trace.go lines 3-15):
```go
import (
    "context"
    "net"
    "time"

    "golang.org/x/net/icmp"
    "golang.org/x/net/ipv4"

    "iscan/internal/model"
)
```

**Package declaration and function signature pattern** (traceprobe/trace.go lines 17-19):
```go
package icmpping

func Probe(ctx context.Context, target string, timeout time.Duration) model.PingObservation {
```

**ICMP socket creation pattern** (traceprobe/trace.go lines 40-47) — same permission handling:
```go
conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
if err != nil {
    observation.Error = err.Error()
    return observation
}
defer func() {
    _ = conn.Close()
}()
```

**ICMP echo message construction pattern** (traceprobe/trace.go lines 101-109):
```go
message := icmp.Message{
    Type: ipv4.ICMPTypeEcho,
    Code: 0,
    Body: &icmp.Echo{
        ID:   probeID,
        Seq:  seq,
        Data: []byte("iscan"),
    },
}
bytes, err := message.Marshal(nil)
if err != nil {
    return model.PingObservation{Target: target, Error: err.Error()}
}
```

**Read deadline and write pattern** (traceprobe/trace.go lines 115-127):
```go
_ = conn.SetDeadline(time.Now().Add(timeout))
sent := time.Now()
if _, err := conn.WriteTo(bytes, &net.IPAddr{IP: ip}); err != nil {
    return model.PingObservation{Target: target, Error: err.Error()}
}
reply := make([]byte, 1500)
n, peer, err := conn.ReadFrom(reply)
if err != nil {
    if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
        return model.PingObservation{Target: target, Error: "read timeout"}
    }
    return model.PingObservation{Target: target, Error: err.Error()}
}
```

**ICMP reply parsing and EchoReply detection pattern** (traceprobe/trace.go lines 128-163):
```go
parsed, err := icmp.ParseMessage(1, reply[:n])
if err != nil {
    return model.PingObservation{Target: target, Address: peer.String(), Error: err.Error()}
}
switch body := parsed.Body.(type) {
case *icmp.Echo:
    if body.ID == probeID {
        return model.PingObservation{
            Target:  target,
            Address: peer.String(),
            RTT:     time.Since(sent),
            TTL:     parsedTTL, // extracted from IP header
            Success: true,
        }
    }
}
```

**TTL extraction from IP header pattern** (new — traceprobe extracts from payload, Ping can extract via ipv4.Header):
```go
// Use ipv4.ParseHeader on the IP portion of the reply to extract TTL.
// Alternatively, the default TTL (64 or 128) can be reported.
```

**Graceful permission error handling pattern** (traceprobe/trace.go lines 41-44 + model/errors.go lines 14-17):
```go
if err != nil {
    if model.IsLocalPermissionError(err.Error()) {
        // Return observation with clear warning, don't panic
    }
    observation.Error = err.Error()
    return observation
}
```

**Observation return with latency defer pattern** (traceprobe/trace.go lines 17-21):
```go
func Probe(ctx context.Context, target string, timeout time.Duration) (observation model.PingObservation) {
    start := time.Now()
    observation = model.PingObservation{Target: target}
    defer func() {
        observation.Latency = time.Since(start)
    }()
```

**Test pattern** — analogous to `internal/model/errors_test.go` lines 9-27 (table-driven tests):
```go
package icmpping_test

import (
    "testing"
    "time"

    "iscan/internal/model"
    "iscan/internal/probe/icmpping"
)

func TestPing(t *testing.T) {
    cases := []struct {
        name    string
        target  string
        timeout time.Duration
    }{
        // NOTE: actual ICMP ping requires privileges; test may be a compile check
    }
    for _, c := range cases {
        t.Run(c.name, func(t *testing.T) {
            // ...
        })
    }
}
```

---

### `internal/probe/icmpping/adapter.go` (adapter, request-response) [NEW]

**Analog:** `internal/probe/traceprobe/adapter.go` (lines 1-27)

**Imports and package pattern** (traceprobe/adapter.go lines 1-9):
```go
package icmpping

import (
    "context"

    "iscan/internal/model"
    "iscan/internal/probe"
)
```

**Opts + Adapter + Run + init() pattern** (traceprobe/adapter.go lines 10-27 — exact copy target):
```go
type PingOpts struct {
    Timeout time.Duration
}

type Adapter struct {
    Opts PingOpts
}

func (a *Adapter) Run(ctx context.Context, target model.Target) model.ProbeResult {
    obs := Probe(ctx, target.Domain, a.Opts.Timeout)
    return probe.NewResult(model.LayerPing, obs)
}

func init() {
    probe.Registry[model.LayerPing] = &Adapter{
        Opts: PingOpts{Timeout: 5 * time.Second},
    }
}
```

**Import ordering pattern** — three-group: stdlib / third-party / internal:
```go
import (
    "context"
    "time"

    "golang.org/x/net/icmp"
    "golang.org/x/net/ipv4"

    "iscan/internal/model"
    "iscan/internal/probe"
)
```

---

### `internal/model/model.go` (MODIFY, model, CRUD)

**Analog:** Same file — existing type definition patterns (lines 1-179)

**Layer constant pattern** (lines 7-14) — add `LayerPing`:
```go
const (
    LayerDNS   Layer = "dns"
    LayerTCP   Layer = "tcp"
    LayerTLS   Layer = "tls"
    LayerHTTP  Layer = "http"
    LayerQUIC  Layer = "quic"
    LayerTrace Layer = "trace"
    LayerPing  Layer = "ping"   // NEW
)
```

**PingObservation struct pattern** — follow `TraceHop` struct pattern (lines 165-171) since PingObservation has overlapping fields:
```go
type PingObservation struct {
    Target  string        `json:"target"`
    Address string        `json:"address,omitempty"`
    RTT     time.Duration `json:"rtt,omitempty"`
    TTL     int           `json:"ttl,omitempty"`
    Latency time.Duration `json:"latency"`
    Success bool          `json:"success"`
    Error   string        `json:"error,omitempty"`
}
```

**Target.AddressFamily field pattern** — follow existing `Target` struct convention (lines 38-47):
```go
type Target struct {
    Name          string   `json:"name"`
    Domain        string   `json:"domain"`
    Scheme        string   `json:"scheme"`
    Ports         []int    `json:"ports"`
    Control       bool     `json:"control"`
    HTTPPath      string   `json:"http_path"`
    CompareSNI    []string `json:"compare_sni,omitempty"`
    QUICPort      int      `json:"quic_port,omitempty"`
    AddressFamily string   `json:"address_family,omitempty"`  // NEW: "ipv4", "ipv6", or ""
}
```

**JSON struct tag conventions** (lines 38-47 and 165-171) — lowercase snake_case, `omitempty` on optional fields. All new fields follow this.

---

### `internal/targets/targets.go` (MODIFY, service, CRUD)

**Analog:** Same file — existing function and type patterns (lines 1-53)

**TargetSource interface pattern** — new interface definition following Go conventions:
```go
package targets

import "iscan/internal/model"

// TargetSource abstracts loading of scan targets.
type TargetSource interface {
    Load() ([]model.Target, error)
}
```

**BuiltinSource pattern** — wraps existing `BuiltinTargets()` in the interface:
```go
type BuiltinSource struct{}

func (BuiltinSource) Load() ([]model.Target, error) {
    return BuiltinTargets(), nil
}
```

**FileSource pattern** — reads JSON file, validates each target, using existing `model.Target.Validate()` pattern (model.go lines 49-63):
```go
type FileSource struct {
    Path string
}

func (f FileSource) Load() ([]model.Target, error) {
    data, err := os.ReadFile(f.Path)
    if err != nil {
        return nil, fmt.Errorf("reading target set %q: %w", f.Path, err)
    }
    var targets []model.Target
    if err := json.Unmarshal(data, &targets); err != nil {
        return nil, fmt.Errorf("parsing target set %q: %w", f.Path, err)
    }
    for i := range targets {
        if err := targets[i].Validate(); err != nil {
            return nil, fmt.Errorf("target %d (%s): %w", i, targets[i].Name, err)
        }
    }
    return targets, nil
}
```

**IPv6 resolvers addition pattern** — extend `BuiltinResolvers()` (lines 46-53):
```go
func BuiltinResolvers() []model.Resolver {
    return []model.Resolver{
        {Name: "system", System: true},
        {Name: "cloudflare", Server: "1.1.1.1:53"},
        {Name: "google", Server: "8.8.8.8:53"},
        {Name: "quad9", Server: "9.9.9.9:53"},
        {Name: "cloudflare-ipv6", Server: "[2606:4700:4700::1111]:53"},   // NEW
        {Name: "google-ipv6", Server: "[2001:4860:4860::8888]:53"},       // NEW
        {Name: "quad9-ipv6", Server: "[2620:fe::fe]:53"},                 // NEW
    }
}
```

**Imports for FileSource pattern** — adding `encoding/json`, `fmt`, `os`, `path/filepath`:
```go
import (
    "encoding/json"
    "fmt"
    "os"

    "iscan/internal/model"
)
```

---

### `internal/scanner/scanner.go` (MODIFY, service, CRUD)

**Analog:** Same file — existing `buildProbes()` (lines 91-119), `Run()` (lines 25-89)

**LayerPing addition to buildProbes pattern** (lines 91-119) — add after LayerTLS, before LayerHTTP:
```go
func buildProbes(options model.ScanOptions) []probe.Probe {
    var probes []probe.Probe
    timeout := options.Timeout

    add := func(layer model.Layer) {
        p, ok := probe.Registry[layer]
        if !ok {
            return
        }
        p = middleware.Chain(p,
            middleware.Timeout(timeout),
            middleware.Retry(options.Retries, 500*time.Millisecond),
            middleware.Logging(nil),
        )
        probes = append(probes, p)
    }

    add(model.LayerDNS)
    add(model.LayerTCP)
    add(model.LayerTLS)
    if options.ICMPPing {                    // NEW
        add(model.LayerPing)                 // NEW
    }                                        // NEW
    add(model.LayerHTTP)
    if options.QUIC {
        add(model.LayerQUIC)
    }
    if options.Trace {
        add(model.LayerTrace)
    }
    return probes
}
```

**ScanOptions.ICMPPing field in model** — add field to model.ScanOptions (model.go lines 71-77):
```go
type ScanOptions struct {
    Timeout     time.Duration `json:"timeout"`
    Retries     int           `json:"retries"`
    Trace       bool          `json:"trace"`
    QUIC        bool          `json:"quic"`
    ICMPPing    bool          `json:"icmp_ping,omitempty"`   // NEW
    Parallelism int           `json:"parallelism"`
}
```

**TargetSource selection pattern** — in `Run()` (lines 25-89), replace direct `targets.BuiltinTargets()` call:
```go
// Before:
targetList := targets.BuiltinTargets()

// After:
var source targets.TargetSource
if options.TargetSet != "" {
    source = targets.FileSource{Path: options.TargetSet}
} else {
    source = targets.BuiltinSource{}
}
targetList, err := source.Load()
if err != nil {
    // wrap result with error
}
```

**Ping warning suppression pattern** — follow existing trace permission warning pattern (lines 75-83):
```go
for _, pr := range result.Results {
    if pr.Layer == model.LayerPing {
        if obs, ok := pr.Data.(model.PingObservation); ok && !obs.Success {
            if model.IsLocalPermissionError(obs.Error) {
                report.Warnings = append(report.Warnings, targetList[i].Domain+": ping unavailable: "+obs.Error)
            }
        }
    }
}
```

---

### `cmd/iscan/main.go` (MODIFY, controller, request-response)

**Analog:** Same file — existing cobra command patterns (lines 1-103)

**Cobra subcommand pattern** (lines 37-44 show `cmd` construction; lines 45-92 show `scanCmd`):
```go
pingCmd := &cobra.Command{
    Use:   "ping <target>",
    Short: "ICMP ping a target and print RTT + TTL",
    Args:  cobra.ExactArgs(1),
    RunE: func(cmd *cobra.Command, args []string) error {
        target := args[0]
        ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
        defer cancel()
        obs := icmpping.Probe(ctx, target, pingTimeout)
        fmt.Printf("PING %s (%s): rtt=%s ttl=%d\n", target, obs.Address, obs.RTT, obs.TTL)
        if !obs.Success {
            return fmt.Errorf("ping failed: %s", obs.Error)
        }
        return nil
    },
}
pingCmd.Flags().DurationVar(&pingTimeout, "timeout", 5*time.Second, "ping timeout")
```

**Registration pattern** (lines 101-102 shows `cmd.AddCommand(scanCmd)`):
```go
cmd.AddCommand(scanCmd)
cmd.AddCommand(pingCmd)   // NEW
```

**--icmp-ping flag addition to scanCmd** (lines 93-100 show flag pattern):
```go
scanCmd.Flags().BoolVar(&icmpPing, "icmp-ping", false, "enable ICMP ping probe")
```

**Import addition pattern** (lines 3-18):
```go
import (
    "context"
    "fmt"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/spf13/cobra"

    "iscan/internal/model"
    "iscan/internal/probe/icmpping"   // NEW
    "iscan/internal/profile"
    "iscan/internal/recommend"
    "iscan/internal/report"
    "iscan/internal/scanner"
)
```

**Variable declaration pattern** (lines 28-35):
```go
var pingTimeout time.Duration   // NEW
var icmpPing bool                // NEW
```

---

### `internal/probe/traceprobe/trace.go` (MODIFY, probe, request-response)

**Analog:** Same file — existing ICMP patterns (lines 1-164)

**IPv6 ICMP ListenPacket pattern** — add alternative ICMPv6 socket creation (around line 40):
```go
var conn *icmp.PacketConn
if ip.To4() != nil {
    conn, err = icmp.ListenPacket("ip4:icmp", "0.0.0.0")
} else {
    conn, err = icmp.ListenPacket("ip6:icmp", "::")
}
if err != nil {
    observation.Error = err.Error()
    return observation
}
defer func() { _ = conn.Close() }()
```

**IPv6 IP resolution pattern** — modify resolution to prefer target AddressFamily (around lines 23-34):
```go
ips, err := net.LookupIP(target)
if err != nil {
    observation.Error = err.Error()
    return observation
}
var ip net.IP
for _, candidate := range ips {
    if options.AddressFamily == "ipv6" && candidate.To4() == nil {
        ip = candidate
        break
    }
    if options.AddressFamily == "ipv4" && candidate.To4() != nil {
        ip = candidate
        break
    }
}
if ip == nil {
    // fallback: pick any
    for _, candidate := range ips {
        if candidate.To4() != nil {
            ip = candidate
            break
        }
    }
    if ip == nil && len(ips) > 0 {
        ip = ips[0]
    }
}
if ip == nil {
    observation.Error = "no IP address for trace"
    return observation
}
```

**ICMPv6 message type pattern** — use `ipv6.ICMPTypeEchoRequest` instead of `ipv4.ICMPTypeEcho` (around lines 101-108):
```go
var msgType icmp.Type
if ip.To4() != nil {
    msgType = ipv4.ICMPTypeEcho
} else {
    msgType = ipv6.ICMPTypeEchoRequest
}
message := icmp.Message{
    Type: msgType,
    Code: 0,
    Body: &icmp.Echo{...},
}
```

**ICMPv6 ParseMessage pattern** — use protocol number 58 for IPv6 instead of 1 (around line 128):
```go
proto := 1   // ICMP for IPv4
if ip.To4() == nil {
    proto = 58  // ICMPv6
}
parsed, err := icmp.ParseMessage(proto, reply[:n])
```

**ICMPv6 TimeExceeded type pattern** — use `ipv6.ICMPTypeTimeExceeded`:
```go
import "golang.org/x/net/ipv6"

// In the type switch:
case *icmp.TimeExceeded:
    // Already works for both IPv4 and IPv6 — icmp.TimeExceeded body is the same
```

**Import addition** — add `"golang.org/x/net/ipv6"` to imports.

---

### `internal/probe/dnsprobe/dns.go` (MODIFY, probe, request-response)

**Analog:** Same file — existing DNS query patterns (lines 1-91)

**AAAA query addition pattern** — `Probe()` already handles AAAA answers in its response parsing (lines 39-48), so the main change is to add a separate AAAA query call alongside A.

**Dual-stack DNS query pattern** (around line 14, or create a new function):
```go
func ProbeAAAA(ctx context.Context, resolver model.Resolver, domain string, timeout time.Duration) model.DNSObservation {
    return Probe(ctx, resolver, domain, mdns.TypeAAAA, timeout)
}
```

**DNS resolver selection by IP version** — when using IPv6 resolvers, modify the client net:
```go
// In Probe(), when server is an IPv6 address, use "udp6" network
client := &mdns.Client{Net: "udp", Timeout: timeout}
if strings.Contains(server, "]:") || strings.HasPrefix(server, "[") {
    client.Net = "udp6"
}
```

---

### `internal/probe/tcp/tcp.go` (MODIFY, probe, request-response)

**Analog:** Same file — existing TCP dial patterns (lines 1-69)

**IPv6 dial pattern** — `Probe()` already uses `net.Dialer.DialContext` which supports IPv6 natively. The change is to modify the `target.Domain` resolution to try both A and AAAA records.

**Dual-stack dial pattern** (around line 16-41):
```go
func Probe(ctx context.Context, host string, port int, timeout time.Duration) model.TCPObservation {
    address := net.JoinHostPort(host, strconv.Itoa(port))
    start := time.Now()
    dialer := net.Dialer{Timeout: timeout}

    // Try IPv4 first, then IPv6 (or vice versa based on target config)
    // net.Dialer with "tcp" network does dual-stack automatically,
    // but we may want explicit control per target.
    conn, err := dialer.DialContext(ctx, "tcp", address)
    // ... (rest unchanged)
}
```

The existing code already works with IPv6 addresses passed as `host`. The `net.JoinHostPort` handles IPv6 bracketing automatically when the host contains a colon. No structural change needed — the function naturally supports IPv6.

---

### `internal/probe/tlsprobe/tls.go` (MODIFY, probe, request-response)

**Analog:** Same file — existing TLS dial patterns (lines 1-79)

**SNI handling for IPv6 pattern** — `tls.Config.ServerName` now needs to pass the target SNI name (hostname), not the resolved IP address. The existing code (line 20) already uses `sni` parameter for `ServerName`, which accepts hostnames or IPs.

**IPv6 address in SNI** — `crypto/tls` does not perform DNS lookups for SNI, so passing a hostname works fine:
```go
// Existing pattern (lines 19-25) — no change needed for SNI:
cfg := &tls.Config{
    ServerName:     sni,    // This is the original hostname, works with IPv6
    NextProtos:     nextProtos,
    InsecureSkipVerify: insecureSkipVerify,
}
```

For IPv6 addresses as SNI, strip brackets:
```go
if strings.HasPrefix(sni, "[") && strings.HasSuffix(sni, "]") {
    sni = sni[1 : len(sni)-1]
}
```

The existing code already uses `net.JoinHostPort` which properly brackets IPv6 addresses. No structural change needed for basic IPv6 support.

---

### `internal/probe/quicprobe/quic.go` (MODIFY, probe, request-response)

**Analog:** Same file — existing QUIC dial patterns (lines 1-74)

**IPv6 address handling pattern** — `quic.DialAddr` accepts string addresses. The existing `net.JoinHostPort(host, strconv.Itoa(port))` already handles IPv6 bracketing. No structural change needed.

**Verify quic-go IPv6 support** (around line 34) — quic-go supports IPv6 natively, `quic.DialAddr` resolves both address families:
```go
// Existing pattern (line 34):
conn, err := quic.DialAddr(ctx, address, tlsConf, quicConf)
// This already works for IPv6 addresses passed as host
```

Existing code is IPv6-compatible without changes.

---

## Shared Patterns

### ICMP Socket Creation and Error Handling
**Source:** `internal/probe/traceprobe/trace.go` lines 40-47
**Apply to:** `internal/probe/icmpping/icmp.go`, `internal/probe/traceprobe/trace.go` (ICMPv6 path)
```go
conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
if err != nil {
    observation.Error = err.Error()
    return observation
}
defer func() { _ = conn.Close() }()
```

### Permission Error Handling
**Source:** `internal/model/errors.go` lines 14-17, `internal/scanner/scanner.go` lines 75-83
**Apply to:** `internal/probe/icmpping/icmp.go`, `internal/scanner/scanner.go`
```go
if model.IsLocalPermissionError(obs.Error) {
    report.Warnings = append(report.Warnings, "ping unavailable: "+obs.Error)
}
```

### Adapter + init() Registration
**Source:** `internal/probe/traceprobe/adapter.go` lines 10-27, `internal/probe/dnsprobe/adapter.go` lines 12-36
**Apply to:** `internal/probe/icmpping/adapter.go`
```go
type PingOpts struct {
    Timeout time.Duration
}
type Adapter struct {
    Opts PingOpts
}
func (a *Adapter) Run(ctx context.Context, target model.Target) model.ProbeResult {
    obs := Probe(ctx, target.Domain, a.Opts.Timeout)
    return probe.NewResult(model.LayerPing, obs)
}
func init() {
    probe.Registry[model.LayerPing] = &Adapter{
        Opts: PingOpts{Timeout: 5 * time.Second},
    }
}
```

### JSON Struct Tag Conventions
**Source:** `internal/model/model.go` lines 38-47, 165-171
**Apply to:** All new and modified types — lowercase snake_case, `omitempty` on optional fields.
```go
AddressFamily string `json:"address_family,omitempty"`
```

### Import Organization (Three-Group)
**Source:** All Go files — stdlib / third-party / internal separated by blank lines. Example from `internal/scanner/scanner.go` lines 3-23.
**Apply to:** All new and modified files.

### Cobra Command and Flag Registration
**Source:** `cmd/iscan/main.go` lines 37-103
**Apply to:** `cmd/iscan/main.go` (ping subcommand, --icmp-ping flag)
```go
pingCmd := &cobra.Command{
    Use:   "ping <target>",
    Short: "ICMP ping a target and print RTT + TTL",
    Args:  cobra.ExactArgs(1),
    RunE: func(cmd *cobra.Command, args []string) error { ... },
}
pingCmd.Flags().DurationVar(&pingTimeout, "timeout", 5*time.Second, "ping timeout")
cmd.AddCommand(pingCmd)
```

### Table-Driven Test Pattern
**Source:** `internal/model/errors_test.go` lines 9-27
**Apply to:** `internal/probe/icmpping/icmpping_test.go`, `internal/targets/targets_test.go`
```go
cases := []struct {
    name   string
    input  string
    want   bool
}{
    {"case name", "some input", true},
}
for _, c := range cases {
    t.Run(c.name, func(t *testing.T) {
        got := fn(c.input)
        if got != c.want {
            t.Errorf("got %v, want %v", got, c.want)
        }
    })
}
```

### Probe Registration via init() Side-Effect Import
**Source:** `internal/probe/traceprobe/adapter.go` lines 24-26, `internal/scanner/scanner.go` lines 11-16
**Apply to:** `internal/scanner/scanner.go` — import icmpping for side effect
```go
import (
    _
    // Add:
    _ "iscan/internal/probe/icmpping"
)
```

### Dual-Stack Address Resolution
**Source:** `internal/probe/traceprobe/trace.go` lines 23-34
**Apply to:** All probes needing IPv6 support — resolve both A and AAAA records, select based on `Target.AddressFamily`.
```go
ips, err := net.LookupIP(target)
if err != nil {
    return observation
}
var ip net.IP
for _, candidate := range ips {
    if target.AddressFamily == "ipv6" && candidate.To4() == nil {
        ip = candidate
        break
    }
    if target.AddressFamily == "ipv4" && candidate.To4() != nil {
        ip = candidate
        break
    }
}
if ip == nil {
    // fallback
}
```

### DNS AAAA Query (Existing, Already Handled)
**Source:** `internal/probe/dnsprobe/dns.go` lines 39-48 — the response parser already handles AAAA records:
```go
case *mdns.AAAA:
    observation.Answers = append(observation.Answers, rr.AAAA.String())
```
The change is to also call `Probe()` with `mdns.TypeAAAA` for dual-stack support.

---

## No Analog Found

All 11 files have exact or same-file analogs. No new patterns requiring analog-free construction.

---

## Metadata

**Analog search scope:** `internal/model/`, `internal/targets/`, `internal/scanner/`, `cmd/iscan/`, `internal/probe/*/`, `internal/probe/middleware/`
**Files scanned:** 15 Go source files, 2 Go test files, 1 Phase 2 PATTERNS.md reference
**Pattern extraction date:** 2026-04-26
