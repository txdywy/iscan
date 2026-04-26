# Testing Patterns

**Analysis Date:** 2026-04-26

## Test Framework

**Runner:**
- Standard Go `testing` package (Go 1.24.0)
- No external test runner (no Jest, Ginkgo, testify, etc.)
- Config: No test config file -- tests use the Go toolchain default

**Assertion Library:**
- Standard `testing.T` methods only: `t.Fatal`/`t.Fatalf`, `t.Errorf`, `t.Log`, `t.Helper`, `t.Cleanup`, `t.Run`
- No external assertion libraries (no testify, no assert/require)

**Run Commands:**
```bash
go test ./...              # Run all tests
go test -v ./internal/...  # Verbose for a subtree
```

## Test File Organization

**Location:**
- Co-located `_test.go` files in the same directory as the source package
- Every package directory with source code has a corresponding test file (except `targets/` and `cmd/iscan/`)

**Naming:**
- Test files mirror source file names with `_test` suffix:
  ```
  internal/classifier/
    classifier.go
    classifier_test.go
  internal/probe/dnsprobe/
    dns.go
    dns_test.go
  ```

**All test files:**
```
internal/classifier/classifier_test.go
internal/model/errors_test.go
internal/probe/dnsprobe/dns_test.go
internal/probe/httpprobe/http_test.go
internal/probe/quicprobe/quic_test.go
internal/probe/tcp/tcp_test.go
internal/probe/tlsprobe/tls_test.go
internal/profile/profile_test.go
internal/recommend/recommend_test.go
internal/report/report_test.go
internal/scanner/scanner_test.go
```

## Package Convention

**External test packages** (`package foo_test`) are used throughout. Every test file uses external test package naming:

```go
package classifier_test   // in internal/classifier/classifier_test.go
package dnsprobe_test     // in internal/probe/dnsprobe/dns_test.go
package scanner_test      // in internal/scanner/scanner_test.go
```

This enforces testing through the exported API only and prevents access to unexported symbols, ensuring tests validate public contract behavior.

## Test Structure

**Suite Organization:**
Each test file contains standalone `TestXxx` functions -- no test suites, no `TestMain` functions, no setup/teardown functions at the package level.

**Patterns:**
- **Table-driven tests** used in two locations:
  ```go
  // model/errors_test.go:9-26
  func TestIsLocalPermissionError(t *testing.T) {
      cases := []struct {
          input string
          want  bool
      }{
          {"operation not permitted", true},
          {"Permission denied", true},
          {"PERMISSION DENIED", true},
          {"some other error", false},
          {"", false},
          {"operation not", false},
      }
      for _, c := range cases {
          got := model.IsLocalPermissionError(c.input)
          if got != c.want {
              t.Errorf("IsLocalPermissionError(%q) = %v, want %v", c.input, got, c.want)
          }
      }
  }
  ```
  ```go
  // model/errors_test.go:29-52
  func TestTargetValidate(t *testing.T) {
      cases := []struct {
          name    string
          target  model.Target
          wantErr bool
      }{...}
      for _, c := range cases {
          t.Run(c.name, func(t *testing.T) {
              err := c.target.Validate()
              ...
          })
      }
  }
  ```
- **Given/when/then style** via function naming: tests are named as complete sentences describing the scenario being validated (e.g., `TestClassifyKeepsSingleTLSFailureLowConfidence`, `TestBuildProfileDetectsSNIFiltering`)
- **Fatalf for failure cases** -- tests use `t.Fatalf` to abort on first assertion failure rather than `t.Error` + continue

**Error reporting format:**
- `t.Fatalf("expected X, got %#v", actual)` -- `%#v` used liberally for full struct dump
- `t.Fatalf("expected %v, got %v", want, got)` -- for simple value comparisons

## Mocking

**Framework:** No mocking framework is used. The project does not use mock libraries (no gomock, mockery, mockgen, etc.).

**Patterns:** The codebase uses real infrastructure in tests:

- **Real in-memory TCP servers** in `tcp_test.go:13-25`:
  ```go
  listener, err := net.Listen("tcp", "127.0.0.1:0")
  ...
  go func() {
      conn, err := listener.Accept()
      if err == nil { conn.Close() }
      close(done)
  }()
  ```

- **Real HTTP test servers** (`net/http/httptest`) in `httpprobe_test.go:14-16` and `tlsprobe_test.go:16-20`:
  ```go
  server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
      w.WriteHeader(http.StatusAccepted)
  }))
  ```

- **Real DNS test servers** built from scratch in `dnsprobe_test.go:61-108`:
  ```go
  func startDNSServer(t *testing.T, truncated bool) string {
      mux := mdns.NewServeMux()
      mux.HandleFunc(".", func(w mdns.ResponseWriter, r *mdns.Msg) { ... })
      listener, err := net.ListenPacket("udp", "127.0.0.1:0")
      go func() { _ = udpServer.ActivateAndServe() }()
      ...
  }
  ```

**What NOT to Mock:**
- Model types (`model.TargetResult`, `model.DNSObservation`, etc.) are constructed as literal structs
- Profile and Recommendation types are constructed inline
- No interface abstractions are introduced solely for testability

## Fixtures and Factories

**Test Data:**
- Test data is constructed inline as Go struct literals at the point of use
- No fixture files, no factory functions, no testdata directories
- Example from `classifier_test.go:11-17`:
  ```go
  result := model.TargetResult{
      Target: model.Target{Name: "example", Domain: "example.com"},
      DNS: []model.DNSObservation{
          {Resolver: "system", Answers: []string{"93.184.216.34"}},
          {Resolver: "public", Answers: []string{"93.184.216.35"}},
      },
  }
  ```

## Coverage

**Requirements:** No coverage target enforced. No `-coverprofile` in the README. No CI configuration detected.

**Statements tested:**
- `internal/model/` -- 2 test files covering sentinel errors and validation
- `internal/classifier/` -- 8 test cases covering each finding type
- `internal/scanner/` -- 4 test cases covering utility functions and a smoke test for `Run`
- `internal/probe/tcp/` -- 2 tests covering success and refused
- `internal/probe/dnsprobe/` -- 3 tests covering A records, missing port, TCP truncation retry
- `internal/probe/httpprobe/` -- 1 test covering HTTP status and timing
- `internal/probe/tlsprobe/` -- 2 tests covering TLS success and handshake failure
- `internal/probe/quicprobe/` -- 1 test covering failure on non-QUIC endpoint
- `internal/report/` -- 1 test verifying summary output includes domain and finding
- `internal/profile/` -- 3 tests covering tier computation, SNI filtering, error degradation
- `internal/recommend/` -- 2 tests covering ranking sort order and SNI filtering preference

**Untested packages:**
- `internal/targets/` -- no tests (pure data, no logic)
- `internal/probe/traceprobe/` -- no tests (requires root/ICMP privileges)
- `cmd/iscan/` -- no tests (CLI entry point)

## Test Types

**Unit Tests (primary):**
- All tests are unit tests that test exported functions with constructed inputs
- Probe tests use real local server infrastructure (in-memory TCP/TLS/DNS/HTTP servers) -- borderline integration but still self-contained

**Integration Tests:**
- `TestBuildScanReportSkipsCancelledTargets` in `scanner_test.go:58-74` is a smoke/integration test that calls `scanner.Run()` against the real builtin target set with a short timeout. It validates that the function does not panic and returns a well-formed report.
- No dedicated integration test directory or build tags.

**E2E Tests:** Not used.

## Common Patterns

**Async Testing:**
```go
// tcp_test.go:19-25 -- channel-based goroutine coordination
done := make(chan struct{})
go func() {
    conn, err := listener.Accept()
    if err == nil { conn.Close() }
    close(done)
}()
...
<-done
```

**Error Testing:**
```go
// classifier_test.go:73-80 -- check finding existence + field inspection
finding, ok := getFinding(findings, model.FindingTLSHandshakeFailure)
if !ok {
    t.Fatalf("expected tls_handshake_failure finding, got %#v", findings)
}
if finding.Confidence != model.ConfidenceLow {
    t.Fatalf("expected low confidence for single TLS failure, got %q", finding.Confidence)
}
```

**Test Helpers:**
```go
// dnsprobe_test.go:61-108
func startDNSServer(t *testing.T, truncated bool) string {
    t.Helper()
    ...
    t.Cleanup(func() {
        _ = udpServer.Shutdown()
        _ = tcpServer.Shutdown()
    })
    return listener.LocalAddr().String()
}

// tcp_test.go:66-73
func mustPort(t *testing.T, value string) int {
    t.Helper()
    port, err := net.LookupPort("tcp", value)
    if err != nil { t.Fatal(err) }
    return port
}
```

**Table of test coverage by package:**

| Package | Test File(s) | Tests | Style |
|---------|-------------|-------|-------|
| `model` | `errors_test.go` | 2 | Table-driven (table-driven struct + `t.Run`) |
| `classifier` | `classifier_test.go` | 8 | Scenario-per-function, custom `hasFinding`/`getFinding` helpers |
| `scanner` | `scanner_test.go` | 4 | Pure function tests + 1 smoke integration test |
| `probe/tcp` | `tcp_test.go` | 2 | Real listener infrastructure |
| `probe/dnsprobe` | `dns_test.go` | 3 | Custom DNS server, truncated fallback, `t.Cleanup` |
| `probe/httpprobe` | `http_test.go` | 1 | `httptest.NewServer` |
| `probe/tlsprobe` | `tls_test.go` | 2 | `httptest.NewUnstartedServer` + TLS, `t.Helper` |
| `probe/quicprobe` | `quic_test.go` | 1 | Connection failure test only (no QUIC server) |
| `probe/traceprobe` | (none) | 0 | Requires system privileges |
| `profile` | `profile_test.go` | 3 | Struct-literal scan reports |
| `recommend` | `recommend_test.go` | 2 | Profile-injection, score verification |
| `report` | `report_test.go` | 1 | String-output inspection |
| `targets` | (none) | 0 | Data-only package |

## Gaps and Recommendations

- **`traceprobe` has no tests** -- requires root/ICMP privileges. Consider splitting the ICMP socket creation into an injectable interface for testing.
- **No coverage target enforced** -- consider `go test -coverprofile=coverage.out ./...` in CI.
- **No `go test -race` usage** -- race detection not mentioned in README.
- **`scanner.Run()` test** is a live network integration test that depends on external infrastructure. It will fail offline and is slow. Consider extracting `scanner.Run()` into smaller testable units.
- **quicprobe** tests only a failure case; a test with a real QUIC server is missing (requires external dependency).

---

*Testing analysis: 2026-04-26*
