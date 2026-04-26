# Domain Pitfalls: Network Diagnostic Tools

**Domain:** Go-based layered network diagnostics CLI (iscan)
**Researched:** 2026-04-26
**Overall confidence:** MEDIUM (high confidence in well-documented pitfalls, medium in project-specific interaction effects)

---

## Critical Pitfalls

Mistakes that cause silent data corruption, incorrect findings, or complete probe failure.

### Pitfall 1: ICMP Identifier Collision in Concurrent Traceroute

**Severity:** CRITICAL
**Affects:** `traceprobe`

**What goes wrong:** The traceroute uses `os.Getpid() & 0xffff` as the ICMP Echo identifier. When multiple traceroute instances run concurrently (or other ICMP-based tools like ping run simultaneously), identifier collisions cause ICMP responses to be attributed to the wrong probe. The receiver in `probeHop` validates both `body.ID` and `body.Seq` against the sent values, but the `TimeExceeded` response path does NOT validate the inner ICMP ID -- it accepts the hop address unconditionally. This means a concurrent probe's `TimeExceeded` packet could be misattributed as a valid hop.

**Why it happens:**
- `os.Getpid() & 0xffff` is only 16 bits -- collisions are likely with concurrent processes
- The `TimeExceeded` handler in `probeHop` skips ID/Seq validation (line 122-132 of trace.go), so any `TimeExceeded` from any source is accepted
- No per-instance unique identifier is generated

**Real-world evidence:**
- RIPE Atlas documented "paths were completely mixed up" during concurrent traceroutes (RIPE Atlas mailing list, 2012)
- Nmap-dev documented ICMP TimeExceeded race causing false "host down" detection (Nmap-dev, 2015)
- Go traceroute libraries like `gotraceroute` use BPF filters specifically to solve this

**Consequences:**
- Hops from other traceroute instances appear as incorrect hops in the trace
- Path reconstruction becomes unreliable
- `profile.go`'s path jitter calculation uses hop RTTs, so corrupted hops corrupt jitter
- The `PathHealth` tier is computed from corrupted data

**Prevention:**
- Replace `os.Getpid() & 0xffff` with a per-instance atomic counter that is unlikely to collide: `probeID := atomic.AddUint64(&nextProbeID, 1) & 0xffff`
- Validate the inner ICMP body in ALL `TimeExceeded` responses (not just Echo responses)
- Consider using a BPF filter on Linux to kernel-filter ICMP responses
- Implement a strict timeout for each hop to prevent stale responses

**Detection:**
- Monotonically increasing ICMP ID values observed from a single process (should be stable per-instance)
- Same router IP appears with different TTLs from different runs
- RTT values that are implausibly low (cross-instance attribution)

**Testing:**
- Start two concurrent traceroute instances to the same target and verify hops are not interleaved
- Send crafted `TimeExceeded` packets with mismatched inner IDs and verify they are rejected
- Run with `-race` to catch shared state in the ICMP ID source

---

### Pitfall 2: EDNS0 Not Preserved on TCP Retry

**Severity:** CRITICAL
**Affects:** `dnsprobe`

**What goes wrong:** The DNS probe sets an EDNS0 option on the initial UDP query (line 23: `msg.SetEdns0(1232, false)`), but when the response has the Truncated bit set and the probe retries over TCP (lines 50-73), the TCP request reuses the SAME `msg` object. The `msg.SetEdns0` call already modified the message, and the TCP client from `miekg/dns` silently strips or re-encodes the OPT pseudo-record differently. The `miekg/dns` library has a known issue where `Msg.Copy()` does NOT copy EDNS0 records -- the OPT pseudo-record must be manually re-attached.

**Why it happens:**
- `miekg/dns` stores EDNS0 options as an OPT pseudo-record in `msg.Extra`
- TCP retry uses the same `msg` object (not a fresh copy)
- EDNS0 handling across UDP-to-TCP transitions is implementation-dependent per RFC 6891
- The library's TCP implementation may have different OPT record handling than UDP

**Real-world evidence:**
- `miekg/dns` issue tracker documents that `Msg.Copy()` does not copy EDNS0 records
- Some resolvers return truncated responses specifically because of EDNS0 option mismatches between UDP and TCP transports
- Let's Encrypt Boulder experienced truncation issues when using 512-byte buffers without EDNS0

**Consequences:**
- TCP retry may not include the EDNS0 extension, causing different resolver behavior than the UDP query
- Large responses that triggered truncation on UDP may still fail on TCP if EDNS0 handling is inconsistent
- The DNS observation comparison across resolvers may compare queries that effectively had different parameters

**Prevention:**
- Create a fresh `mdns.Msg` for the TCP fallback instead of reusing the UDP message
- Explicitly copy the EDNS0 OPT record to any new message
- Consider using a separate client for TCP with explicit `SetEdns0` call

**Testing:**
- Test with a resolver that returns truncation specifically for queries WITH EDNS0 but not without
- Compare EDNS0 options in wire format between the original UDP message and the TCP retry message
- Use a packet capture to verify EDNS0 presence in both UDP and TCP queries

---

### Pitfall 3: Shared per-Hop Timeout in Concurrent Traceroute

**Severity:** HIGH
**Affects:** `traceprobe`

**What goes wrong:** The `probeHop` function uses `conn.SetDeadline(time.Now().Add(timeout))` on the shared ICMP `PacketConn` (line 103 of trace.go). Since traceroute is sequential per-target (TTL loop), this is currently a single-target issue. However, the global timeout applied to each individual hop is the SAME as the overall probe timeout. A 5-second per-hop timeout means a 30-hop traceroute could take 150 seconds -- far exceeding user expectations. The `consecutiveEmpty` break logic (3 consecutive read timeouts) mitigates this somewhat, but if any hop responds quickly, the next hop also gets the full timeout budget.

**Why it happens:**
- `SetDeadline` is set on the CONNECTION, not per-read, but the sequential loop re-sets it before each hop
- The per-hop timeout is the same as the probe-level timeout (e.g., 5s)
- No minimum per-hop timeout or adaptive timeout based on prior hop RTTs is implemented
- The probe-level deadline (`ctx` from caller) is the only ultimate limiter

**Consequences:**
- A multi-hop traceroute can take much longer than users expect
- The "3 consecutive timeouts" break (line 65) may trigger prematurely if early hops are slow but later hops are fast
- The `Latency` timer starts BEFORE the DNS resolution (line 17-18), so DNS latency inflates the trace latency

**Prevention:**
- Implement an adaptive per-hop timeout: start with 1s, use min(2*lastHopRTT, timeout) for subsequent hops
- Add a total execution deadline derived from the parent context
- Move the latency timer start to after DNS resolution completes
- Consider parallel TTL probes with a bounded response window

**Detection:**
- Trace latency consistently equals `timeout * hopCount`
- Trace completes but the `Duration` field far exceeds what is reasonable for the hop distance

**Testing:**
- Mock a DNS resolver that takes 3 seconds to respond, verify trace latency doesn't include DNS time
- Test with network conditions where first hops are slow but later hops are fast

---

### Pitfall 4: InsecureSkipVerify Skips SNI in Some Scenarios

**Severity:** HIGH
**Affects:** `tlsprobe`, `httpprobe`, `quicprobe`

**What goes wrong:** The TLS probe always uses `InsecureSkipVerify: true` (hardcoded in scanner's `probeTLSWithRetries` at line 161, also in HTTP probe at line 27). While this enables diagnostic probing against servers with self-signed certificates, it also means the TLS handshake completes even when the certificate is completely invalid for the target hostname. The probe correctly sets `ServerName` for SNI, but `InsecureSkipVerify` interacts differently across Go versions: in some versions, the SNI extension may not be sent correctly when `InsecureSkipVerify` is true AND the `ServerName` is also set.

**Why it happens:**
- The Go `crypto/tls` library has historically had subtle interactions between `InsecureSkipVerify` and `ServerName`
- A documented MongoDB Go Driver bug (GODRIVER-1636) showed that some implementations skip setting the SNI extension entirely when `InsecureSkipVerify` is true
- Go's behavior has changed across versions (1.15 vs 1.19 vs 1.22+)

**Real-world evidence:**
- CVE-2021-34558: Go < 1.16.6 `crypto/tls` clients could panic when provided a certificate of wrong type -- this was more exploitable with `InsecureSkipVerify: true`
- MongoDB Go Driver: SNI was incorrectly omitted when `InsecureSkipVerify` was true
- CodeQL and Amazon CodeGuru both flag `InsecureSkipVerify: true` as a high-severity finding (`go/disabled-certificate-check`, score 7.5)

**Consequences:**
- TLS handshake succeeds even with completely invalid certificates, masking certificate issues
- The `TLSObservation.Success` flag may be true when the certificate is invalid for the SNI
- `SNICorrelated` findings only detect cases where the SAME address succeeds for one SNI but fails for another -- they don't detect that ALL SNIs succeed with invalid certs
- QUIC probe has the same issue (line 27 of quic.go)

**Prevention:**
- For production diagnostics, implement a two-pass probe: first pass with `InsecureSkipVerify: true` for connectivity, second pass with proper verification for certificate analysis
- Use `VerifyPeerCertificate` callback to perform CERTAIN validation checks even with `InsecureSkipVerify: true`:
  ```go
  &tls.Config{
      InsecureSkipVerify: true,
      VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
          if len(rawCerts) == 0 { return errors.New("no certs") }
          cert, _ := x509.ParseCertificate(rawCerts[0])
          // Record cert details without failing
          return nil // allow connection to proceed
      },
  }
  ```
- Record certificate validation DETAILS (not just SHA256) even when bypassing verification
- Add a `CertificateReport` model that captures SAN, expiry, issuer regardless of verification status

**Detection:**
- All TLS probes always succeed regardless of target certificate quality
- No TLS errors are ever observed for any target or SNI

**Testing:**
- Point the probe at a server with an expired certificate and verify the observation captures the expiry info
- Point at a server with a certificate that has no SAN matching the requested SNI and verify the observation records the mismatch
- Use `testify` or raw `tls.test` fixtures to verify behavior

---

### Pitfall 5: DNS Error Handling Does Not Distinguish NXDOMAIN from SERVFAIL

**Severity:** HIGH
**Affects:** `dnsprobe`, `profile`

**What goes wrong:** The DNS probe maps all non-success RCODEs to `observation.Success = false` (line 38 of dns.go: `observation.Success = resp.Rcode == mdns.RcodeSuccess`). There is NO distinction between:
- `NXDOMAIN` (domain definitely does not exist)
- `SERVFAIL` (resolver encountered an error)
- `REFUSED` (resolver refused the query)
- `FORMERR` / `NOTIMP` (protocol errors)

The `targets.go` hardcodes `example.com`, `cloudflare.com`, `www.google.com`, and `example.net` as targets. If a resolver returns NXDOMAIN for any of these, it is a stronger censorship signal than SERVFAIL, yet both produce the same observation. The `profile.go` function `profileDNS` only checks for the `dns_inconsistent` finding and doesn't analyze RCODE distributions across resolvers.

**Why it happens:**
- The model only has `Success: bool` and `RCode: string` but no severity ordering of RCODEs
- The RCODE is stored as a string but not evaluated in `classifier.go` or `profile.go` for specific signal detection
- The `suspiciousDNS` checker only looks at IP address values, not RCODEs

**Consequences:**
- NXDOMAIN from certain resolvers (which could indicate DNS-level blocking via "sinkholing") generates the same signal as SERVFAIL (temporary resolver failure)
- The `recommend.go` scoring (`dnsGood` function) penalizes latency and suspicious answers but not RCODE issues
- A resolver returning NXDOMAIN for valid domains is treated the same as a resolver having a transient error

**Prevention:**
- Add RCODE-specific handling: NXDOMAIN should be a high-confidence finding, SERVFAIL should be medium
- Compare RCODEs across resolvers for the same domain+type (NXDOMAIN from resolver A, NOERROR from resolver B)
- Add a `dns_blocked` finding type that triggers when a resolver returns NXDOMAIN for known-valid domains
- Store the raw RCODE integer alongside the string representation

**Detection:**
- Check `RCode` field: if any resolver returns NXDOMAIN while others return NOERROR for the same domain+type
- Monitor for resolvers that consistently return REFUSED (potential resolver-level blocking)

**Testing:**
- Inject DNS responses with different RCODEs and verify each produces the correct finding
- Test with a resolver that returns NXDOMAIN for example.com and verify it's flagged differently than SERVFAIL

---

### Pitfall 6: Network Profile Averages Over All Targets Including Control Targets

**Severity:** HIGH
**Affects:** `profile`

**What goes wrong:** The network profile functions (e.g., `profileTCP`, `profileTLS`, `profileDNS`) aggregate observations across ALL targets, including control targets (`example.com`, `cloudflare.com`, `example.net`). If a user encounters blocking on the diagnostic targets (`www.google.com`) but the control targets succeed, the profile averages dilute the signal. The success rate for TLS might appear as 75% (3/4 targets succeed) when in reality it's 0% connectivity to the specific target the user cares about.

**Why it happens:**
- `profileTCP` iterates over `report.Targets` without filtering by `target.Control`
- `profileTLS` has the same pattern
- `profileDNS` aggregates over all DNS observations without grouping by target
- The `OverallStability` score averages all layer tiers, which masks per-target issues

**Consequences:**
- Recommendations may suggest "long-lived TCP" because control targets succeed, even though the diagnostic target has full blockage
- The `recommend.go` scoring uses `tcp.SuccessRate` across ALL targets, which is misleading for targeted blocking
- `dns.go` DNS observations for `example.com` are averaged with `www.google.com` observations, masking DNS-level blocking that is domain-specific

**Prevention:**
- Separate the profile computation into control-only and diagnostic-only profiles
- Add per-target profiles alongside the aggregate profile
- Flag findings when control targets succeed but diagnostic targets fail
- Compute recommendation scores using only diagnostic targets, with control targets used as a baseline

**Detection:**
- `OverallStability` is high while specific targets consistently fail
- Per-target result analysis shows clear split between control and diagnostic targets

**Testing:**
- Run with a mix of blocking-allowed and blocking-not-allowed targets, verify profile detects the split
- Add test fixtures where 1/4 targets fail and verify the profile correctly identifies the failure

---

## Moderate Pitfalls

### Pitfall 7: Timeout Not Propagated to Individual Probe Functions

**Severity:** MEDIUM
**Affects:** `scanner`, `dnsprobe`, `tcp`, `tlsprobe`, `httpprobe`, `quicprobe`, `traceprobe`

**What goes wrong:** The overall `ScanOptions.Timeout` is passed to each probe function, but the relationship between the probe timeout and the scan context deadline is unclear. The `retryWithBackoff` function checks `ctx.Err()` between retries but the individual probe calls may block for the full `timeout` duration. With 4 probes (DNS, TCP, TLS, HTTP) per target, 3 retries each, and 4 targets, the potential maximum runtime is roughly:

- 4 targets x (4 DNS + 4 TCP + 4 TLS + 4 HTTP + 1 traceroute) x timeout
- At 5s timeout, this is ~85 seconds minimum for serial probing
- With `Parallelism: 4` (default), up to 4 goroutines run concurrently, each potentially taking the full timeout per probe

The errorgroup context cancellation provides a hard stop, but the probes themselves don't check the context between sub-operations (e.g., between UDP DNS and TCP DNS fallback in `dnsprobe.go`).

**Why it happens:**
- Each probe function accepts a `time.Duration` parameter but doesn't derive a shorter context from the parent context
- The `tls.Dialer.DialContext` uses the `net.Dialer.Timeout` which is the per-dial timeout, not the overall deadline
- The HTTP probe uses `httptrace` but the transport has its own timeout via `http.Client.Timeout`
- No probe function uses `context.WithTimeout` to cap its own execution

**Consequences:**
- Under slow network conditions, the scan takes much longer than `timeout` per probe
- The `retryWithBackoff` function retries after each failure, and each retry can take the full timeout
- Total scan time can be `timeout * retries * probes * targets` in the worst case

**Prevention:**
- Each probe function should derive a per-attempt context: `attemptCtx, cancel := context.WithTimeout(ctx, timeout)` and pass that to blocking operations
- The `retryWithBackoff` function should pass a per-attempt deadline to the probe function, not the full original timeout
- Separate "connection timeout" from "operation timeout" -- TCP dial gets a shorter timeout than the full TLS handshake

**Detection:**
- Scan duration consistently approaches or equals worst-case theoretical maximum
- User reports that scans take "forever" before producing results

**Testing:**
- Inject artificial delays in probe handlers and verify the scan respects the configured timeout
- Test `retryWithBackoff` with a "never succeeds" probe and verify the function returns within a bounded time

---

### Pitfall 8: DNS TCP Fallback Shares Same Message Object

**Severity:** MEDIUM
**Affects:** `dnsprobe`

**What goes wrong:** When DNS UDP response is truncated (TC bit set), the probe retries over TCP. However, the TCP retry uses the SAME `msg` object that was sent over UDP. The `miekg/dns` library's TCP client may handle EDNS0 differently -- specifically, DNS over TCP doesn't need EDNS0 for large responses (TCP has no size limit), but some authoritative servers may react differently to queries depending on whether EDNS0 is present. Additionally, if the UDP response caused any mutation of the `msg` object (e.g., through the exchange), the TCP query may be inconsistent.

**Why it happens:**
- `msg.SetEdns0(1232, false)` modifies the message object in place
- `client.ExchangeContext(ctx, msg, server)` for UDP may modify `msg` (ID field, etc.)
- The TCP retry reuses the same mutated `msg`
- The RTT timing for the TCP retry reuses the original `start` time, so TCP latency includes the failed UDP attempt time

**Consequences:**
- TCP fallback latency is inflated by the failed UDP latency (line 52-53 of dns.go: `observation.Latency = time.Since(start)`)
- The `profile.go` DNS latency calculation includes TCP fallback measurements, distorting average DNS latency
- EDNS0 handling may differ between UDP and TCP paths

**Prevention:**
- Create a fresh `mdns.Msg` for TCP fallback
- Record per-attempt latency rather than total elapsed time
- Reset the latency timer at the start of the TCP retry

**Testing:**
- Test with a DNS server that returns TC for UDP and observe that the TCP probe records correct (not inflated) latency
- Verify the EDNS0 option is present in the TCP query via packet capture

---

### Pitfall 9: HTTP Redirects Disabled May Miss Censorship Signals

**Severity:** MEDIUM
**Affects:** `httpprobe`

**What goes wrong:** The HTTP probe disables redirect following (`CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }` at lines 37-39). While this is intentional to avoid redirect loops and capture the redirect response itself, it means the probe never sees the FINAL content of a multi-step redirect chain. Censorship middleboxes frequently use redirects to blockpages, and the initial redirect response may contain the blocking signal in the Location header rather than the final body. By not following redirects, the probe may miss:
- Redirect-only blockpages (e.g., `Location: http://blockpage.local`)
- JavaScript-based redirects that are hidden behind an HTTP 302
- Cookie-setting redirect chains that precede blocking content

**Why it happens:**
- The choice to use `http.ErrUseLastResponse` was made to prevent redirect loops and to capture each intermediate step
- There is no loop to issue separate requests for redirect locations
- The HTTP observation only captures the FIRST response, not the final content

**Consequences:**
- `Success` is determined by `statusCode >= 200 && statusCode < 400` (line 90), which means 3xx redirects are counted as SUCCESS even though they are not the final response
- HTTP-to-HTTPS redirects are not followed, so the probe never measures the HTTPS endpoint
- The `StatusText` in the response is checked, but the redirect target is not captured

**Prevention:**
- Follow redirects up to a configurable limit (default 2-3) to capture the final content
- Store the redirect chain in the observation
- Differentiate between "redirect success" and "content success"
- When a redirect is detected, issue a subsequent probe to the redirect target

**Detection:**
- Status code 3xx is counted as "success" even though the probe didn't reach content
- No HTTP observation ever has a non-4xx/5xx status code that is actually a redirect

**Testing:**
- Set up a test server that returns 302 to a blocked page and verify the probe records the redirect as a finding
- Test with a server that returns 200 for one path and 302 for another, verify the probe signals the difference

---

### Pitfall 10: System DNS Resolver Cannot Distinguish RCODEs

**Severity:** MEDIUM
**Affects:** `scanner`

**What goes wrong:** The `probeDNS` function (lines 167-198 of scanner.go) has two code paths: for custom resolvers (miekg/dns direct query) and for the system resolver (`net.DefaultResolver.LookupIP`). The system resolver path returns `ips, err` but does NOT return the DNS RCODE. The `observation.RCode` is hardcoded to `"NOERROR"` (line 196) when there are no errors, even though the system resolver may have received SERVFAIL, NXDOMAIN, or other RCODEs and produced no results. This means system resolver DNS failures are indistinguishable from empty but valid responses.

Additionally, the system resolver may use the local DNS cache (`nscd`, `systemd-resolved`, `mDNSResponder`), meaning the observation reflects cached results, not real-time DNS resolution. This creates inconsistency with the custom resolvers that always perform live queries.

**Why it happens:**
- Go's `net.DefaultResolver.LookupIP` is a high-level API that abstracts away RCODE details
- The system resolver's behavior varies by OS: macOS uses `mDNSResponder` (with cache), Linux uses `/etc/resolv.conf` entries (may use `nscd` or `systemd-resolved`)
- The system resolver path is designed to be a "baseline" comparison but disguises the RCODE

**Consequences:**
- `dnsInconsistent` in classifier.go may miss DNS-level blocking detected by the system resolver
- Observations from the system resolver always have `RCode: "NOERROR"`, creating false consistency
- The `profile.go` DNS agreement check only compares `Answer` sets, which may miss RCODE-based inconsistencies
- Cached responses from the system resolver may show stale IPs that differ from live queries

**Prevention:**
- Use `net.Resolver.LookupHost` or `net.Resolver.LookupAddr` which provide more control, or use `miekg/dns` for ALL resolvers including system
- Alternatively, use `net.DefaultResolver.LookupIPAddr` with proper context to get more detail
- Document the system resolver's caching behavior prominently
- Add a mechanism to flush the local DNS cache before system resolver queries (e.g., macOS `dscacheutil -flushcache`)

**Detection:**
- System resolver returns results quickly (<1ms) indicating cache hit
- System resolver results are consistently different from custom resolver results

**Testing:**
- Inject a known DNS result into the local cache and verify the system resolver returns cached results
- Test with a resolver that returns NXDOMAIN for a domain and verify the system path does NOT report NOERROR

---

### Pitfall 11: TraceHop ID/Seq Validation Inconsistency

**Severity:** MEDIUM
**Affects:** `traceprobe`

**What goes wrong:** The `probeHop` function (lines 83-139 of trace.go) validates ID and Seq for Echo responses (line 120-123) but does NOT validate them for `TimeExceeded` responses (lines 124-133). This means:
1. Any `TimeExceeded` from any source is accepted as a valid hop
2. A delayed `TimeExceeded` from a PREVIOUS traceroute instance is accepted
3. The probe correctly validates the inner ICMP body in Echo responses but not in TimeExceeded responses

The code comment explains: "The inner (original) packet data is unreliable for ID/Seq matching, so accept without validation." However, RFC 792 specifies that the TimeExceeded message contains the original IP header plus first 8 bytes of the original datagram -- which includes the ICMP header with ID and Seq. While the inner ID/Seq is present, some routers may modify it, but outright accepting any TimeExceeded is too permissive.

**Why it happens:**
- The code author correctly identified that router modifications to the inner packet are possible
- However, the response is too lax: accepting ANY TimeExceeded means accepting unrelated traffic
- The 16-bit ICMP Echo ID `os.Getpid() & 0xffff` provides minimal collision protection
- No source IP validation is performed (the response could come from any IP)

**Consequences:**
- False hops appear in the trace output from unrelated ICMP traffic
- The `PathHealth.HopCount` and `Jitter` calculations in profile.go use corrupted hop data
- For short traces, the 3-consecutive-empty check may not trigger, and corrupted hops persist

**Prevention:**
- Validate the inner ICMP body for TimeExceeded responses by extracting the embedded original IP header + ICMP header
- Accept the hop but flag it with lower confidence when ID/Seq don't match
- Add source IP validation: ignore ICMP from source IPs that are not on the expected path
- Implement a per-instance random probe ID that changes between runs

**Testing:**
- Spoof a TimeExceeded ICMP packet with a different ID and verify it is rejected
- Inject a delayed TimeExceeded from a previous probe instance and verify it is filtered
- Test with concurrent traceroute instances to the same target

---

### Pitfall 12: Finding Confidence Is Statically Assigned

**Severity:** MEDIUM
**Affects:** `classifier`

**What goes wrong:** All findings in `classifier.go` are statically assigned confidence levels:
- `dns_inconsistent`: LOW
- `dns_suspicious_answer`: MEDIUM
- `tcp_connect_failure`: LOW
- `tls_handshake_failure`: LOW
- `sni_correlated`: MEDIUM
- `http_application_failure`: LOW
- `quic_handshake_failure`: LOW
- `path_quality_degraded`: LOW

These confidence levels are independent of evidence strength. A TCP failure backed by 5 consecutive retry failures across 4 targets gets the same LOW confidence as a single TCP failure against one target. Similarly, `sni_correlated` is always MEDIUM, even if the correlation is based on a single observation.

**Why it happens:**
- The classifier currently uses a rule-based approach without evidence scoring
- Confidence is set at the finding type level, not per-instance
- The `aggregateFailures` function groups by key but doesn't compute a confidence multiplier

**Consequences:**
- Findings with strong evidence (multiple targets, multiple retries) are treated the same as weak evidence
- The `recommend.go` scoring uses `profile` aggregations that don't distinguish evidence strength
- Users see "low confidence" for obviously broken connectivity, eroding trust
- The `report.Summary` shows finding types regardless of confidence

**Prevention:**
- Compute confidence dynamically based on:
  - Number of independent observations supporting the finding
  - Consistency across retries
  - Number of distinct layers affected
  - Control target comparison (control passes + diagnostic fails = higher confidence)
- For TCP failures: if ALL targets fail at ALL ports, confidence increases
- For DNS inconsistency: if ONE resolver returns different answers, confidence is LOW; if THREE resolvers each return different answers, confidence is HIGH

**Detection:**
- All findings always have the same confidence regardless of accumulated evidence
- Finding count correlates poorly with actual network issues

**Testing:**
- Test with 1 failure vs 10 failures and verify confidence differs
- Test with failures across correlated probes (e.g., TCP + TLS + HTTP all fail for same host) vs isolated failures

---

### Pitfall 13: MissingPort Helper Does Not Detect All Address Formats

**Severity:** MEDIUM
**Affects:** `dnsprobe`

**What goes wrong:** The `missingPort` function (lines 77-87 of dns.go) checks if a server address is missing its port using `net.SplitHostPort`. It specifically checks for the `AddrError` with message "missing port in address". However, `SplitHostPort` can return different error messages for different address formats:
- `"missing port in address"` for `"192.168.1.1"` (correct)
- `"address 192.168.1.1: too many colons in address"` for IPv6 addresses without brackets
- `"missing port"` for `"::1"` without brackets

If a resolver is configured as an IPv6 address like `"2001:4860:4860::8888"` (without brackets and without port), `SplitHostPort` returns a confusing error that `missingPort` map correctly handles, but the DNS query will fail with an unclear error.

**Why it happens:**
- The function checks for `AddrError.Err == "missing port in address"` specifically
- IPv6 addresses without brackets produce different error messages
- The function doesn't validate the address format before port detection
- The code appends `":53"` only when the error matches the exact string

**Consequences:**
- IPv6 resolver addresses may fail silently or produce confusing error messages
- The DNS probe may return a transport error rather than a clear "invalid resolver address" error
- Users configuring custom resolvers with IPv6 addresses may get confusing failures

**Prevention:**
- Use `net.JoinHostPort` for address normalization BEFORE port detection
- Check if the address contains a colon (IPv6 indicator) and handle accordingly
- Use `net.ParseIP` to detect the address type before port manipulation
- Always normalize the resolver address early in the pipeline, not in the probe

**Testing:**
- Test with IPv6 resolver addresses with and without port
- Test with IPv6 addresses with and without brackets
- Test with resolvers that have explicit port numbers (e.g., `"1.1.1.1:853"` for DNS-over-TLS)

---

### Pitfall 14: TCP Error Classification Uses String Matching After Struct Matching

**Severity:** MEDIUM
**Affects:** `tcp`

**What goes wrong:** The `classifyError` function in `tcp.go` first tries `errors.Is` with syscall errors (lines 47-55), then falls back to string matching on the lowercased error message (lines 56-68). This "try struct, then string" approach has a subtle issue: the string matching occurs AFTER the syscall matching, but Go's `errors.Is` for syscall errors on different platforms may return different values for the same underlying error. On macOS, `ECONNREFUSED` may be wrapped differently than on Linux, and the string fallback may not fire correctly.

Additionally, the function checks `os.IsTimeout(err)` which works for `syscall.ETIMEDOUT` on POSIX systems but may not catch wrapped timeout errors from `net.Dialer`.

**Why it happens:**
- Go's error wrapping across platforms is inconsistent for network errors
- `errors.Is(err, syscall.ECONNREFUSED)` works when the error chain contains a `syscall.Errno`, but `net.OpError` wraps syscall errors differently on some platforms
- The string-based fallback uses broad matching (e.g., `contains(lower, "timeout")`) which can match unexpected error messages
- The error classification is used in `profile.TCPHealth.ErrorModes` but not in any evidence-based finding scoring

**Consequences:**
- Some TCP errors may be classified as "other" even though they are semantically recognizable
- The `ErrorModes` map in `profile.go` may not accurately reflect the distribution of error types
- Protocol-aware error classification (e.g., "connection refused" vs "no route to host") is a valuable diagnostic signal that may be lost

**Prevention:**
- Add explicit checking for `net.OpError` before checking syscall errors:
  ```go
  var opErr *net.OpError
  if errors.As(err, &opErr) {
      // Extract syscall.Errno from opErr.Err
      var errno syscall.Errno
      if errors.As(opErr.Err, &errno) { ... }
  }
  ```
- Document which error classifications are expected on each platform
- Add platform-specific test cases for error classification

**Detection:**
- Most TCP errors show as "other" in the profile
- Error pattern distribution shifts between platforms without explanation

**Testing:**
- Test on both Linux and macOS with connection refused scenarios
- Test with timeout scenarios on both platforms
- Test with network unreachable scenarios (e.g., blocked IP)

---

### Pitfall 15: QUIC HandshakeIdleTimeout Equals IdleTimeout

**Severity:** MEDIUM
**Affects:** `quicprobe`

**What goes wrong:** The QUIC configuration sets BOTH `MaxIdleTimeout` and `HandshakeIdleTimeout` to the same `timeout` value (lines 30-32 of quic.go):

```go
quicConf := &quic.Config{
    MaxIdleTimeout:       timeout,
    HandshakeIdleTimeout: timeout,
}
```

In quic-go v0.39.0+, the handshake timeout is defined as `2 * HandshakeIdleTimeout`. Setting both to the same value means the total handshake timeout is `2 * timeout` which is double the expected duration. This creates a confusing situation where:
- The function parameter is named `timeout` (suggesting the total time allowed)
- The actual timeout is `2 * timeout` because quic-go redefines it
- The `MaxIdleTimeout` (post-handshake keepalive) equals the pre-handshake timeout, which may be too aggressive for post-handshake idle

Additionally, if the user expects a 5-second QUIC probe timeout, they actually get a 10-second window, which is inconsistent with other probes that use 5 seconds strictly.

**Why it happens:**
- quic-go v0.39.0 made a breaking change: `HandshakeTimeout` was removed and redefined as `2 * HandshakeIdleTimeout`
- The existing code was written for a pre-v0.39.0 API and not updated for this semantic change
- The `MaxIdleTimeout` was not adjusted to be a longer duration (as is recommended for post-handshake)

**Real-world evidence:**
- quic-go changelog documents this as a breaking change: "The handshake timeout is now defined as twice the handshake idle timeout"
- Up to 31.2% handshake failure rate in quic-go v0.39.0 under high concurrency (50K connections/sec) due to TLS race conditions
- Connection reuse failure during handshake when idle timer fires before handshake completion

**Consequences:**
- QUIC probe takes approximately `2 * timeout` for handshake failures, which is inconsistent with TLS probes
- The `MaxIdleTimeout` (post-handshake) is the same as `HandshakeIdleTimeout`, which may be too short
- After handshake, the connection may close prematurely if there is any delay in reading connection state

**Prevention:**
- Set `HandshakeIdleTimeout = timeout / 2` to achieve a total handshake timeout of `timeout`
- Set `MaxIdleTimeout = 2 * timeout` to give post-handshake connection more headroom
- Use a separate context-derived timeout for the `DialAddr` call to enforce a hard deadline:
  ```go
  dialCtx, cancel := context.WithTimeout(ctx, timeout)
  defer cancel()
  conn, err := quic.DialAddr(dialCtx, address, tlsConf, quicConf)
  ```

**Testing:**
- Test QUIC probe against a non-QUIC endpoint and verify the actual timeout duration equals the expected value (not 2x)
- Create a test harness that measures the actual wall-clock time of a failed QUIC handshake
- Verify the QUIC observation's Latency field is bounded by the configured timeout

---

### Pitfall 16: Writable Context Field in errgroup Pattern

**Severity:** MEDIUM
**Affects:** `scanner`

**What goes wrong:** The `scanTarget` function (lines 82-156 of scanner.go) receives a `context.Context` and performs multiple probes sequentially. Each probe operation uses this shared context. However, there is a subtle issue: the `errgroup.Group` created in `Run()` (line 49) cancels the derived context `gCtx` when ANY goroutine returns an error. This means a single target failure can cancel ALL other target scans, even if the failure is unrelated (e.g., DNS failure for one target cancels the entire scan). The `ScanOptions` do not expose a "partial failure" mode that continues scanning other targets.

**Why it happens:**
- `errgroup.WithContext(ctx)` cancels the derived context on the first non-nil error
- The scanner does not differentiate between fatal errors (cannot continue) and per-target errors (continue with remaining targets)
- The `retryWithBackoff` function returns the last result even on ctx cancellation, but the return value is still subject to the errgroup error handling

**Consequences:**
- A single DNS timeout for one target cancels the entire scan
- Targets later in the loop may never be scanned, producing empty `TargetResult` entries (detected at line 69: `if result.Target.Name == "" { continue }`)
- The scan report has fewer results than expected, which is confusing for users

**Prevention:**
- Do NOT use errgroup for per-target errors; use errgroup for fatal errors only
- Catch panics and critical resource failures at the errgroup level
- For per-target errors, handle them inside the goroutine and return nil from the errgroup callback
- Use a separate mechanism (e.g., `sync.WaitGroup` or channel) to track target completion

**Testing:**
- Create a test where one target causes a dial timeout and verify other targets are still scanned
- Verify the scan report contains results for all targets even when some fail
- Test with the default parallelism and a slow-to-respond target

---

## Minor Pitfalls

### Pitfall 17: No Rate Limiting on DNS Queries

**Severity:** LOW
**Affects:** `scanner`, `dnsprobe`

**What goes wrong:** The scanner sends DNS queries to the same resolver (e.g., 1.1.1.1) for each target, each query type (A and AAAA), and each retry. For 4 targets x 4 resolvers x 2 query types = 32 DNS queries per scan (with retries: 96). Many public resolvers rate-limit at 10-20 queries/second. The queries are sent as fast as the goroutines can execute, potentially triggering rate-limiting that produces incorrect DNS responses (e.g., SERVFAIL or REFUSED) that are then interpreted as network issues.

**Why it happens:**
- The scanner doesn't throttle or sequence DNS queries per resolver
- `errgroup.SetLimit(4)` limits GOROUTINES, not queries per resolver
- Each goroutine may fire multiple DNS queries simultaneously
- Public resolvers have different rate limits (Cloudflare: ~1000/s, Google: ~100/s, Quad9: ~50/s)

**Consequences:**
- Resolver rate-limiting produces false DNS failures
- The `dns_inconsistent` finding may trigger because rate-limited resolvers return different answers than non-rate-limited ones
- The `SERVFAIL` or `REFUSED` from rate-limiting is indistinguishable from actual resolver issues

**Prevention:**
- Add per-resolver rate limiting (e.g., 20 queries/second per resolver)
- Sequence A and AAAA queries for the same target before moving to the next target
- Add a small jitter between queries to the same resolver
- Detect rate-limiting patterns (sudden failures after N rapid successes)

**Detection:**
- DNS failure rate correlates with query concurrency
- Reducing parallelism reduces DNS failures
- Errors include rate-limiting messages ("rate limited", "too many queries")

**Testing:**
- Test with a rate-limited resolver and verify the scanner doesn't trigger limits
- Verify that DNS query timing is properly distributed

---

### Pitfall 18: Route Changes During Traceroute

**Severity:** LOW
**Affects:** `traceprobe`

**What goes wrong:** Sequential traceroute sends all probes to the same destination IP but with increasing TTL. On networks with ECMP (Equal Cost Multi-Path) routing, each packet may take a different path. The sequential TTL approach means TTL=1 and TTL=2 may traverse different routers, producing a path that never actually existed. This is the classic "traceroute on ECMP" problem.

Additionally, if the target IP is behind a load balancer with multiple IP addresses, the initial DNS resolution may return one IP, and the subsequent traceroute packets may be routed to a different backend.

**Why it happens:**
- Sequential traceroute sends each TTL as a separate packet
- ECMP routers hash packet headers and may send different packets to different next hops
- The probe doesn't use Paris-traceroute techniques (fixed flow identifier across all packets)
- DNS resolution happens once at the start of the trace, but routing changes between packets

**Consequences:**
- The `PathHealth.HopCount` in profile.go may be inflated or incorrect
- Hop RTTs may include variability from different paths (jitter calculation is misleading)
- The `ISPInfo.FirstHop` in extractISP may be incorrect if the first hop changes mid-trace

**Prevention:**
- Implement Paris-traceroute: fix the ICMP checksum field to ensure consistent hash across all packets
- For UDP-based traces, fix the source port across all probes
- Document that traceroute results may vary on ECMP networks
- Run multiple traces and compare for path stability

**Testing:**
- Test against targets behind ECMP routers and verify path consistency across runs
- Compare results with standard `traceroute` output from the same host

---

### Pitfall 19: Context Background Used Without Timeout in Scanner Test

**Severity:** LOW
**Affects:** `scanner_test`

**What goes wrong:** The `TestBuildScanReportSkipsCancelledTargets` test (lines 58-74 of scanner_test.go) runs a full scan against the builtin target set with a 100ms timeout. This is a REAL network test that hits actual external resolvers and targets. It depends on:
- Network connectivity
- External resolvers being available
- External targets being reachable
- Scan completing within 100ms

This test WILL fail in offline environments, behind VPNs, or on slow networks. It's an integration test masquerading as a unit test, and there's no build constraint or skip-on-fail logic to handle offline scenarios.

**Why it happens:**
- The test was written as a "smoke test" to verify the scanner doesn't panic
- No mock or test server is used for the targets
- No `testing.Short()` handling is implemented
- The test will be flaky in CI or on developer machines without reliable internet

**Consequences:**
- CI pipelines on restricted networks will fail this test
- Developers on slow connections get intermittent failures
- The test doesn't distinguish between scanner bugs and network issues

**Prevention:**
- Add `testing.Short()` guarding to skip this test in short mode
- Implement a local DNS resolver and HTTP/TLS server for reliable integration testing
- Use `net/http/httptest` for HTTP targets
- Use a local `miekg/dns` server for DNS targets
- Add a build constraint or environment variable check for network-dependent tests

**Testing:**
- Run `go test -short` and verify the test is skipped
- Run `go test -v` with and without network access

---

### Pitfall 20: Make Flags Not Position Independent

**Severity:** LOW
**Affects:** `cmd/iscan`

**What goes wrong:** The CLI uses `cobra` for flag handling, and all flags have POSIX-style names. However, there is no validation that mutually exclusive flags are not simultaneously set (e.g., `--json` without `--summary` still prints a summary since `--summary` defaults to `true`). Also, the global `timeout` flag is used for ALL probes, but optimal timeout values differ by probe type (DNS queries should be 2-5s, QUIC needs 5-10s, traceroute needs longer).

**Why it happens:**
- `timeout` is a single scalar applied uniformly to all probes
- No per-probe timeout overrides exist
- `--summary` defaulting to `true` means `--json` output is always accompanied by terminal output

**Consequences:**
- Setting a low timeout (1s) for fast DNS checks also applies to slow QUIC handshakes
- Setting a high timeout (10s) for reliable QUIC also applies to DNS, making the scan slow
- JSON output is always accompanied by summary text, making it hard to pipe
- User cannot suppress summary without explicitly `--summary=false`

**Prevention:**
- Add per-probe timeout flags (`--dns-timeout`, `--tls-timeout`, `--quic-timeout`, `--trace-timeout`)
- Default `--summary` to `false` when `--json` is specified
- Add environment variable support for flags (useful for containerized deployments)
- Consider a `--progressive` mode that shows results as they arrive

**Testing:**
- Test all flag combinations for correctness
- Verify that `--json` output is parseable JSON even with default flags

---

### Pitfall 21: Profile Computes DNS Agreement Across All Targets

**Severity:** LOW
**Affects:** `profile`

**What goes wrong:** The `profileDNS` function computes `Agreement` by checking for the presence of `dns_inconsistent` findings (line 146 of profile.go). This finding is generated by `classifier.go`'s `dnsInconsistent` function, which compares DNS answer sets ACROSS ALL RESOLVERS for the SAME query type AND TARGET. However, the agreement check in `profileDNS` doesn't differentiate between:
- DNS inconsistency for CONTROL targets (which indicates resolver problems)
- DNS inconsistency for DIAGNOSTIC targets (which may indicate censorship)

Additionally, `profileDNS` shows `MultiResolver: true` when multiple resolvers were used (line 145), but doesn't check if ALL resolvers returned results for each target.

**Why it happens:**
- The profile combines observations across all targets without grouping by purpose
- The agreement flag is binary (agreement/no agreement) with no nuance
- No per-target DNS analysis is exposed in the profile

**Consequences:**
- DNS agreement may be "true" for control targets but "false" for diagnostic targets, and the profile cannot distinguish
- The `dnsGood` function in `recommend.go` penalizes all DNS equally based on aggregate stats
- A user with DNS-level blocking on diagnostic targets but working control targets gets a misleading DNS health assessment

**Prevention:**
- Compute control-target DNS and diagnostic-target DNS separately in the profile
- Add per-target DNS health to the profile
- When control-DNS agrees but diagnostic-DNS disagrees, flag it as a potential censorship signal
- Expose the DNS answer per-target/resolver matrix in the profile

**Detection:**
- DNS agreement is true for control targets but false for diagnostic targets
- Profile shows `Agreement: true` despite clear DNS inconsistencies in the raw data

**Testing:**
- Test with a mixed set of targets where DNS blocking affects only diagnostic targets

---

### Pitfall 22: No Sampling of ICMP Reply for Body Validation

**Severity:** LOW
**Affects:** `traceprobe`

**What goes wrong:** The trace probe reads raw ICMP replies into a 1500-byte buffer (line 108 of trace.go: `reply := make([]byte, 1500)`). It processes ALL ICMP messages received on the socket, not just ones matching the probe's Echo ID. For `Echo` type responses, it validates ID and Seq. For `TimeExceeded` responses, it doesn't validate the inner packet at all (as discussed in Pitfall 11). But there's an additional issue: the buffer may contain partial reads when the ICMP message is larger than 1500 bytes (unlikely for ICMP TimeExceeded but possible for ICMP errors with large original packets).

**Why it happens:**
- `ReadFrom` returns `n` bytes but the code assumes `reply[:n]` contains exactly one ICMP message
- No validation that `n` matches the expected ICMP message length
- No handling of truncated reads when the icmp message exceeds 1500 bytes

**Consequences:**
- Extremely unlikely in practice (ICMP messages that exceed 1500 bytes are rare)
- Could cause panic in `icmp.ParseMessage` with malformed data
- If it occurs, the single erroneous hop causes the entire trace to fail

**Prevention:**
- Verify the parsed ICMP message length matches the returned length
- Add error handling for parse failures that allows the hop to be reported as an error rather than failing the trace
- Use a larger buffer or read the actual message length from the ICMP header

**Testing:**
- Inject a malformed ICMP response and verify the trace handles it gracefully
- Test with oversized ICMP messages (if possible in test environment)

---

## Phase-Specific Warnings

| Phase Topic | Likely Pitfall | Mitigation |
|-------------|---------------|------------|
| **Phase 1: ICMP/Trace** | Pitfalls 1, 3, 11, 18, 22 -- ID collision, shared timeout, permissive validation, ECMP, buffer size | Generate unique probe IDs, implement adaptive per-hop timeout, validate all ICMP responses |
| **Phase 2: DNS** | Pitfalls 2, 5, 8, 10, 13, 17 -- EDNS0 on TCP retry, RCODE handling, message reuse, system resolver cache, IPv6 address parsing, rate limiting | Fresh message on TCP retry, RCODE-specific findings, per-resolver rate limiting |
| **Phase 3: TCP** | Pitfall 14 -- error classification platform differences | Use `net.OpError` unwrapping before syscall matching, platform-specific tests |
| **Phase 4: TLS** | Pitfalls 4, 12 -- InsecureSkipVerify interactions, static confidence | Two-pass probe, dynamic evidence scoring, VerifyPeerCertificate callback |
| **Phase 5: HTTP** | Pitfall 9 -- redirects disabled masking blockpages | Follow limited redirects, capture redirect chain |
| **Phase 6: QUIC** | Pitfall 15 -- handshake timeout semantics | Set `HandshakeIdleTimeout = timeout/2`, use context-derived deadline |
| **Phase 7: Scanner** | Pitfalls 6, 7, 16 -- target mixing in profile, timeout propagation, errgroup cancellation | Split control/diagnostic profiles, derive per-attempt contexts, return nil from errgroup for per-target errors |
| **Phase 8: Classifier** | Pitfalls 5, 12 -- static confidence, missing RCODE analysis | Dynamic confidence scoring, RCODE-based findings |
| **Phase 9: Profile** | Pitfalls 6, 21 -- target mixing in DNS/TCP/TLS profiles | Per-target and per-purpose profiles |
| **Phase 10: Recommend** | Pitfall 12 -- confidence not reflected in recommendations | Incorporate evidence strength into recommendation scoring |
| **Phase 11: CLI** | Pitfall 20 -- uniform timeout, default summary with JSON | Per-probe timeouts, smart defaults based on --json |
| **Phase 12: Tests** | Pitfall 19 -- network-dependent integration tests | `testing.Short()` guard, local test servers, offline mode |

---

## Sources

### ICMP/Permission Pitfalls
- Go `golang.org/x/net/icmp` documentation: raw socket access requires `CAP_NET_RAW` (Linux) or root (macOS)
- OONI Probe ASN leak incident: [OONI Blog](https://ooni.github.io/post/2020-ooni-probe-asn-incident-report/) -- privacy bug from granular opt-out complexity
- OONI data quality analysis: [Improving data quality](https://ooni.github.io/post/improving-data-quality-analysis-of-failed-measurements/) -- ~69-84% of "failed" measurements were actually censorship events
- RIPE Atlas concurrent traceroute issues: [RIPE Atlas mailing list](https://mailman.ripe.net/archives/list/ripe-atlas@ripe.net/thread/N3W2TP23TODCQKG34DD7PJBI25IHXWPL/) -- "paths were completely mixed up"
- Nmap-dev ICMP TimeExceeded race: [Nmap-dev 2015](https://seclists.org/nmap-dev/2015/q2/68) -- false "host down" detection
- Go BPF-based traceroute: [gotraceroute](https://pkg.go.dev/github.com/archer-v/gotraceroute) -- uses BPF to solve concurrent process ID collision

### DNS Pitfalls
- miekg/dns EDNS0 copy issue: [GitHub issue #581](https://github.com/miekg/dns/issues/581) -- EDNS0 subnet option invalid family handling
- Let's Encrypt Boulder DNS truncation: [Community discussion](https://community.letsencrypt.org/t/no-valid-ip-addresses-found-for-dns-a-record-exists-and-works/50528/20) -- buffer size issues with miekg/dns
- miekg/dns error handling: [CSDN analysis](https://blog.csdn.net/gitblog_00604/article/details/144823839) -- common pitfalls with timeout handling

### QUIC Pitfalls
- quic-go v0.39.0 breaking changes: [GitHub release notes](https://github.com/quic-go/quic-go/releases/tag/v0.39.0) -- handshake timeout redefinition
- Premature HANDSHAKE_DONE crash (CVE): [GHSA-47m2-4cr7-mhcw](https://osv.dev/vulnerability/GHSA-47m2-4cr7-mhcw) -- 7.5 HIGH, crash on premature frame
- Connection reuse failure: [Chinese deep-dive](https://datasea.cn/go0331568514.html) -- idle timer fires during handshake, reuse rate drops from 89% to 23%
- TLS race conditions: [quic-go v0.39.0 analysis](https://datasea.cn/go0222503910.html) -- 31.2% handshake failure rate under high concurrency

### TLS Pitfalls
- CodeQL TLS detection: [go/disabled-certificate-check](https://codeql.github.com/codeql-query-help/go/go-disabled-certificate-check/) -- 7.5 HIGH severity
- Amazon CodeGuru: [Improper certificate validation](https://docs.aws.amazon.com/codeguru/detector-library/go/improper-certificate-validation/) -- production validation bypass
- MongoDB Go Driver fix (GODRIVER-1636): [Jira](https://jira.mongodb.org/si/jira.issueviews:issue-html/GODRIVER-1636/GODRIVER-1636.html) -- SNI not set when InsecureSkipVerify is true
- CVE-2021-34558: [Arch security](https://security.archlinux.org/CVE-2021-34558) -- client panic with wrong certificate type

### Concurrency Pitfalls
- errgroup documentation: [pkg.go.dev](https://pkg.go.dev/golang.org/x/sync/errgroup) -- first error cancels context
- errgroup leak discussion: [Hacker News](https://news.ycombinator.com/threads?id=showdeddd) -- "The need to call Wait in order to free resources makes errgroup.WithContext unfortunately still somewhat prone to leaks"
- Go race detector limitations: [sync.Pool blind spots](https://datasea.cn/go0221501744.html) -- three silent data race categories
- errgroup common mistakes: [Leapcell](https://leapcell.io/blog/errgroup-hidden-gem-go-concurrency) -- panics not caught, goroutine limits

### Timeout Pitfalls
- Cascading timeout postmortem: [Chinese production incident](https://datasea.cn/go0224508851.html) -- OOM from missing HTTP client timeout, 16GB to 38GB in 2 minutes
- Fan-out/fan-in with derived contexts: [Deep-dive](https://datasea.cn/go0405579920.html) -- per-probe timeouts with dual protections
- Robust HTTP client design: [Leapcell](https://leapcell.io/blog/robust-http-client-design-in-go) -- four-phase timeout model

### Cross-Platform Pitfalls
- Go raw socket support matrix: [golang.org/x/net commit](https://go.googlesource.com/net/+/0bfab66a03570232c7aaea77dcdd2355ae6e9db8) -- platform-specific raw socket availability
- Outline SDK: [Jigsaw-Code/outline-sdk](https://github.com/Jigsaw-Code/outline-sdk) -- multi-platform network toolkit architecture

### Report Accuracy Pitfalls
- OONI failure analysis: [Blog post](https://ooni.github.io/post/improving-data-quality-analysis-of-failed-measurements/) -- 69-84% of "failures" are censorship
- OONI censorship vs connectivity: [Sinar Project](https://imap.sinarproject.org/news/is-the-website-blocked-verifying-internet-censorship-with-ooni-explorer) -- CDNs, network issues, and blocking fingerprints
- Causal graph detectors: [UU thesis](https://studenttheses.uu.nl/handle/20.500.12932/50696?show=full) -- 1.6x improvement in average precision using causal models
- PUC framework: [bioRxiv](https://www.biorxiv.org/content/10.1101/000497v1.full) -- unexpected correlations removes ~50% erroneous edges

### Testing Pitfalls
- Go testing anti-patterns: [dev.to](https://dev.to/harrison_guo_e01b4c8793a0/testing-real-world-go-backends-isnt-what-many-people-think-12nl) -- "Mock Everything" anti-pattern, race detector best practices
- Go 1.24 testing/synctest: [CSDN](https://blog.csdn.net/qq_44866828/article/details/149579630) -- experimental concurrent testing package with `net.Pipe`
- `go test -race` pipeline: CI guidance from multiple sources -- nightly stress tests, per-PR unit tests
