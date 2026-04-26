# Phase 4: DNS Enhancements - Discussion Log

> **Audit trail only.**
> **Auto mode — all decisions auto-resolved using recommended defaults.**

**Date:** 2026-04-27
**Phase:** 04-DNS Enhancements
**Areas discussed:** RCODE Handling, DoH/DoT Transport, Rate Limiting, Transparent Proxy Detection, System Resolver RCODE

---

## RCODE Handling Approach
[auto] — Q: "How should per-RCODE findings be surfaced?" → Selected: Classification layer generates DNSFinding with distinct messages per RCODE (NXDOMAIN, SERVFAIL, REFUSED)

## DoH/DoT Transport
[auto] — Q: "How to integrate DoH/DoT via miekg/dns?" → Selected: miekg/dns Client `Net` parameter route based on resolver URL prefix (https:// → DoH, tls:// → DoT)

## Per-Resolver Rate Limiter
[auto] — Q: "Rate limiter placement and algorithm?" → Selected: Token bucket per-resolver via golang.org/x/time/rate, 20 qps default, configurable

## Transparent DNS Proxy Detection
[auto] — Q: "Detection technique?" → Selected: whoami.akamai.net A record query, compare resolved IP vs configured resolver IP

## System Resolver RCODE
[auto] — Q: "How to capture system resolver RCODE?" → Selected: miekg/dns with empty server string dials OS default, extract RCODE normally

## Claude's Discretion

- Exact RCODE finding text and severity levels
- CLI flag names for DoH/DoT resolver configuration
- Rate limiter burst size
- whoami.akamai.net fallback domain list
- init() registration approach for DoH/DoT adapters

## Deferred Ideas

None.
