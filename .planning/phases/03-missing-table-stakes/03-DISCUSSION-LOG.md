# Phase 3: Missing Table Stakes - Discussion Log

> **Audit trail only.**
> **Auto mode — all decisions auto-resolved using recommended defaults.**

**Date:** 2026-04-26
**Phase:** 03-Missing Table Stakes
**Areas discussed:** ICMP Ping approach, Ping model types, Custom target set format, IPv6 strategy, IPv6 traceroute

---

## ICMP Ping Approach
[auto] — Q: "What library and permission model?" → Selected: Use golang.org/x/net/icmp (same as traceroute), graceful permission fallback

## Ping Model Types
[auto] — Q: "New observation type or reuse?" → Selected: New PingObservation with Target, RTT, TTL, Success, Error fields

## Custom Target Set Format
[auto] — Q: "JSON schema?" → Selected: Array of model.Target with TargetSource interface (BuiltinSource + FileSource)

## IPv6 Strategy
[auto] — Q: "Dual-stack or separate?" → Selected: Dual-stack, probe both families when available

## IPv6 Traceroute
[auto] — Q: "ICMPv6 approach?" → Selected: Detect address family, use ICMPv6 for IPv6 targets

## Claude's Discretion

- Ping timeout/retry details
- CLI flag names (--icmp-ping vs --ping)
- IPv6 resolver port assignment
- JSON target validation details

## Deferred Ideas

None.
