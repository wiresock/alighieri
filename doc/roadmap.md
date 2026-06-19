# Alighieri Roadmap

A living, proposed plan for closing the remaining gaps with
[Dante](https://www.inet.no/dante/) and pushing past it. See the
[comparison in the README](../README.md#comparison-with-dante) for the current
feature delta, and the [CHANGELOG](../CHANGELOG.md) for what has shipped.

Guiding principle: reach **parity where it matters** (the gaps real deployments
hit), and **differentiate with modern strengths** — safety, cross-platform
reach, observability, and a cloud-native operations story — rather than chasing
every legacy Dante feature. SOCKS4 and GSSAPI are intentionally low priority.

Effort is a rough order of magnitude: **S** ≈ days, **M** ≈ 1–2 weeks, **L** ≈
multi-week. Value is the expected impact on real deployments.

## Shipped (v0.1.0)

The initial release delivered the core proxy: SOCKS5 TCP `CONNECT` and UDP
`ASSOCIATE` (dual-stack, IPv4-mapped clients, configurable `udp.portrange`),
deny-by-default `client`/`socks` ACLs with username/password (Argon2id) auth, a
DNS resolution policy, optional TLS listener and Prometheus metrics, text/JSON
logging, per-client abuse controls, hot reload (SIGHUP / Windows SCM), Windows
Service integration, a Linux systemd lifecycle manager, and a configuration
wizard. See the [CHANGELOG](../CHANGELOG.md) for the full list.

## Parity — close the Dante gaps

| Item | Value | Effort | Notes |
| --- | --- | --- | --- |
| ~~**Hostname / domain ACL rules**~~ | — | — | **Shipped** — `socks` rule `to:` accepts `.example.com` (domain + subdomains) and exact hostnames, matched against the requested host before resolution. |
| ~~**External auth hook**~~ | — | — | **Shipped** (command form) — `auth.command` verifies credentials via an external program (username/password on stdin, exit 0 = allow), covering LDAP/OIDC/PAM via a script. A native HTTP-webhook form remains a possible follow-up. |
| **PAM / system auth (Unix)** | Med | M | Native PAM backend for Unix deployments that expect it. Follows the external-auth hook. |
| **BIND command** | Med | L | RFC 1928 §6 two-stage reverse connect (active FTP, callbacks). Security-sensitive — gated off by default, restricted by `socks` rules. |
| **SOCKS4 / 4a** | Low | S | Cheap, but legacy; modern clients use SOCKS5. Add only on demand. |
| **GSSAPI / Kerberos** | Low | L | Complex and niche; SOCKS-over-TLS already covers channel security. Revisit only if asked. |

## Beyond Dante — differentiate

| Item | Value | Effort | Notes |
| --- | --- | --- | --- |
| ~~**PROXY protocol (v1/v2) ingress**~~ | — | — | **Shipped** — `proxyprotocol` accepts v1/v2 headers from trusted upstream CIDRs, keying rules, limits, metrics, and logs on the real client. |
| ~~**Token-bucket bandwidth throttle**~~ | — | — | **Shipped** — `ratelimit.byterate` is now a smooth per-client token-bucket throttle (TCP shaped, UDP policed), plus a per-rule `bandwidth:` selector that throttles each matching CONNECT session. Slows rather than drops/tears down. |
| ~~**ACME / Let's Encrypt TLS**~~ | — | — | **Shipped** — `tls.acme.*` obtains and auto-renews certificates via the TLS-ALPN-01 challenge on the TLS listener (port 443), no certbot/cron. Dante has no TLS at all. |
| **Geo / ASN access rules** | Med | M | `from`/`to` by country or ASN (optional MaxMind dataset). Modern access control Dante lacks natively. |
| **Audit log + OpenTelemetry** | Med | S–M | Per-rule metrics, a structured audit stream (who → where, rule hit, bytes), and optional OTel traces. Extends an existing strength. |
| **Transparent / intercept mode (Linux)** | Med | L | TPROXY/redirect ingress so unmodified apps are proxied without SOCKS awareness — the modern answer to Dante's socksify preload library. |
| **Happy Eyeballs (RFC 8305) for CONNECT** | Med | M | Concurrent dual-stack dialing for faster, more robust connects (builds on the existing all-address fallback). |

## Platform & packaging

| Item | Value | Effort | Notes |
| --- | --- | --- | --- |
| ~~**ARM64 builds**~~ | — | — | **Shipped** — `aarch64` Linux and Windows ARM64 are in the release matrix, validated on every change by a CI cross-build job. |
| **macOS / *BSD as first-class** | Med | M | CI coverage, a `launchd` plist, and docs — closes the portability gap that keeps Dante ahead on Unix. |
| ~~**Container image**~~ (+ Helm/compose) | — | — | **Shipped** (image) — official multi-arch distroless image on GHCR, built from source. Helm chart / compose examples remain a follow-up. |
| **Native packages** | Med | M | `deb`/`rpm`, Homebrew, and `winget` for first-class install. |

## Suggested first wave

Ordered for value-to-effort while leaning into Alighieri's identity
(~~hostname / domain ACL rules~~, ~~PROXY protocol ingress~~,
~~external auth hook~~, ~~token-bucket bandwidth throttle~~, and
~~ARM64 builds + container image~~ have shipped):

The first wave is complete. Next up: BIND, geo/ASN rules, macOS/BSD
first-class, audit/OTel, native packages (deb/rpm/Homebrew/winget), and a Helm
chart / compose examples. Deprioritized unless requested: SOCKS4, GSSAPI.

---

This is a proposal, not a commitment — priorities and scope are open to change.
Items can be promoted to tracked GitHub issues/milestones as they are picked up.
