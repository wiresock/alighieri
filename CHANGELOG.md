# Changelog

All notable changes to Alighieri are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `auth.command` external authentication hook: when set, username/password
  verification runs an external program (the username and password are written
  to its stdin; exit `0` allows) instead of the userlist, so credentials can be
  checked against LDAP / OIDC / PAM / anything via a script. Successful results
  are cached like the userlist path, and the `username` method no longer
  requires a `userlist` when a command is configured.
- `proxyprotocol` config option: accept the PROXY protocol (v1 text and v2
  binary) from trusted upstream load balancers (HAProxy, nginx, AWS/GCP NLBs),
  so `client` rules, abuse limits, metrics, and logs key on the real client
  address rather than the balancer. Only connections from the configured trusted
  CIDRs are honoured — and required to carry a header — while others are
  rejected, which prevents source-address spoofing.
- `socks` rule `to:` selectors now accept hostname patterns: `.example.com`
  matches the domain and all subdomains, and a bare `example.com` matches that
  exact host. They are matched against the requested destination *before* DNS
  resolution, so a rule allowlists the name the client asked for rather than
  whatever it resolves to. `from:` selectors and `client` rule `to:` remain
  IP/CIDR-only.

## [0.1.1] - 2026-06-17

### Added

- `udp.portrange` config option to bind the client-facing UDP relay socket (the
  `BND.PORT` advertised in the UDP ASSOCIATE reply) within a fixed inclusive
  port range instead of an OS-assigned ephemeral port, so the inbound UDP ports
  can be opened predictably on a firewall. Unset keeps the previous ephemeral
  behaviour.

## [0.1.0] - 2026-06-17

Initial public release. Dual-licensed under `AGPL-3.0-or-later`, with a
commercial license available for proprietary use (see
[`LICENSING.md`](LICENSING.md)).

### Added

- SOCKS5 (RFC 1928) TCP `CONNECT` and UDP `ASSOCIATE` — including IPv4-mapped
  clients on dual-stack `[::]` listeners — with username/password authentication
  (RFC 1929) backed by Argon2id userlist hashes and a verified credential cache.
- Dante-inspired configuration with deny-by-default `client` / `socks` ACL
  rules — CIDR, port, command, protocol, and auth-method selectors, across IPv4
  and IPv6 — plus named rules and `include` support.
- DNS resolution policy: address-family preference, all-address TCP fallback,
  post-resolution deny categories, and optional answer caching with request
  coalescing.
- Optional Prometheus-style metrics endpoint; structured text/JSON logging with
  size-based rotation and a non-blocking background writer.
- Per-client rate limits and abuse controls (connection rate, auth-failure
  rate, concurrent connections, and a `ratelimit.byterate` hard cap that logs a
  warning when a client trips it).
- Relay tuning for sustained high-rate UDP: larger kernel socket buffers and
  resilience to transient `recv_from` errors.
- Optional TLS-wrapped listener (rustls 0.23, `ring` provider).
- Hot reload of policy, DNS, auth, userlist, and timeout settings on `SIGHUP`
  (Unix) and via the Service Control Manager (Windows).
- Windows Service integration with Windows Event Log reporting.
- Linux systemd lifecycle manager (`scripts/alighieri.sh`): install, upgrade,
  uninstall, and status, with a self-bootstrapping standalone mode and an
  `install-linux.sh` compatibility shim.
- A short-lived, loopback-only configuration wizard that can generate a new
  config or import and edit an existing one; it logs to stdout by default, with
  file logging opt-in.
- Userlist management commands: `user add`, `user delete`, `user list`, and
  `user verify`.
- Configuration validation (`--check`, `--check --json`), machine-readable
  reload metadata (`config metadata --json`), and a `--version` / `-V` flag.

[Unreleased]: https://github.com/wiresock/alighieri/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/wiresock/alighieri/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/wiresock/alighieri/releases/tag/v0.1.0
