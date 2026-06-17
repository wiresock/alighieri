# Changelog

All notable changes to Alighieri are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
  config or import and edit an existing one.
- Userlist management commands: `user add`, `user delete`, `user list`, and
  `user verify`.
- Configuration validation (`--check`, `--check --json`), machine-readable
  reload metadata (`config metadata --json`), and a `--version` / `-V` flag.

[Unreleased]: https://github.com/wiresock/alighieri/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/wiresock/alighieri/releases/tag/v0.1.0
