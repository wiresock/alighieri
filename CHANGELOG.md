# Changelog

All notable changes to Alighieri are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Log a warning the first time a client trips `ratelimit.byterate` (UDP
  datagrams dropped / TCP relay torn down), so an exhausted byte cap is no
  longer a silent stall (previously only a metric moved).
- Relay robustness for sustained high-rate UDP: the relay sockets request
  larger kernel send/receive buffers (raise `net.core.{r,w}mem_max` to benefit),
  and a transient `recv_from` error no longer tears down the whole UDP
  association — only a sustained run of failures does.

### Changed

- Dual licensing: Alighieri remains available under `AGPL-3.0-or-later`, and a
  commercial license is now offered for proprietary use. See
  [`LICENSING.md`](LICENSING.md).
- Document `ratelimit.byterate` as a hard per-window drop cap (not a throttle),
  with sizing guidance, in the README and the sample config.

## [0.1.0]

Initial release.

### Added

- SOCKS5 (RFC 1928) TCP `CONNECT` and UDP `ASSOCIATE`, with username/password
  authentication (RFC 1929) backed by Argon2id userlist hashes and a verified
  credential cache.
- Dante-inspired configuration with deny-by-default `client` / `socks` ACL
  rules — CIDR, port, command, protocol, and auth-method selectors, across IPv4
  and IPv6 — plus named rules and `include` support.
- DNS resolution policy: address-family preference, all-address TCP fallback,
  post-resolution deny categories, and optional answer caching with request
  coalescing.
- Optional Prometheus-style metrics endpoint; structured text/JSON logging with
  size-based rotation and a non-blocking background writer.
- Per-client rate limits and abuse controls (connection rate, auth-failure
  rate, concurrent connections, byte rate).
- Optional TLS-wrapped listener (rustls 0.23, `ring` provider).
- Hot reload of policy, DNS, auth, userlist, and timeout settings on `SIGHUP`
  (Unix) and via the Service Control Manager (Windows).
- Windows Service integration with Windows Event Log reporting.
- A short-lived, loopback-only configuration wizard that can generate a new
  config or import and edit an existing one.
- Userlist management commands: `user add`, `user delete`, `user list`, and
  `user verify`.
- Configuration validation (`--check`, `--check --json`) and machine-readable
  reload metadata (`config metadata --json`).

[Unreleased]: https://github.com/wiresock/alighieri/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/wiresock/alighieri/releases/tag/v0.1.0
