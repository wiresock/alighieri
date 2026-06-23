# Changelog

All notable changes to Alighieri are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- The per-client abuse-control map is now capped. A connection spray from many
  distinct source IPs can no longer grow the map — or the periodic prune scan
  that runs under the accept lock — without bound: a new client at the cap evicts
  an idle (non-active) entry to make room. Active states are never evicted, so
  the map can still exceed the cap by the concurrently active set, but that is
  itself bounded by `maxconnections`, so memory and prune cost stay bounded
  regardless of source-IP diversity.
- The userlist is now read and hash-parsed off the runtime worker threads
  (`spawn_blocking`) during startup and reload, so a large userlist on slow
  storage cannot stall a worker.
- `connecttimeout` and `handshaketimeout` now reject `0`. Zero is not "disabled"
  for these — it makes `tokio::time::timeout` expire immediately and fail every
  connection — so it is refused at parse time instead of silently breaking the
  proxy. (`iotimeout`/`udptimeout` still accept `0` to mean a disabled idle
  timeout.)

### Fixed

- DNS resolution is now bounded by a deadline (`dns.timeout`, default 5s). The
  CONNECT path awaited resolution with no timeout (only the *connect* had one),
  and the UDP relay resolved domain targets inside its single client→remote loop,
  so a slow or wedged resolver could pin a connection permit or stall UDP
  forwarding. Resolution now fails with a timeout at the deadline (the CONNECT
  path replies host-unreachable; UDP drops the datagram). `dns.timeout: 0` is
  rejected, since it would time out every lookup.
- The config wizard's backup is now written to a fresh `create_new` temp file and
  atomically renamed over `<name>.bak`, instead of `std::fs::copy` after removing
  the old backup. A wizard run in an attacker-writable directory could otherwise
  have the backup write redirected through a symlink raced onto the backup path
  (the same hardening already applied to the userlist backup).
- UDP ASSOCIATE no longer silently drops IPv6 destinations. The single outbound
  socket was bound to `external` (default `0.0.0.0`, IPv4-only), so datagrams to
  an IPv6 target failed to send — and the error was discarded — while the TCP
  path already chose the socket family per target. When `external` is
  unspecified the outbound is now a dual-stack socket that reaches both families
  (IPv4 sent as `::ffff:` mapped); a concrete `external` still pins the source
  family. Outbound `send_to` failures are now counted via a new
  `alighieri_udp_send_failures_total` metric instead of being dropped silently.
- A `dns.cachettl` change now takes effect immediately on hot reload. Cache
  entries previously stored an absolute expiry computed from the TTL in force
  when they were cached, so lowering `dns.cachettl` (e.g. 1h → 60s) left existing
  entries alive for up to the old TTL — even though the resolver/cache is kept
  across reloads. Entries now record their insertion time and liveness is judged
  against the *current* TTL at lookup, so a reduced TTL shortens existing entries
  at once (and a raised one extends them).
- Userlist management (`alighieri user …`) no longer follows a symlink planted
  at a `.lock` or `.bak` sidecar path. Both are created in the userlist's own
  directory; if that directory was attacker-writable, a pre-placed symlink could
  previously be truncated (the lock's `set_len(0)`) or have credentials copied
  through it (the backup) when the command ran with elevated privileges. The
  lock now refuses a symlink and opens with `O_NOFOLLOW` on Unix, and the backup
  is written to a fresh `create_new` temp file and atomically renamed into place
  (rename replaces the link instead of following it). The temporary file was
  already safe (`create_new`/`O_EXCL`).
- UDP ASSOCIATE is now authorised before any resources are allocated: if the
  `socks` rules could not permit UDP for the client (a `command: connect` only
  policy, or a wildcard `block` that matches first), the request is rejected with
  "connection not allowed by ruleset" instead of binding a relay socket and
  replying success only for the per-datagram checks to drop every datagram while
  the association lingers until the idle timeout. The check honours first-match
  ordering and is conservative about wildcard blocks, so destination-restricted
  UDP policies are never falsely rejected; per-datagram destination checks are
  unchanged for clients that pass this gate.
- RFC 1929 authentication now rejects a zero-length username before it reaches
  an auth backend (notably `auth.command`, which would otherwise be handed a
  blank credential). An empty password is still accepted, since the userlist
  plaintext format permits one.
- Duplicate usernames in a userlist now log a warning (with the line number)
  identifying that a later entry overrides an earlier one, instead of silently
  shadowing it. The last entry still wins, so existing userlists keep loading.

### Documentation

- The per-rule hit metrics (`alighieri_rule_hits_total`,
  `alighieri_rule_named_hits_total`) are documented as best-effort: they may
  undercount under heavy load/scrape contention because the hot path never
  blocks on the metrics lock. Aggregate counters remain exact.

## [0.2.0] - 2026-06-21

### Changed

- The systemd installer (`scripts/alighieri.sh`) now makes Let's Encrypt work
  under the hardened unit with no manual edits: it provisions a writable
  `StateDirectory=` (`/var/lib/alighieri`) for the ACME certificate cache —
  previously `ProtectSystem=strict` left it read-only — and automatically grants
  `CAP_NET_BIND_SERVICE` when the config enables `tls.acme.*` or binds an
  `internal:` port below 1024, so the non-root service can bind `:443`.
  Otherwise the capability set stays empty. The need is detected by asking the
  binary (`alighieri --check --json`), so it honours case-insensitive keywords,
  `include:` files, and `internal:` last-wins. A new `--purge-state` uninstall
  flag (included in `--purge-all`) removes the cache directory.
- Minimum supported Rust version raised from 1.85 to **1.88**, required by the
  RUSTSEC-2026-0009-patched `time` crate that the ACME (Let's Encrypt) support
  pulls in transitively. Prebuilt binaries and the container image are
  unaffected; only building from source needs the newer toolchain.
- `ratelimit.byterate` is now a per-client **token-bucket bandwidth throttle**
  instead of a hard fixed-window cap. The `BYTES/WINDOW_SECONDS` value is
  reinterpreted as a sustained rate (`BYTES / WINDOW`) with a burst up to
  `BYTES`. TCP relays are *shaped* — slowed via read backpressure rather than
  torn down when the budget is spent — and UDP datagrams over the rate are
  policed (dropped), so a sustained legitimate flow is throttled smoothly
  instead of stalling or being cut. Both directions still share one per-client
  budget.

### Added

- `alighieri --check --json` now also reports the effective `listen` address
  (`internal:` is last-wins) and whether `acme` is enabled, so tooling can read
  the resolved configuration facts without reparsing the file.
- Automatic TLS certificates from Let's Encrypt (ACME) for the TLS listener:
  set `tls.acme.domains` (plus a `tls.acme.cache` directory and optional
  `tls.acme.email`) instead of `tls.certfile`/`tls.keyfile`, and Alighieri
  obtains and renews certificates in the background. Validation uses the
  TLS-ALPN-01 challenge answered on the listener itself, so it needs no port 80
  or DNS API but requires the listener reachable on port 443. A
  `tls.acme.staging` toggle selects the Let's Encrypt staging environment for
  testing.
- Official multi-arch (`linux/amd64`, `linux/arm64`) container image published to
  the GitHub Container Registry (`ghcr.io/wiresock/alighieri`) on each release,
  built on a distroless non-root base (no shell, `--read-only`-friendly). A
  `Dockerfile` builds it from source by cross-compiling per target arch.
- ARM64 release binaries: `aarch64-unknown-linux-gnu` and
  `aarch64-pc-windows-msvc` are now built and attached to releases, validated on
  every change by a CI cross-build job.
- Per-rule `bandwidth: BYTES/WINDOW_SECONDS` selector on `socks` rules: throttles
  each matching CONNECT relay with a per-session token bucket (sustained
  `BYTES / WINDOW`, burst up to `BYTES`), shaped like `ratelimit.byterate`. A
  session is bounded by both its per-client `byterate` and the matched rule's
  limit, whichever is tighter. Valid only in `socks` rules and applied to CONNECT
  (UDP keeps the per-client limit).
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

[Unreleased]: https://github.com/wiresock/alighieri/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/wiresock/alighieri/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/wiresock/alighieri/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/wiresock/alighieri/releases/tag/v0.1.0
