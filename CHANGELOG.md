# Changelog

All notable changes to Alighieri are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Alighieri now warns at startup and on reload when the no-authentication
  (`none`) SOCKS method is offered on a non-loopback `internal` listener. `none`
  is offered by default and whenever `socksmethod` lists it (e.g. `username
  none`); combined with permissive `socks`/`client` rules that is an open proxy.
  The warning points to dropping `none` from `socksmethod`, tightening the rules,
  or binding `internal` to loopback. Loopback listeners (including IPv4-mapped)
  are not flagged.
- Concurrent system DNS lookups are now capped (128 per resolver). `getaddrinfo`
  runs on a blocking thread that a timeout cannot cancel, so a DNS outage with
  many unique names could otherwise leave an unbounded number of orphaned blocking
  lookups running and starve Tokio's blocking pool — which also serves userlist
  reads and other blocking work. Lookups beyond the cap now wait for a slot
  (bounded by `dns.timeout`) rather than piling up, and the slot is held until the
  real OS lookup returns, not freed early when a caller times out. Coalesced
  lookups for the same name still share one slot, so normal traffic is unaffected.
- A name whose DNS lookup times out is now briefly remembered (a ~2s backoff), so
  a burst of requests for a wedged name fails fast instead of each starting — and
  waiting `dns.timeout` on — its own uncancellable system lookup. The window is
  short and applies only to timeouts (not to definitive "no such host" answers),
  so a name that recovers is retried within a couple of seconds; it works
  regardless of `dns.cachettl` (positive answer caching can be off).
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
- Configuration settings now reject trailing tokens instead of silently ignoring
  them: numeric and boolean settings (e.g. `maxconnections`, `dns.tryall`), the
  `internal:`/`metrics.listen:`/`external:` addresses, and single-keyword settings
  (`logformat`, `dns.prefer`, and the `dns.cachettl`/`auth.cachettl`
  `off`/`none`/`disabled` keyword). A typo like `dns.tryall: yes maybe`,
  `logformat: json text`, or `internal: 127.0.0.1 port = 10 80` now fails to parse
  rather than quietly using only the first value.
- A `ratelimit.byterate` rate change now retunes every live per-client throttle
  bucket in place the moment the config reloads, so a client's in-flight flows
  pick up the new rate immediately — the bucket is shared with the client's
  connections, matching the documented "existing flows pick up a new rate." The
  retune previously ran only when a client was next admitted, so a long-lived
  client that did not reconnect kept its old rate until it did. Enabling or
  disabling `byterate` continues to take effect per connection: an in-flight flow
  keeps the bucket (or lack of one) it was admitted with.

### Fixed

- The `proxyprotocol` trust gate now canonicalizes the peer address before
  matching it against the trusted-upstream CIDRs, so a trusted IPv4 upstream that
  reaches a dual-stack (`::`) listener as an IPv4-mapped address (`::ffff:a.b.c.d`)
  is recognised instead of being rejected. The raw address was passed to
  `Cidr::contains`, which treats a mapped address as IPv6 and never matches an
  IPv4 CIDR — so enabling `proxyprotocol` with IPv4 trust entries on a dual-stack
  listener dropped every connection from the legitimate upstream. Other rule
  paths already canonicalize; this brings the trust check in line.
- The userlist and config-wizard backups now refuse a symlinked *source* path,
  not just a symlinked `.bak` destination. The file being backed up was opened
  with a plain `File::open`, which follows a symlink, so a symlink planted at the
  userlist/config path could redirect the copy and stream an arbitrary target
  file (e.g. credentials read out of another file) into `.bak` under a privileged
  run. The source is now opened `O_NOFOLLOW` on Unix and must be a regular file;
  the `.bak` destination was already protected by the temp-file + atomic rename.
- A `socks`/`client` rule address selector now rejects stray or misspelled tokens
  instead of silently ignoring them. The parser recognised only an exact `port`
  token and dropped anything else, so a typo like `to: 0.0.0.0/0 ports = 443`
  (note the trailing `s`) parsed as *no port restriction* — i.e. **all ports** —
  silently broadening an allow rule. A token after the address that is not `port`,
  an extra word before `port`, or garbage after the range is now a parse error.
  The documented `ADDR port = RANGE` form still parses (the `=` stays optional,
  e.g. `port 443`, and ranges like `port = 1024 - 2000` are unchanged).
- A present-but-empty `protocol:` or `command:` selector in a `socks`/`client`
  rule is now a parse error instead of silently meaning *any*. An empty selector
  parsed to an empty set, which the matcher treats as a wildcard, so a directive
  left without a value (e.g. `protocol:` with the intended values dropped, or
  `protocol: command: connect` where the next keyword swallows `protocol`'s value)
  broadened the rule rather than restricting it. Each present selector must now
  carry at least one value; omitting the directive entirely still means "any" for
  that axis. (`method:` already required a value; this extends the same rule to
  `protocol:` and `command:`.)
- Tokens after a rule's closing `}` are now a parse error instead of being
  silently discarded. The block reader stopped at the closing brace, so a
  selector typed *outside* the braces was dropped, leaving the rule broader than
  written. For example, `socks pass { to: 0.0.0.0/0 } command: connect` kept any
  command rather than just `connect`, because the trailing selector was ignored.
  A second rule crammed onto the same line is likewise rejected now; comments
  after `}` are still fine.
- The UDP ASSOCIATE idle timeout is no longer refreshed by traffic the relay
  rejects. Activity was marked *before* a datagram was validated, so a spoofed or
  unrelated source datagram, a malformed header, a fragment, or even bytes on the
  TCP control channel could keep an association — and its relay socket and port —
  alive past `udptimeout`. An off-path host that learned the relay port could
  pin associations open and, with a configured `udp.portrange`, exhaust it. The
  idle timer is now refreshed only once a datagram is fully validated and
  authorized (client direction) or matched to a locked client endpoint (remote
  direction); control-channel data never refreshes it (only its close tears the
  association down). A validated, authorized datagram still counts as activity
  even if the token bucket then polices it, since the client is genuinely active.
- UDP ASSOCIATE replies are now accepted only from a remote the client has
  actually sent to. The relay forwarded any datagram arriving on the outbound
  socket once the client endpoint was locked, so an off-path host that learned
  the socket's port could inject unsolicited UDP to the client. Each association
  now records the destination IPs the client sends to (bounded, with the
  least-recently-recorded evicted at the cap) and drops a reply whose source IP
  is not among them. Matching is on the canonical IP (port-agnostic), so a server
  that answers from a different port still works.
- `maxconnections` and `logrotate.keep` no longer truncate a value too large for
  the platform's pointer width. They were cast with `u64 as usize`, which wraps a
  value above `usize::MAX` on a 32-bit target; the value is now rejected at parse
  time instead.
- `maxconnections` and `logrotate.keep` are now also bounded at the top.
  `maxconnections` is passed to `Semaphore::new`, which panics above
  `Semaphore::MAX_PERMITS`, so an absurd value crashed the server at startup;
  `logrotate.keep` drives an O(n) rename loop on each rotation, so an absurd value
  stalled logging. Both are now rejected during configuration validation.
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
- The background ACME certificate-renewal task is now aborted when the `Server`
  is dropped, instead of being left running detached. This prevents a leaked
  task when a server is bound and dropped without running to process exit.
- The ACME certificate cache directory is now created owner-only (mode `0700` on
  Unix), and a pre-placed symlink (or non-directory) at its path is rejected.
  `ensure_writable_dir` used `create_dir_all`, which silently follows a symlink,
  so on a console/custom deployment without the systemd unit's
  `StateDirectoryMode=0750` an attacker who could write the parent could redirect
  the ACME account key and issued certificates, and the directory could be
  group/other-readable. An existing directory is tightened to `0700` best-effort
  (a cache owned by another user only warns). The write-probe was already
  symlink-safe (`create_new`).
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
