# Alighieri

[![CI](https://github.com/wiresock/alighieri/actions/workflows/ci.yml/badge.svg)](https://github.com/wiresock/alighieri/actions/workflows/ci.yml)
[![Security audit](https://github.com/wiresock/alighieri/actions/workflows/audit.yml/badge.svg)](https://github.com/wiresock/alighieri/actions/workflows/audit.yml)
[![License: AGPL-3.0+ or Commercial](https://img.shields.io/badge/license-AGPL--3.0%2B%20or%20Commercial-blue.svg)](LICENSING.md)

**A** **LIGH**tweight, **I**ntuitive, **E**fficient **R**ust **I**mplementation for secure asynchronous SOCKS5 proxying.

Alighieri speaks SOCKS5 (RFC 1928/1929) with TCP `CONNECT` and UDP `ASSOCIATE`,
configured through a small, Dante-inspired rule language. It is aimed at
operators who want explicit, deny-by-default access control — CIDR, port,
command, protocol, and auth-method filters, Argon2id-hashed credentials, DNS
safety policy, and per-client rate limits — in a single binary that runs as a
console process or a native Windows Service.

New to it? Jump to [Quick start](#quick-start), or let the
[configuration wizard](#configuration-wizard) write your first config.

## Contents

- [Features](#features)
- [Quick start](#quick-start)
  - [Container image](#container-image)
- [Configuration wizard](#configuration-wizard)
- [Configuration](#configuration)
  - [Settings](#settings)
  - [Rules](#rules)
  - [Userlist format](#userlist-format)
  - [Hot reload](#hot-reload)
- [Linux service (systemd)](#linux-service-systemd)
- [Windows Service](#windows-service)
- [Architecture](#architecture)
- [Benchmarks](#benchmarks)
- [Comparison with Dante](#comparison-with-dante)
- [Security considerations](#security-considerations)
- [License](#license)

## Features

- **RFC 1928/1929** SOCKS5 with TCP CONNECT and UDP ASSOCIATE
- **Dante-inspired** line-oriented configuration (`client` / `socks` rule blocks)
- **Access control** with CIDR selectors, port ranges, command/protocol/method filters
- **Username/password** authentication with Argon2id userlist hashes
- **Deny-by-default** rule evaluation (first match wins)
- **Structured logs** with optional file output and size-based rotation
- **DNS policy controls** for address-family preference, caching, and unsafe ranges
- **Prometheus-style metrics** on an optional local HTTP endpoint
- **Optional TLS listener** for clients that can wrap SOCKS5 in TLS, with
  automatic **Let's Encrypt (ACME)** certificates via TLS-ALPN-01
- **Per-client abuse controls** for connection and auth-failure rates, plus a
  token-bucket **bandwidth throttle** (TCP shaped, UDP policed)
- **Windows Event Log** service lifecycle and startup failure events
- **Hot reload** for policy, DNS, timeout, auth, and userlist changes
- **Configuration wizard** — generate or edit a config from a short-lived, loopback-only web UI
- **Async** — built on [Tokio](https://tokio.rs) for high-performance I/O
- **Portable** — first-class on Windows and Linux; macOS and *BSD are not yet
  officially supported (no CI coverage)
- **Secure defaults** — no auth required? Think again. The default config still lets you build restrictive rules.

## Quick start

Prebuilt Linux and Windows binaries are attached to each
[release](https://github.com/wiresock/alighieri/releases). To build
from source instead, you need a stable Rust toolchain (1.88 or newer):

```sh
cargo build --release
./target/release/alighieri doc/alighieri.conf
```

Or with Cargo directly:

```sh
cargo run --release -- doc/alighieri.conf
```

That starts a no-auth SOCKS5 proxy on `127.0.0.1:1080`. From another shell,
route a request through it to confirm it works:

```sh
curl --socks5-hostname 127.0.0.1:1080 https://example.com
```

Validate a configuration without starting the server:

```sh
cargo run -- --check doc/alighieri.conf
cargo run -- --check --json doc/alighieri.conf
cargo run -- config metadata --json
```

Starter templates live under [`doc/templates`](doc/templates). They are meant
as safe wizard/UI seeds and should still be reviewed before deployment.

Generate or edit a configuration through a short-lived local web UI — see
[Configuration wizard](#configuration-wizard) for the full workflow:

```sh
cargo run -- config wizard --output alighieri.conf   # generate a new file
cargo run -- config wizard --import alighieri.conf    # edit an existing file
```

Manage hashed userlist entries:

```sh
alighieri user add alice --userlist /etc/alighieri/users
alighieri user list --userlist /etc/alighieri/users
alighieri user delete alice --userlist /etc/alighieri/users
```

On Linux, install and start Alighieri as a hardened systemd service (details
under [Linux service (systemd)](#linux-service-systemd)):

```sh
sudo ./scripts/alighieri.sh           # install, or open the management menu if already installed
```

On Windows, install and start Alighieri as a native Windows Service:

```powershell
alighieri service install --config "C:\ProgramData\Alighieri\alighieri.conf"
alighieri service start
alighieri service reload
```

### Container image

Multi-arch (`linux/amd64`, `linux/arm64`) images are published to the GitHub
Container Registry. Mount a config and publish the port:

```sh
docker run --rm -p 1080:1080 \
  -v "$(pwd)/alighieri.conf:/etc/alighieri/alighieri.conf:ro" \
  ghcr.io/wiresock/alighieri:latest
```

In that config set `internal: 0.0.0.0 port = 1080` so the listener is reachable
from outside the container, and `logoutput: stdout` so logs reach `docker logs`.
The image is distroless and runs as a non-root user (uid 65532) with no shell,
so it also works under `--read-only`. Because of the non-root user, the
bind-mounted config must be readable by it — a host-only `chmod 600` config will
fail with a permission error, so make it world-readable or owned by uid 65532.
Use `:latest` or pin a release with `ghcr.io/wiresock/alighieri:X.Y.Z`.

## Configuration wizard

Alighieri can generate — or edit — its configuration through a short-lived
local web UI, so operators don't have to hand-write the Dante-inspired syntax:

```sh
alighieri config wizard                       # generate ./alighieri.conf
alighieri config wizard --output proxy.conf   # choose the output path
alighieri config wizard --import proxy.conf   # load an existing file to edit
```

The wizard starts a one-shot HTTP server, prints a URL containing a one-time
token, and exits as soon as one configuration is saved. It is configuration
*generation*, not remote administration:

- it binds to loopback only (override the port with `--listen 127.0.0.1:PORT`,
  which is still validated to stay on a loopback address);
- the URL carries a random per-run token, and requests without it are refused;
- it never exposes runtime control, credential browsing, or service management.

Two built-in templates seed the form:

- **Local, no auth** — a loopback listener for apps on the same machine.
- **LAN, username/password** — a `0.0.0.0` listener backed by an Argon2id
  userlist.

Whatever you choose, the result is validated with the real parser before it is
written, saved atomically, and the previous file (if any) is preserved as
`<name>.bak`.

### Editing an existing configuration

`--import PATH` loads an existing file into the form and, unless `--output`
overrides it, writes back to the same path. The form only models the fields the
two templates expose — listener, trusted-client range, auth method, userlist,
and log file — so importing a richer configuration is **loss-aware**: before you
save, the wizard lists every setting it cannot reproduce, both on the console
and in a banner above the form. Flagged areas include the TLS listener, the
metrics endpoint, rate limits, custom timeouts or DNS policy, the auth cache
TTL, and any extra or customised ACL rules. The original is still kept as
`<name>.bak`, so a dropped setting can be restored.

## Configuration

The configuration language is inspired by Dante's `sockd.conf` but is an
independent, simplified implementation. A minimal permissive example:

```conf
# Interface to listen on.
internal: 127.0.0.1 port = 1080

# Address used for outbound connections (0.0.0.0 = OS default).
external: 0.0.0.0

# Offer no-auth and username/password. 'username' requires a userlist.
socksmethod: none username
userlist: /etc/alighieri/users

connecttimeout: 30
handshaketimeout: 10
iotimeout: 0        # 0 = no idle timeout
udptimeout: 60
maxconnections: 1024
logoutput: stdout
logformat: text
dns.prefer: system
dns.tryall: false
# dns.cachettl: 60
# metrics.listen: 127.0.0.1:9090
# tls.certfile: /etc/alighieri/tls/server.crt
# tls.keyfile: /etc/alighieri/tls/server.key
# ratelimit.connectionrate: 60/60
# ratelimit.authfailurerate: 5/300
# ratelimit.concurrentconnections: 10
# ratelimit.byterate: 10MiB/60

# Optionally split policy into separate files.
# include: conf.d/*.conf

# Admit connections from localhost and the LAN.
client pass "localhost" {
    from: 127.0.0.1 to: 0.0.0.0/0
}
client pass "lan" {
    from: 10.0.0.0/8 to: 0.0.0.0/0
}

# Deny SOCKS access to loopback destinations.
socks block "deny-loopback" {
    from: 0.0.0.0/0 to: 127.0.0.0/8
}

# Allow everything else.
socks pass "allow-default" {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    protocol: tcp udp
    command: connect udpassociate
}
```

### Settings

| Setting            | Default         | Description                                          |
|--------------------|-----------------|------------------------------------------------------|
| `include`          | —               | Include another config file or final-component glob  |
| `internal`         | — (required)    | Listening address (`IP port = N` or `IP:PORT`)       |
| `external`         | `0.0.0.0`       | Source address for outbound connections              |
| `proxyprotocol`    | —               | Trusted upstream CIDR(s) allowed to send a PROXY protocol (v1/v2) header; the real client address then drives rules/limits/logs. Unset disables it |
| `socksmethod`      | `none`          | Offered auth methods (`none`, `username`)            |
| `userlist`         | —               | Path to `username:password-or-hash` file             |
| `auth.command`     | —               | External verifier program; runs per credential (username/password on stdin, exit 0 = allow) instead of the userlist |
| `auth.cachettl`    | `300`           | Reuse successful credential checks for this many seconds (`0` disables) |
| `connecttimeout`   | `30`            | Seconds to wait for outbound connects                |
| `handshaketimeout` | `10`            | Seconds to wait for SOCKS greeting/auth/request      |
| `iotimeout`        | `0` (disabled)  | Idle timeout for established TCP relays (seconds)    |
| `udptimeout`       | `60`            | Idle timeout for UDP associations (seconds)          |
| `udp.portrange`    | —               | Bind the client-facing UDP relay port (`BND.PORT`) within a fixed `MIN-MAX` range for firewalling; unset uses an ephemeral port |
| `udp.strictreply`  | `true`          | Require UDP replies from the exact remote `host:port` contacted; set `false` to relax to host-only for compatibility (see below) |
| `maxconnections`   | `1024`          | Maximum concurrent client TCP connections            |
| `shutdown.draintimeout` | `10`       | Seconds shutdown waits for in-flight connections before aborting the rest (`0` cuts immediately) |
| `logoutput`        | `stdout`        | One or more of `stdout`, `stderr`, `file`            |
| `logfile`          | —               | File path used when `logoutput` includes `file`      |
| `logformat`        | `text`          | Log encoding: `text` or `json`                       |
| `logrotate.size`   | `10MiB`         | Rotate active log file above this size               |
| `logrotate.keep`   | `5`             | Number of rotated log files to retain                |
| `dns.prefer`       | `system`        | DNS address ordering: `system`, `ipv4`, or `ipv6`    |
| `dns.tryall`       | `false`         | Try every resolved address for TCP CONNECT           |
| `dns.deny`         | —               | Deny resolved IP categories after DNS lookup         |
| `dns.cachettl`     | `0`             | Cache domain lookup answers for this many seconds    |
| `dns.timeout`      | `5`             | Deadline (seconds) for resolving one destination name |
| `metrics.listen`   | —               | Optional HTTP metrics endpoint address (loopback unless `metrics.allowpublic`) |
| `metrics.allowpublic` | `false`      | Allow a non-loopback `metrics.listen`; required because the endpoint is unauthenticated |
| `tls.certfile`     | —               | PEM certificate chain for TLS-wrapped client traffic |
| `tls.keyfile`      | —               | PEM private key for TLS-wrapped client traffic       |
| `tls.acme.domains` | —               | Domains for automatic Let's Encrypt certs (TLS-ALPN-01, needs port 443) |
| `tls.acme.email`   | —               | Optional ACME account contact e-mail                 |
| `tls.acme.cache`   | —               | Directory persisting the ACME account and certificates |
| `tls.acme.staging` | `off`           | Use Let's Encrypt staging (testing; untrusted certs) |
| `ratelimit.connectionrate` | —        | Per-client TCP accepts as `COUNT/WINDOW_SECONDS`     |
| `ratelimit.authfailurerate` | —       | Per-client auth failures as `COUNT/WINDOW_SECONDS`   |
| `ratelimit.concurrentconnections` | —  | Per-client concurrent accepted TCP connections       |
| `ratelimit.byterate` | —             | Per-client bandwidth **throttle** (both directions) as `BYTES/WINDOW_SECONDS`: TCP is shaped (slowed), UDP policed (excess dropped) |

When `logfile` is set, file logging is enabled even if `file` is omitted from
`logoutput`. Size suffixes accept bytes or `K`, `KB`, `KiB`, `M`, `MB`, `MiB`,
`G`, `GB`, and `GiB`.

When Alighieri runs behind a TCP load balancer (HAProxy, nginx `stream`, an
AWS/GCP Network Load Balancer), set `proxyprotocol` to the balancer's address
range so the original client address is recovered from the PROXY protocol header
it prepends:

```conf
proxyprotocol: 10.0.0.0/8        # one or more trusted upstream CIDRs
```

Both v1 (text) and v2 (binary) are accepted. Only connections from the listed
CIDRs are trusted (and must send a header); any other source is rejected, so a
client cannot forge its address — keep the listener firewalled to the balancer.

`include` loads additional configuration files before continuing with the
current file. Relative include paths are resolved from the file that declares
them, and simple wildcards are supported in the final path component:

```conf
include: conf.d/*.conf
```

Included files are processed in sorted path order. Include cycles are rejected
and configuration errors report file and line context.

`dns.deny` accepts `private`, `linklocal`, `loopback`, `multicast`,
`unspecified`, `documentation`, and `reserved`. For IPv4, `reserved` covers the
IANA special-purpose ranges the other categories do not — `0.0.0.0/8`,
`100.64.0.0/10` (CGNAT), `192.0.0.0/24`, `192.88.99.0/24` (6to4), `198.18.0.0/15`
(benchmarking), and `240.0.0.0/4` (including the broadcast address). For IPv6 it
instead overlaps the specific categories, matching `::` (unspecified), `::1`
(loopback), and `2001:db8::/32` (documentation). Private, link-local, multicast,
and the `TEST-NET` documentation ranges have their own categories, so combine
`reserved` with them (e.g. `private linklocal loopback reserved`) for broader
coverage. For example:

```conf
dns.prefer: ipv4
dns.tryall: true
dns.deny: private linklocal loopback reserved
dns.cachettl: 60
```

DNS deny rules apply to both domain names and IP literals before ACL
evaluation. TCP CONNECT can try later DNS answers when `dns.tryall` is enabled;
UDP ASSOCIATE uses the first allowed answer. `dns.cachettl` is disabled by
default; set it to a positive number of seconds to cache domain lookups, or to
`0`/`off` to keep every lookup live.

For UDP ASSOCIATE, the relay forwards a reply to the client only from a remote
the client has actually sent to, so an off-path host cannot inject unsolicited
datagrams. By default the match is the exact `host:port` the client contacted,
which blocks a co-located attacker on the same host but a different port (notably
on shared hosts or loopback). Set `udp.strictreply: false` to relax the match to
host-only (any source port on a contacted host) for servers that legitimately
answer from a different port (e.g. TFTP) — at the cost of that protection.

When `metrics.listen` is set, Alighieri serves Prometheus-style text metrics at
`/metrics`. The endpoint is unauthenticated and exposes operational counters and
rule labels, so it must be bound to loopback:

```conf
metrics.listen: 127.0.0.1:9090
```

Binding it to a non-loopback (or unspecified, e.g. `0.0.0.0`) address is refused
at startup unless you explicitly opt in — only do so behind your own network
access controls (a firewall, private network, or an authenticating reverse
proxy):

```conf
metrics.listen: 0.0.0.0:9090
metrics.allowpublic: true
```

The endpoint reports connection counts, auth failures, SOCKS allow/deny counts,
TCP and UDP relay byte counters, UDP association counters, and ACL rule hits by
scope, verdict, and config source line. Named ACL rule hits are also reported
through `alighieri_rule_named_hits_total`, which adds the optional rule name as
a label. It also reports rate-limit events.

The per-rule hit counters (`alighieri_rule_hits_total` and
`alighieri_rule_named_hits_total`) are **best-effort**: to keep the
authorisation hot path non-blocking, an increment is dropped if it would
contend with another update or an in-progress scrape, so these series can
slightly undercount under heavy load. The aggregate counters (connections,
allow/deny totals, bytes, rate-limit events) are exact.

Optional per-client abuse controls are keyed by source IP. The connection and
auth-failure rates use fixed windows; `byterate` is a token-bucket bandwidth
throttle:

```conf
ratelimit.connectionrate: 60/60       # 60 accepted TCP connections per minute
ratelimit.authfailurerate: 5/300      # 5 failed auth attempts per 5 minutes
ratelimit.concurrentconnections: 10   # 10 active accepted TCP connections
ratelimit.byterate: 10MiB/60          # bandwidth throttle (both directions) — see below
```

Changes apply on hot reload: the per-client throttle bucket is re-tuned in place
(so a client's existing flows pick up a new rate), and connection/auth-failure
accounting updates for new admissions.

> **`ratelimit.byterate` is a bandwidth throttle, not a hard cap.** The
> `BYTES/WINDOW_SECONDS` value is a sustained rate (`BYTES / WINDOW`) with a
> burst up to `BYTES`, metering both directions against one per-client budget.
> TCP relays are *shaped* — slowed with read backpressure — and UDP datagrams
> over the rate are *policed* (dropped, since delaying real-time traffic is
> worse), so a sustained flow is throttled smoothly instead of stalling or being
> cut. For per-destination throttling, a `socks` rule can add a per-session
> [`bandwidth`](#rules) limit.

When both `tls.certfile` and `tls.keyfile` are set, Alighieri expects clients to
complete a TLS handshake before sending the SOCKS5 greeting. SOCKS5 clients
must explicitly support TLS or connect through a local TLS wrapper:

```conf
tls.certfile: /etc/alighieri/tls/server.crt
tls.keyfile: /etc/alighieri/tls/server.key
```

Instead of certificate files, Alighieri can obtain and renew certificates
automatically from **Let's Encrypt (ACME)** — no certbot, no cron:

```conf
tls.acme.domains: proxy.example.com
tls.acme.email: admin@example.com         # optional account contact
tls.acme.cache: /var/lib/alighieri/acme   # persists the account + certs
# tls.acme.staging: on                    # Let's Encrypt staging while testing
```

Validation uses the **TLS-ALPN-01** challenge, answered on the TLS listener
itself — so it needs no port 80 and no DNS API, but the listener **must be
reachable at each domain on port 443** (set `internal` to `:443`, directly or
behind a forwarder). The cache directory persists the ACME account and issued
certificates so they survive restarts without re-requesting (which would hit
Let's Encrypt's rate limits), and certificates renew in the background with no
restart. `tls.acme.*` is mutually exclusive with `tls.certfile`/`tls.keyfile`.

Because the challenge is validated by an inbound connection, ACME interacts with
the admission gates. With **`proxyprotocol`** enabled, any validation connection
that reaches the listener **without** a trusted PROXY header (for example Let's
Encrypt connecting directly) is rejected by the proxy-protocol gate, so
issuance/renewal fails unless every validation connection is proxied through a
trusted PROXY-protocol upstream doing TCP passthrough (the proxy warns when both
are set). Likewise, don't set
`ratelimit.connectionrate`/`ratelimit.concurrentconnections` so tight that the
handful of validation connections are rejected.

For a complete end-to-end walkthrough on a fresh public server — DNS, firewall,
running it, watching issuance, and proxying a request through the TLS listener —
see [doc/acme-tls-test.md](doc/acme-tls-test.md).

### Rules

Rules are evaluated **top-to-bottom**, **first match wins**. If no rule matches,
the request is **denied**.

- `client pass/block { from: CIDR [port = N] to: CIDR [port = N] }` —
  evaluated at connection admission.
- `socks pass/block { from: CIDR [port = N] to: CIDR|HOSTNAME [port = N] [command: ...] [protocol: tcp|udp] [method: none|username] [bandwidth: BYTES/WINDOW_SECONDS] }` —
  evaluated per SOCKS request.

Rules can optionally be named by placing a single token between the verdict and
the opening brace. Quoted names are accepted for readability:

```conf
socks pass "allow-web" {
    to: 0.0.0.0/0 port = 80-443
    command: connect
}
```

The matching rule name is included in structured logs and the
`alighieri_rule_named_hits_total` metric.

Omitted selectors match both IPv4 and IPv6. Explicit IPv4 CIDRs such as
`0.0.0.0/0` remain IPv4-only; add `::/0` in a separate rule for explicit
dual-stack matching. `to:` in a `client` rule refers to the proxy's own
accepting address; in a `socks` rule it refers to the request destination.

A `socks` rule `to:` can match the **requested destination hostname** instead of
an IP/CIDR. The hostname is matched **before** DNS resolution, so you allowlist
the name the client asked for rather than whatever it resolves to:

- `.example.com` — the domain **and all subdomains** (`example.com`,
  `api.example.com`, …).
- `example.com` — that exact host only.

```conf
# Allow only GitHub over TLS; everything else is denied by default.
socks pass "github" {
    to: .github.com port = 443
    command: connect
}
```

Hostname patterns are valid only in a `socks` rule `to:` — a `from:` selector
and a `client` rule `to:` stay IP/CIDR-only. An earlier `block { to: 10.0.0.0/8 }`
still rejects a domain that *resolves* into a denied range, so deny-by-default
and DNS-rebinding protection are preserved.

A `socks` rule may carry a **`bandwidth: BYTES/WINDOW_SECONDS`** limit that
throttles each matching **CONNECT** relay (a per-session token bucket: sustained
`BYTES / WINDOW` with a burst up to `BYTES`). It is enforced like
`ratelimit.byterate` — the flow is *shaped* (slowed), not torn down — and a
session is bounded by both its per-client `byterate` and the matched rule's
limit, whichever is tighter. `bandwidth` is valid only in a `socks` rule and
applies to CONNECT; UDP keeps the per-client limit.

```conf
# Throttle each bulk-download session to ~5 MiB/s, leave everything else alone.
socks pass "downloads" {
    to: .cdn.example.com port = 443
    command: connect
    bandwidth: 5MiB/1
}
```

### Userlist format

One entry per line. Argon2id entries generated by `alighieri user add` are
stored as Alighieri comment directives so they cannot collide with legacy
plaintext passwords:

```text
# /etc/alighieri/users
# alighieri:user:argon2:616c696365:$argon2id$v=19$m=19456,t=2,p=1$...
# alighieri:user:argon2:626f62:$argon2id$v=19$m=19456,t=2,p=1$...
```

Manage entries with:

```sh
alighieri user add alice --userlist /etc/alighieri/users
alighieri user list --userlist /etc/alighieri/users
alighieri user verify alice --userlist /etc/alighieri/users
alighieri user delete alice --userlist /etc/alighieri/users
```

Plaintext `username:password` entries remain supported for compatibility, but
hashed entries are preferred. The file should be readable only by the user
running Alighieri (`chmod 600`).

`user add` and `user delete` update the file under a lock, replace it
atomically, and keep the previous contents beside it as `<userlist>.bak` when
the file already existed.

Alighieri loads the userlist once when the proxy starts. After adding, updating,
or removing users, send SIGHUP on Unix to reload the running proxy process, or
run `alighieri service reload` on Windows for the change to take effect.

Because SOCKS clients open a new proxy connection per stream and Argon2id
verification is deliberately expensive, successful credential checks are
cached in memory for `auth.cachettl` seconds (default 300). The cache stores
a keyed tag derived with a per-process random salt — never the password — only
caches successes (failed attempts always pay the full hashing cost), and is
cleared whenever the configuration or userlist is reloaded. Set
`auth.cachettl: 0` to verify every handshake at full cost.

### External authentication

Set `auth.command` to delegate username/password verification to an external
program instead of the userlist — useful for LDAP, OIDC, PAM, or a corporate
auth service:

```conf
socksmethod: username
auth.command: /usr/local/bin/verify-user
```

For each attempt Alighieri runs the program and writes two newline-terminated
lines to its **stdin** — the username, then the password (never on the command
line or environment, which can leak). Exit status `0` allows the connection;
anything else, or a timeout, denies it. The script should read with `read -r`,
and credentials containing a newline or NUL byte are rejected to keep the
framing unambiguous. Successful results are cached exactly like the userlist
(`auth.cachettl`), and with `auth.command` set the `username` method no longer
requires a `userlist`. To bound resource use, at most 64 verifier processes run
concurrently; under a heavier burst the excess waits for a slot and is denied
(treated as a timeout) if it cannot start within the handshake timeout.

The value is split on whitespace into the program path and its arguments, with
no quoting — so a program path that itself contains spaces (for example
`C:\Program Files\...`) cannot be expressed directly. Point `auth.command` at a
space-free wrapper script (the usual pattern anyway, since the verifier
typically shells out to `ldapsearch`, `curl`, `pamtester`, and the like) and put
the real path inside it.

### Hot reload

On Unix, send SIGHUP to reload the configuration without restarting the
process:

```sh
kill -HUP <alighieri-pid>
```

On Windows, ask the installed service to reload through the Service Control
Manager:

```powershell
alighieri service reload
```

The new configuration is validated before it replaces the active runtime
policy. New client connections use the reloaded ACLs, DNS policy,
authentication settings, userlist, timeout values, and rate-limit settings.
Existing connections continue with the configuration they accepted under.

Listener addresses, `maxconnections`, metrics listener settings, TLS listener
settings, and logging sinks are process-level resources; changes to those
settings are reported in the logs and require a restart.

Tools and local setup UIs can inspect the same distinction with
`alighieri config metadata --json`.

## Linux service (systemd)

On Linux, [`scripts/alighieri.sh`](scripts/alighieri.sh) manages the whole
lifecycle as a hardened systemd service — install, upgrade, uninstall, and
status.

**Standalone (download just the script):**

```sh
curl -O https://raw.githubusercontent.com/wiresock/alighieri/main/scripts/alighieri.sh
chmod +x alighieri.sh
sudo ./alighieri.sh
```

When run outside a checkout it shallow-clones the repository into a temporary
directory to build the binary and read the default config, so the single file
is enough (needs `git` and a Rust toolchain on the host; or add
`--binary ./alighieri` to install a prebuilt binary and skip the build). The
clone is removed when the script exits.

**From a checkout:** run it directly — it uses an existing `target/release`
build if present, otherwise builds one, or takes a binary extracted from a
[release](https://github.com/wiresock/alighieri/releases):

```sh
sudo ./scripts/alighieri.sh                        # install, or manage if already installed
sudo ./scripts/alighieri.sh install --binary ./alighieri  # install a prebuilt binary
sudo ./scripts/alighieri.sh upgrade                # rebuild/replace the binary and restart
sudo ./scripts/alighieri.sh status                 # show binary, service, and config state
sudo ./scripts/alighieri.sh uninstall              # remove the service and binary
sudo ./scripts/alighieri.sh uninstall --purge-all  # also remove config, logs, and the user
```

Run with no command on an already-installed host to get an interactive menu
(status, logs, upgrade, reconfigure, uninstall). `upgrade` swaps in the new
binary — pre-flighting it with `--check` against the live config first — and
restarts, leaving your unit and config untouched; `install` (re-run) also
rewrites the unit and re-applies permissions. (The older
[`scripts/install-linux.sh`](scripts/install-linux.sh) remains as a thin
compatibility shim that forwards to `alighieri.sh`.)

The installer puts the binary at `/usr/local/bin/alighieri`, creates a
dedicated unprivileged `alighieri` system user, installs a default config to
`/etc/alighieri/alighieri.conf` (kept if it already exists; either way set to
`root:alighieri` mode `640`, readable only by the service user), and writes
`/etc/systemd/system/alighieri.service` before enabling and starting it.

The unit runs as the `alighieri` user with `NoNewPrivileges`,
`ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, a capability set restricted
to at most `CAP_NET_BIND_SERVICE` (see below), and a `@system-service` syscall
filter. The default config logs to stdout, which systemd captures into the
journal:

```sh
systemctl status alighieri      # service state
journalctl -u alighieri -f      # follow logs
systemctl reload alighieri      # SIGHUP hot reload after editing the config
systemctl stop alighieri
```

Editing `/etc/alighieri/alighieri.conf` and running `systemctl reload alighieri`
applies policy, DNS, auth, and timeout changes to *new* connections; existing
connections keep running under the configuration they were accepted with (see
[Hot reload](#hot-reload)). Binding a port below 1024 — including the `:443`
that ACME's TLS-ALPN-01 challenge needs — requires no hand-editing: when it
generates the unit, the installer grants `CAP_NET_BIND_SERVICE` if the config
uses a privileged `internal:` port or `tls.acme.*` (following `include:` files
too), and otherwise leaves the capability set empty. It also provisions a
writable `StateDirectory=` (`/var/lib/alighieri`) for the ACME certificate
cache, so `tls.acme.cache: /var/lib/alighieri/acme` works under
`ProtectSystem=strict`. Because the capability is baked into the unit at install
time, after switching to a privileged port or enabling ACME in an existing
deployment re-run `sudo ./scripts/alighieri.sh install` to regenerate the unit —
a plain `systemctl reload` keeps the old capability set.

### Tuning for sustained high-rate UDP

Alighieri enlarges its relay sockets' kernel buffers for high-throughput UDP
relaying (e.g. tunnelling a VPN) — it requests 4 MiB each. **On Linux** the
kernel clamps `SO_RCVBUF`/`SO_SNDBUF` to `net.core.rmem_max` /
`net.core.wmem_max` (commonly only ~208 KiB by default), so to actually get the
larger buffers (fewer dropped datagrams under bursts) raise those limits. Linux
also stores roughly double the requested value (kernel bookkeeping), so the
4 MiB request needs a limit of ~8 MiB:

```sh
sudo sysctl -w net.core.rmem_max=8388608 net.core.wmem_max=8388608
# persist:
echo 'net.core.rmem_max=8388608
net.core.wmem_max=8388608' | sudo tee /etc/sysctl.d/90-alighieri.conf
```

## Windows Service

The same `alighieri.exe` supports interactive console mode and Windows Service
mode. Service support is compiled only on Windows and is isolated under the
platform-specific module tree.

Recommended deployment path:

```text
C:\ProgramData\Alighieri\
├── alighieri.conf
└── logs\
    └── alighieri.log
```

Install, start, inspect, stop, and remove the service from an elevated
Administrator shell:

```powershell
alighieri service install --config "C:\ProgramData\Alighieri\alighieri.conf"
alighieri service start
alighieri service status
alighieri service reload
alighieri service stop
alighieri service uninstall
```

The installed service uses:

- service name: `Alighieri`
- display name: `Alighieri SOCKS5 Proxy Server`
- startup type: automatic
- account: `NT AUTHORITY\LocalService`
- log file: `C:\ProgramData\Alighieri\logs\alighieri.log`
- Event Log source: `Alighieri` in the Windows Application log
- recovery: restart on crash (after 5s, then 30s, then 60s; failure count resets
  after an hour), the Windows equivalent of systemd's `Restart=on-failure`
- accepts `STOP` and system `SHUTDOWN`, so an OS restart stops it cleanly: it
  stops accepting, drains in-flight connections for up to `shutdown.draintimeout`
  seconds (default 10; cutting any that remain), then flushes logs and reports a
  clean `Stopped` status

The installer validates the configuration before creating the service and the
start and reload commands validate the installed configuration before asking
the Service Control Manager to act on the service. Credentials stay in the
configured `userlist` file; the service command line stores only the
configuration file path. Service file logs rotate with the same
`logrotate.size`, `logrotate.keep`, and `logformat` settings as console file
logging.

Service install registers the `Alighieri` Event Log source. Service mode writes
startup, stop, reload-request, and startup/runtime failure events to the Windows
Application log. File logging remains the detailed operational log.

For an elevated manual smoke test covering install, start, reload, Event Log
inspection, stop, and uninstall, see
[`doc/windows-service.md`](doc/windows-service.md) and
[`doc/windows-service-smoke-test.ps1`](doc/windows-service-smoke-test.ps1).

## Architecture

```
 src/
 ├── lib.rs           # Module declarations and crate documentation
 ├── main.rs          # CLI entry point, logging setup, signal handling
 ├── errors.rs        # Crate-wide `Error` enum with SOCKS5 reply mapping
 ├── net.rs           # CIDR and port-range primitives
 ├── config.rs        # Dante-inspired parser and `Config` struct
 ├── acl.rs           # Rule evaluation engine (first-match-wins, deny-by-default)
 ├── auth.rs           # Username/password database with constant-time verification
 ├── socks5.rs        # RFC 1928/1929 wire-format helpers
 ├── connection.rs    # Per-client SOCKS5 state machine
 ├── platform/         # Platform-specific integrations such as Windows Service
 ├── runtime.rs        # Shared console/service runtime helpers
 ├── server.rs        # Accept loop with semaphore-based connection limit
 └── relay.rs         # TCP bidirectional relay + UDP associate relay
```

## Benchmarks

An end-to-end load generator lives in `examples/loadgen.rs`; it measures relay
throughput, connection-setup rate (with and without authentication), and UDP
associate packet rates against a self-hosted proxy (or, with `--proxy`, a
separately started proxy on the same host):

```sh
cargo run --release --example loadgen -- throughput --connections 8
```

See [`doc/benchmarks.md`](doc/benchmarks.md) for scenario details,
methodology, and recorded baselines.

## Comparison with Dante

[Dante](https://www.inet.no/dante/) (`sockd`, Inferno Nettverk) is the
long-standing C reference SOCKS server: full SOCKS4/5 including the BIND command
and GSSAPI, a client-side "socksify" preload library, and broad Unix
portability, hardened since the late 1990s. Alighieri borrows Dante's
configuration model but trades breadth (SOCKS4, BIND, GSSAPI, the client
library, exotic Unixes) for memory safety, first-class **Windows** support,
SOCKS-over-TLS, and built-in observability.

Dante capabilities below are drawn from its documented feature set and vary by
version; verify against the version you would deploy.

**Platforms & architecture**

| | Alighieri | Dante |
| --- | --- | --- |
| Linux | first-class (CI + systemd manager) | yes |
| Windows | native Service + Event Log | not supported |
| macOS / *BSD / Solaris / AIX | not officially supported (no CI coverage) | broadly supported |
| Language | Rust (memory-safe) | C |
| Process model | async, single process (Tokio tasks) | multi-process (preforked) / threaded |

**Protocol & commands**

| | Alighieri | Dante |
| --- | --- | --- |
| SOCKS5 (RFC 1928/1929) | yes | yes |
| SOCKS4 / 4a | no | yes |
| CONNECT | yes | yes |
| UDP ASSOCIATE | yes — dual-stack, IPv4-mapped handling, configurable `udp.portrange` | yes |
| BIND (reverse connect, e.g. active FTP) | no — RFC 1928 reply `0x07` (command not supported) | yes |
| IPv4 / IPv6 | yes / yes (dual-stack listeners) | yes / yes |
| Client socksify library (LD_PRELOAD) | no (server only) | yes (`socksify` / libsocks) |

**Authentication**

| | Alighieri | Dante |
| --- | --- | --- |
| None | yes | yes |
| Username/password (RFC 1929) | yes — Argon2id-hashed userlist + verified-credential cache | yes |
| GSSAPI / Kerberos | no | yes |
| PAM / system auth | no | yes |

**Access control & configuration**

| | Alighieri | Dante |
| --- | --- | --- |
| Model | Dante-inspired `client` / `socks` rules, deny-by-default | the original `sockd.conf` |
| Selectors | CIDR, port, command, protocol, auth-method, destination hostname | CIDR, port, command, protocol, user, hostname/domain |
| Hostname / domain rules | yes (`socks` `to:` patterns) | yes |
| libwrap / TCP wrappers | no | yes |
| Named rules + `include` | yes | no (single config file) |
| Destination redirect / rewrite | no | yes |
| DNS policy (family preference, all-address fallback, deny categories, caching) | rich, built-in | basic |

**Operations & observability**

| | Alighieri | Dante |
| --- | --- | --- |
| Log formats | text or JSON, size-rotation, non-blocking writer | syslog + file |
| Prometheus metrics | built-in endpoint | no |
| Hot reload | SIGHUP (Unix) + Windows SCM | SIGHUP |
| Service tooling | systemd install/upgrade/uninstall script; Windows Service | distro init/systemd packaging |
| Config wizard / validation | loopback wizard, `--check`, `--check --json` | startup config check |
| Bandwidth / abuse limits | connection-rate, auth-failure-rate, concurrency, token-bucket throttle (per-client `byterate` + per-rule `bandwidth`) | session limits (+ bandwidth in some builds) |

**Security & project**

| | Alighieri | Dante |
| --- | --- | --- |
| Memory safety | Rust | C |
| SOCKS-over-TLS listener | yes (rustls, TLS 1.2/1.3) | no (uses GSSAPI for confidentiality/integrity) |
| Credential storage | Argon2id hashes | system / crypt / PAM |
| License | AGPL-3.0-or-later + commercial | BSD-style (permissive) |
| Maturity | new (current release v0.1.0) | decades in production |

**Which to choose**

- **Dante** if you need SOCKS4, the BIND command (active FTP / callbacks),
  GSSAPI/Kerberos or PAM auth, the client-side socksify library, run on
  BSD/Solaris/AIX, or want a permissive license and a decades-proven codebase.
- **Alighieri** if you want SOCKS5 on Linux *and* Windows from one memory-safe
  codebase, SOCKS-over-TLS, Prometheus/JSON observability, Argon2id-hashed
  credentials, fixed UDP relay port ranges for firewalling, and a modern ops
  story (wizard, systemd installer, hot reload on both OSes) — and do not need
  SOCKS4/BIND/GSSAPI.

Closing the remaining gaps (and going further) is tracked in
[`doc/roadmap.md`](doc/roadmap.md).

## Security considerations

- **Deny by default.** No `client` or `socks` rules means everything is denied.
- **Argon2id userlist hashes** avoid storing plaintext passwords for
  username/password authentication.
- **UDP relay source validation** drops datagrams from IPs other than the
  authenticated client.
- **Fragmented UDP datagrams are dropped** (`FRAG != 0`) to avoid amplification
  and evasion risks.
- **No BIND support.** Active-mode FTP's BIND command is not implemented; it
  is a common source of misconfiguration and rarely needed today.

## License

Alighieri is **dual-licensed** — AGPL-3.0-or-later by default, with a commercial
option available by agreement:

- **Open source (default):** the [GNU Affero General Public License v3.0 or
  later](LICENSE) (`AGPL-3.0-or-later`). Unless you have signed a commercial
  agreement, your use is under the AGPL. Practically, its network-use clause
  (section 13) means that if you run a *modified* version of Alighieri as a
  network service, you must make the corresponding source of your modified
  version available to that service's users.
- **Commercial (by agreement):** if the AGPL's copyleft and source-disclosure
  obligations don't fit your use — e.g. embedding Alighieri in a proprietary
  product, or running a modified version as a service without publishing your
  changes — a commercial license from WireSock is available, by separate signed
  agreement, that lifts them.

See [`LICENSING.md`](LICENSING.md) for which license applies to you and how to
obtain a commercial one. Copyright © 2026 WireSock; commercial inquiries:
<licensing@wiresock.net>.
