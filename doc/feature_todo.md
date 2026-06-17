# Feature TODO

This list is based on the current code and docs. It focuses on features that
would improve real deployments while keeping compatibility with common SOCKS5
clients.

## Already Supported

- SOCKS5 no-auth method (`socksmethod: none`, RFC 1928 method `0x00`).
- SOCKS5 username/password method (`socksmethod: username`, RFC 1929 method
  `0x02`).
- TCP CONNECT.
- UDP ASSOCIATE.
- Client and request ACLs with CIDR, port, command, protocol, and auth-method
  selectors.
- IPv4 and IPv6 address parsing and matching.
- Windows Service install, uninstall, start, stop, and status commands.

## High Priority

### Hashed Userlist Passwords

Status: implemented for Argon2id PHC verification and generation.

The existing `userlist` file supports hashed password entries as Alighieri
comment directives containing Argon2id PHC strings:

```text
# alighieri:user:argon2:616c696365:$argon2id$v=19$m=19456,t=2,p=1$...
```

This keeps normal SOCKS5 username/password compatibility because clients still
send RFC 1929 credentials. Only server-side storage changes. Plaintext entries
remain supported for backward compatibility, with docs recommending hashes.

### Userlist Tooling

Add commands to create and manage hashed users safely:

```text
alighieri user add USER --userlist PATH
alighieri user delete USER --userlist PATH
alighieri user list --userlist PATH
alighieri user verify USER --userlist PATH
```

The command should prompt for passwords instead of accepting secrets on the
command line.

Status: implemented for `add`, `delete`, `list`, and `verify`. Mutating
commands use a lock, atomic replacement, and `<userlist>.bak` backups for
existing files.

### Log Rotation

Status: implemented with size-based rotation, bounded retention, portable
console file logging, and Windows Service log rotation under
`C:\ProgramData\Alighieri\logs\`.

### Configuration Include Support

Status: implemented for direct file includes and final-component globs:

```text
include: conf.d/*.conf
```

This helps separate listener settings, users, and ACL policy. Include expansion
detects cycles and reports file/line context.

## Medium Priority

### Local Configuration Wizard

Status: MVP implemented as a short-lived localhost web UI for operators who do
not want to handwrite the Dante-inspired config syntax at first:

```text
alighieri config wizard
```

The wizard binds only to loopback, prints a one-time token URL, generates an
`alighieri.conf`, validates it with the existing parser before writing, writes
atomically with a backup, and shows the exact run/service commands. Treat this
as configuration generation rather than remote administration: do not expose
runtime control, credential browsing, or service management until the
authentication and attack-surface story is explicit.

Useful first-step support work:

- expose machine-readable config validation output (status: implemented with
  `alighieri --check --json CONFIG`),
- collect safe starter templates for common deployments (status: started under
  `doc/templates/`),
- reuse existing userlist tooling for credential creation,
- expose machine-readable restart-vs-reload metadata (status: implemented with
  `alighieri config metadata --json`).

Useful follow-up work:

- improve the form with richer browser-side field validation,
- add explicit userlist creation guidance after username/password generation.

Import/edit support is implemented: `alighieri config wizard --import PATH`
parses an existing configuration, pre-fills the form with the fields the
templates model (listener, trusted client, userlist, log file), and lists any
settings the templates cannot reproduce — TLS, metrics, rate limits, custom
timeouts/DNS, or extra ACL rules — which a save would drop. Without an explicit
`--output`, the import path is also the save target (edit in place); the prior
file is kept as a `.bak` backup.

### DNS Policy Controls

Status: implemented for address-family preference, TCP all-address fallback,
and post-resolution deny categories.

Implemented controls:

- `dns.prefer: system|ipv4|ipv6`,
- `dns.tryall: true|false`,
- `dns.deny: private linklocal loopback multicast unspecified documentation reserved`.

This improves reliability for dual-stack domains and reduces SSRF mistakes.
Optional domain lookup caching is implemented with `dns.cachettl`.

### BIND Command

Implement SOCKS5 BIND only if a clear use case appears. It is uncommon today
but part of RFC 1928 and may matter for legacy active FTP-style workflows. Keep
it disabled by default through ACLs.

### Metrics Endpoint

Status: implemented as an optional Prometheus-style HTTP endpoint configured
with `metrics.listen`.

Implemented counters include:

- active and accepted connections,
- denied client connections,
- SOCKS allowed and denied requests,
- auth failures,
- TCP and UDP relay bytes,
- UDP association and packet counters,
- ACL rule hit counts by scope, verdict, and config source line.

Keep the endpoint bound to localhost unless it is protected by another access
control layer.

### Structured Logs

Status: implemented with `logformat: text` and `logformat: json`.

```text
logformat: json
```

Keep text as the default for humans.

### Hot Reload

Status: implemented for Unix SIGHUP in console mode and Windows Service reload
through `alighieri service reload`.

Reload validates the new config before swapping it in. New connections use the
reloaded ACLs, DNS policy, auth settings, userlist, and timeout values. Existing
connections continue with the config they accepted under. Listener addresses,
`maxconnections`, metrics listener settings, and logging sinks require a
restart.

Windows Service mode receives a user-defined Service Control Manager control
code and routes it through the same reloadable runtime used by console mode.

## Lower Priority

### GSSAPI/Kerberos Authentication

SOCKS5 reserves method `0x01` for GSSAPI. This can be useful in enterprise
Active Directory/Kerberos environments, but client support is much less common
than username/password. Treat this as enterprise-specific future work.

### TLS-Wrapped Listener

Status: implemented as an optional listener wrapper configured with:

```text
tls.certfile: /path/to/server.crt
tls.keyfile: /path/to/server.key
```

SOCKS5 itself is plaintext. For untrusted client networks, support an optional
TLS listener mode. This requires explicit client support or a wrapper, so it is
less universally compatible than standard SOCKS5.

### Windows Event Log

Status: implemented for Windows Service source registration and service
lifecycle/startup-failure events.

Service install registers the `Alighieri` source in the Windows Application
log. Service mode reports start, stop, reload-request, configuration-load,
logging, runtime, bind, and server-runtime failure events. File logging remains
the detailed portable baseline.

### Rate Limits and Abuse Controls

Status: implemented as optional fixed-window per-client limits:

```text
ratelimit.connectionrate: 60/60
ratelimit.authfailurerate: 5/300
ratelimit.concurrentconnections: 10
ratelimit.byterate: 10MiB/60
```

Add per-client limits:

- connection rate,
- auth failure rate,
- concurrent connections,
- bytes per time window.

These should be optional and easy to observe through logs or metrics.

### Rule Names and Audit Output

Status: implemented for ACL rule parsing, structured logs, and rule-hit
metrics.

Rules can be named with a single token between the verdict and opening brace:

```text
socks pass "allow-web" {
    to: 0.0.0.0/0 port = 80-443
}
```

The matching rule name is included with the source line in audit logs and the
`alighieri_rule_named_hits_total` metric. The original
`alighieri_rule_hits_total` metric remains available with its previous label
set for compatibility.

## Suggested Implementation Order

1. Add Windows Service smoke-test documentation/tooling for elevated manual
   release checks.
2. Polish the local configuration wizard with existing-config import and richer
   browser-side validation.
3. Implement SOCKS5 BIND only if a clear active FTP-style use case appears.
4. Consider enterprise-only auth such as GSSAPI/Kerberos if deployment demand
   appears.
