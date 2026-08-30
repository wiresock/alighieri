# Alighieri management CLI protocol

Alighieri exposes a local, versioned command-line interface for automation. It
is intended to be executed through an existing authenticated SSH connection by
a cross-platform manager, but it is an ordinary process/stdio interface: it
does not open a management port, start an administration daemon, or implement
SSH itself.

Management protocol version 1 covers capability discovery and machine-readable
user management. Existing `--check --json` and `config metadata --json` output
remain separate, backward-compatible interfaces.

## Compatibility discovery

Call capability discovery before relying on management operations:

```text
alighieri capabilities --json
```

The command writes one compact JSON document followed by LF. A formatted
example is:

```json
{
  "schema_version": 1,
  "ok": true,
  "operation": "capabilities",
  "result": {
    "product": "alighieri",
    "version": "0.x.y",
    "target_os": "linux",
    "target_arch": "x86_64",
    "management_protocol_version": 1,
    "features": [
      "config.check-json",
      "user.add-json",
      "user.delete-json",
      "user.list-json",
      "user.verify-json",
      "user.password-stdin",
      "user.target-userlist",
      "user.target-config"
    ]
  }
}
```

`version` is the package version compiled into the binary. `target_os` and
`target_arch` describe the binary's build target, not the computer running the
manager. Feature names are stable machine identifiers and report what that
binary supports.

A protocol-1 client should:

1. require `schema_version` to be `1` and `product` to be `alighieri`;
2. require `management_protocol_version` to be `1`;
3. check every feature needed for the requested operation;
4. ignore unknown JSON fields and unknown feature names; and
5. fail safely or fall back to an explicitly supported human workflow when a
   required feature is absent.

Future fields and feature names may be appended without changing management
protocol version 1. Clients must not depend on JSON object field order.
`capabilities` without `--json`, or with `--help`, prints short human-readable
usage instead of the machine contract.

## Commands

Protocol 1 supports these forms:

```text
alighieri user add USER \
    (--userlist PATH | --config CONFIG) \
    [--password-stdin] [--json]

alighieri user delete USER \
    (--userlist PATH | --config CONFIG) \
    [--if-present] [--json]

alighieri user list \
    (--userlist PATH | --config CONFIG) \
    [--json]

alighieri user verify USER \
    (--userlist PATH | --config CONFIG) \
    [--password-stdin] [--json]
```

Options are written after the subcommand and, for operations that have one,
the username. Their order after that point is otherwise interchangeable.
Exactly one target option is required. Duplicate target or flag options,
unknown options, and unsupported combinations are errors.

`--password-stdin` is valid only for `add` and `verify`. There is deliberately
no `--password VALUE` option, and passwords are never accepted from an
environment variable, URL, JSON request, or Alighieri-created temporary file.
`--if-present` is valid only for `delete`.

Without `--json`, existing operator-oriented behavior is retained. In
particular, `add` prompts twice without echo, `verify` prompts once without
echo, and `list` prints one username per line. With `--json`, stdout is reserved
for the response document and password prompts should be avoided by using
`--password-stdin`.

## Target selection

### Direct userlist

`--userlist PATH` operates on that path directly and preserves the legacy
manual behavior, including relative paths. Successful JSON results contain
`userlist` and omit `config`.

### Configuration-derived userlist

`--config CONFIG` loads the supplied configuration with Alighieri's real
parser. Includes and existing last-wins settings are honored. The operation
uses the effective local `userlist` only when all of the following are true:

- username/password authentication is active;
- no external `auth.command` backend supersedes the local userlist;
- an effective userlist is configured; and
- the effective userlist path is absolute.

This focused load does not require TLS certificates or perform full server
startup validation. In particular, `user add` may create a missing absolute
userlist so the first authenticated deployment can be bootstrapped, but its
parent directory must already exist with the intended service ownership,
traversal permissions, and ACL. Config-backed mode does not create missing
directory ancestry because elevated caller defaults may not be usable by the
service. It does not canonicalize a file that does not exist yet. On Linux, that
automatic config-backed creation is supported only for the managed-service
layout: the supplied config must be a regular file owned by `root:alighieri`
with mode `0640` and no extended access ACL. The new userlist inherits that
identity and is created with mode `0640`; inherited extended access ACLs are
removed. For custom service groups, owner-only, other-readable, or ACL-based
layouts, pre-create the userlist with the required service metadata. Existing
ownership and mode are preserved, as are Linux access ACLs. A missing userlist
selected directly with `--userlist` retains the legacy caller-owned `0600`
behavior, including parent directory creation. Other Unix platforms require
the config-derived userlist to be pre-created.

Successful JSON results contain both the supplied `config` path and the
effective `userlist` path. The operating system still controls whether the
caller may read, create, lock, or replace that file.

## Password stdin record

With `--password-stdin`, stdin contains one UTF-8 password record and then EOF.
If the record ends in LF or CRLF, only that final terminator is removed. Spaces
and tabs, including leading and trailing ones, are password data and are not
trimmed. Any other CR or LF rejects the input as an additional or ambiguous
record.

The password is limited to 255 bytes after removal of the optional terminator,
matching the RFC 1929 wire limit. The limit is in UTF-8 bytes, not Unicode
characters. Input is read through a small fixed ceiling so an untrusted stream
cannot cause unbounded allocation. An empty password is rejected by `user add`;
`user verify` retains the existing verification behavior.

Alighieri keeps stdin bytes and the decoded password in zeroizing containers.
The secret container implements neither `Debug`, `Display`, nor `Serialize`,
and it is dropped promptly after hashing or verification. Callers must apply the
same discipline to every buffer on their side of the SSH channel.

The writer must close the process stdin or the SSH channel's write side after
the record. It must not place the password in argv, an environment variable,
the JSON response, a log message, a process listing, or command substitution.

## JSON envelope and exit status

Every normal `user ... --json` response is exactly one compact JSON document on
stdout followed by LF. Success uses this envelope:

```json
{
  "schema_version": 1,
  "ok": true,
  "operation": "user.add",
  "result": {}
}
```

Failure uses this envelope:

```json
{
  "schema_version": 1,
  "ok": false,
  "operation": "user.add",
  "error": {
    "code": "invalid_password",
    "message": "password must not exceed 255 bytes"
  }
}
```

The process exits successfully only when the requested operation succeeds.
Machine failures return a non-zero status even when a valid error document was
written. JSON-mode user errors are not repeated as human text on stderr.
Transport, process-launch, stdout-write, or serialization failures can prevent
a usable document, so clients must check both the process status and whether
stdout contains exactly one valid envelope.

`schema_version` versions the common envelope. `operation` identifies the
request whose result is being reported. Machine clients must branch on
`error.code`, never on the English `message`, which is intended for display and
diagnosis and may become more descriptive. Unknown fields must be ignored, and
unknown future error codes should be handled as a generic failed operation.

When a malformed user invocation contains `--json`, Alighieri returns an
`invalid_arguments` envelope when it can identify the requested operation.

## Operation results

### Add or update

```json
{
  "schema_version": 1,
  "ok": true,
  "operation": "user.add",
  "result": {
    "username": "alice",
    "userlist": "/etc/alighieri/users",
    "config": "/etc/alighieri/alighieri.conf",
    "action": "created",
    "changed": true
  }
}
```

`action` is `created` or `updated`. The distinction is made while the existing
userlist update lock is held, rather than with a racy pre-check. `changed` is
always `true` on success. Direct `--userlist` results omit `config`.

Alighieri generates a fresh Argon2id salt for every add/update. The result never
contains the plaintext password, generated hash, salt, complete userlist, or
previous credential form.

### List

```json
{
  "schema_version": 1,
  "ok": true,
  "operation": "user.list",
  "result": {
    "userlist": "/etc/alighieri/users",
    "count": 2,
    "users": ["alice", "bob"]
  }
}
```

Usernames are sorted and deduplicated after the complete userlist has been
parsed and validated. A missing userlist is an error, not an empty result.
Password fields and hashes are never returned. Config-targeted results also
contain `config`.

### Delete

```json
{
  "schema_version": 1,
  "ok": true,
  "operation": "user.delete",
  "result": {
    "username": "alice",
    "userlist": "/etc/alighieri/users",
    "deleted": true,
    "changed": true
  }
}
```

Without `--if-present`, an absent username returns `user_not_found` and a
non-zero status. With `--if-present`, absence is idempotent success:

```json
{
  "schema_version": 1,
  "ok": true,
  "operation": "user.delete",
  "result": {
    "username": "alice",
    "userlist": "/etc/alighieri/users",
    "deleted": false,
    "changed": false
  }
}
```

Config-targeted results also contain `config`.

### Verify

```json
{
  "schema_version": 1,
  "ok": true,
  "operation": "user.verify",
  "result": {
    "username": "alice",
    "userlist": "/etc/alighieri/users",
    "verified": true
  }
}
```

Rejected credentials return `credentials_rejected` and a non-zero status. The
response deliberately does not reveal whether the entry was plaintext, a
legacy form, or Argon2id. Config-targeted results also contain `config`.

## Stable error codes

These identifiers are stable for management protocol version 1:

All protocol-1 error-code identifiers use lowercase ASCII `snake_case`.

| Code | Meaning |
| --- | --- |
| `invalid_arguments` | The command syntax, option combination, or target selection is invalid. |
| `invalid_username` | The username violates Alighieri's shared username rules. |
| `invalid_password` | The password record is malformed, empty where forbidden, invalid UTF-8, or over the RFC 1929 limit. |
| `password_stdin_read_failed` | Stdin could not be read. |
| `password_input_too_large` | Input exceeded the bounded password framing ceiling. |
| `config_load_failed` | The selected configuration or one of its includes could not be loaded. |
| `userlist_not_configured` | The effective configuration has no local userlist. |
| `userlist_not_active` | Username/password authentication is not active. |
| `external_auth_backend` | An external authentication command supersedes the local userlist. |
| `relative_userlist_not_supported` | Config targeting resolved a relative userlist path. |
| `userlist_read_failed` | The userlist could not be opened or read. |
| `userlist_parse_failed` | The complete userlist is malformed. |
| `userlist_update_failed` | A locked transactional add/delete could not be completed. |
| `user_not_found` | Delete did not find the username and `--if-present` was absent. |
| `credentials_rejected` | Verification did not accept the username/password pair. |
| `serialization_failed` | The response could not be serialized. |
| `internal_error` | An unexpected local operation failed without a more specific protocol code. |

Messages are diagnostic text, not compatibility identifiers. Clients must not
branch on their wording.

## SSH flow

SSH is the transport and authorization perimeter. Capability discovery can be
executed without a stdin payload:

```sh
ssh -T -o BatchMode=yes server.example \
  sudo -n -- /usr/local/bin/alighieri capabilities --json
```

For a password operation, connect a trusted password provider directly to the
SSH channel. The placeholder below means a program that writes exactly one
password record to stdout without logging it:

```sh
trusted-password-provider | \
  ssh -T -o BatchMode=yes server.example \
    sudo -n -- /usr/local/bin/alighieri user add alice \
      --config /etc/alighieri/alighieri.conf \
      --password-stdin --json
```

Do not replace the provider with `echo PASSWORD`, put the password in the
remote command, or use command substitution. A shell variable avoids argv but
can still be copied into shell memory, history, crash reports, or debugging
output; the production manager should write its protected buffer directly to
the SSH channel and clear it promptly. Use `printf`, not `echo`, only when an
interactive shell flow is unavoidable because `echo` has implementation-
dependent option and escape handling.

The userlist update does not reload a running service. Initial manager versions
should request service start/stop/reload/restart separately through the target
operating system's service manager over SSH.

## Rust client outline

The following abbreviated example uses the local OpenSSH client as the
transport. A native SSH library follows the same sequence: open an exec channel,
write the password record, close the channel's write side, collect stdout and
the exit status, and deserialize the envelope. Dynamic remote arguments must be
validated or quoted for the selected SSH transport; the password is never one
of those arguments.

```rust,no_run
use std::io::{self, Write};
use std::process::{Command, Stdio};

use serde::Deserialize;
use serde_json::Value;
use zeroize::Zeroizing;

#[derive(Deserialize)]
struct Envelope {
    schema_version: u32,
    ok: bool,
    operation: String,
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<ProtocolError>,
}

#[derive(Deserialize)]
struct ProtocolError {
    code: String,
    message: String,
}

fn add_user(password_bytes: Vec<u8>) -> Result<Envelope, Box<dyn std::error::Error>> {
    let password = Zeroizing::new(password_bytes);
    let mut child = Command::new("ssh")
        .args([
            "-T",
            "-o",
            "BatchMode=yes",
            "--",
            "server.example",
            "sudo",
            "-n",
            "--",
            "/usr/local/bin/alighieri",
            "user",
            "add",
            "alice",
            "--config",
            "/etc/alighieri/alighieri.conf",
            "--password-stdin",
            "--json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    {
        let mut stdin = child.stdin.take().ok_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "SSH stdin unavailable")
        })?;
        stdin.write_all(password.as_slice())?;
        stdin.write_all(b"\n")?;
    } // close the SSH process's stdin before waiting
    drop(password);

    let output = child.wait_with_output()?;
    let envelope: Envelope = serde_json::from_slice(&output.stdout)?;
    if envelope.schema_version != 1 || envelope.operation != "user.add" {
        return Err("unsupported management response".into());
    }
    if output.status.success() != envelope.ok {
        return Err("exit status and management response disagree".into());
    }
    Ok(envelope)
}
```

Serde ignores unknown fields unless a client opts into
`deny_unknown_fields`, which is useful for protocol-1 forward compatibility.
A complete client should first run capability discovery, validate the required
features, limit response size, require exactly one JSON document, treat SSH or
`sudo` stderr as a transport failure when no envelope is available, and avoid
logging either stdin payloads or secret-bearing in-memory objects.

## Security boundaries

- This interface opens no management port and installs no resident management
  agent. It is a local CLI invoked through the caller's existing SSH session.
- SSH authentication, account policy, and host-key verification remain the
  caller's responsibility. Clients must never disable SSH host-key verification.
- JSON mode is a representation, not an authorization boundary. Filesystem,
  service, account, and elevation privileges are enforced by the operating
  system.
- Use non-interactive `sudo -n` and pin delegated privileges to the absolute
  Alighieri binary, the permitted subcommands and options, and one fixed
  absolute `--config` or `--userlist` target. Do not grant a generic
  `alighieri user *` rule: under elevation either target can select files
  outside the intended deployment. Prefer a fixed root-owned wrapper when the
  authorization policy cannot express the required argument checks. The
  delegated account must not be able to modify or replace the selected
  configuration, any transitive include, or that wrapper. It must also be
  unable to create, delete, or rename entries in any directory component of
  those paths or any directory searched by a wildcard include. Protecting only
  files that currently match is insufficient because a new later-sorting
  fragment can change the last-wins effective `userlist`. If the complete
  include search space cannot be kept administrator-controlled, use a
  root-owned wrapper fixed to an absolute `--userlist` instead of allowing
  `--config` to select the elevated target. A manager must not attempt to parse
  or answer an interactive sudo password prompt.
- Passwords must be written directly to stdin, removed from client memory as
  soon as practical, and never recorded by command, SSH, diagnostic, telemetry,
  or audit logs.
- Never send a generated Argon2id line from one server to another. Send the same
  plaintext password independently to each selected instance so every server
  produces its own fresh salt, then clear the plaintext buffer.
- Alighieri preserves its existing lock, no-follow/symlink protections, atomic
  replacement, backup, ownership/mode preservation, and parent-directory
  synchronization. The protocol does not weaken those checks.
- The protocol does not provide HTTP, REST, or gRPC management; fleet state; an
  SSH implementation or SSH credential storage; automatic sudoers changes;
  plaintext credential storage; configuration deployment; service control;
  upgrades; log streaming; DNS-provider management; a web dashboard; or an
  interactive JSON request stream.
