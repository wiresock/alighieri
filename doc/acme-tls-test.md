# Testing the Let's Encrypt (ACME) TLS listener on a fresh server

This is an end-to-end walkthrough: stand Alighieri up on a public VPS, let it get
a real Let's Encrypt certificate automatically, and proxy a request through the
TLS listener to prove it works.

## How it works (1 minute)

With `tls.acme.*` configured, the **single listener on port 443** does double
duty:

- to your SOCKS clients it speaks **SOCKS5-over-TLS**, and
- to Let's Encrypt it answers the **TLS-ALPN-01** challenge itself (a special
  `acme-tls/1` TLS handshake on the same port).

So there is **no port 80 and no DNS API** to manage. On startup Alighieri orders
a certificate in the background, caches it, and renews it automatically. The
catch is the one TLS-ALPN-01 requires: the listener must be reachable at your
domain **on port 443**.

## Prerequisites

1. A VPS with a **public IP** and root (or `sudo`).
2. A DNS **A record** for a domain you control, pointing at the VPS — e.g.
   `proxy.example.com → 203.0.113.10` — and **propagated**
   (`dig +short proxy.example.com` returns the VPS IP). Publish **AAAA** only
   when Alighieri also accepts IPv6 TCP 443 at that address. [Let's Encrypt
   prefers IPv6](https://letsencrypt.org/ca/docs/ipv6-support/) when both records
   exist, so an unreachable or wrong AAAA record can break validation; the
   wizard's `0.0.0.0:443` public profile is IPv4-only.
3. Inbound **TCP 443 open** in both the cloud firewall/security group *and* the
   host firewall (`ufw allow 443/tcp`), with **nothing else listening on 443**
   (stop nginx/apache/etc.).
4. Outbound **TCP 443** allowed (Alighieri talks to the Let's Encrypt API).

Throughout, replace `proxy.example.com` and `you@example.com` with your own.

For a production-oriented starting point, the configuration wizard offers the
**Public SOCKS5-over-TLS (ProxiFyre)** profile. Its reviewed static counterpart
is [`templates/public-tls-proxifyre.conf`](templates/public-tls-proxifyre.conf).
The rest of this guide remains useful for exercising issuance and diagnosing
ACME failures.

## Step 1 — Install Alighieri

Copy the link to the `x86_64-unknown-linux-gnu` (or `aarch64-unknown-linux-gnu`)
tarball for the latest release from the
[releases page](https://github.com/wiresock/alighieri/releases), then:

```sh
curl -fsSLO <paste-the-tarball-url>     # e.g. alighieri-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz
tar xzf alighieri-*.tar.gz
sudo install alighieri-*/alighieri /usr/local/bin/alighieri
alighieri --version
```

(Or use the container image — see the README "Container image" section — and run
it with `--network host` so it can bind 443 and be reached on it.)

## Step 2 — Write the config

Start in the **Let's Encrypt staging environment** (`tls.acme.staging: on`). Its
certificates are *untrusted* by browsers, but its rate limits are far looser, so
you can confirm the whole flow without risking the strict production limits. We
switch to production in Step 6.

Create the directories, then write `/etc/alighieri/alighieri.conf`:

```sh
sudo mkdir -p /etc/alighieri /var/lib/alighieri/acme
```

```conf
# Listen for SOCKS-over-TLS, and answer the ACME challenge, on 443.
internal: 0.0.0.0:443          # or [::]:443 for dual-stack
external: 0.0.0.0

# Require username/password so this is not an open proxy while you test.
socksmethod: username
userlist: /etc/alighieri/users

# Automatic certificates from Let's Encrypt.
tls.acme.domains: proxy.example.com
tls.acme.email: you@example.com
tls.acme.cache: /var/lib/alighieri/acme
tls.acme.staging: on           # STAGING first; turn off for a real cert (Step 6)

logoutput: stdout
# Reject destinations that resolve into private/loopback/link-local/reserved
# ranges (SSRF + DNS-rebinding protection), regardless of address family.
dns.deny: private linklocal loopback reserved

# Omitting from:/to: matches both IPv4 and IPv6 (an explicit 0.0.0.0/0 would be
# IPv4-only — a footgun on the [::]:443 dual-stack listener). The loopback
# blocks are belt-and-suspenders ahead of dns.deny above.
client pass "clients" { }
socks block "deny-loopback-v4" { to: 127.0.0.0/8 }
socks block "deny-loopback-v6" { to: ::1/128 }
socks pass "allow" {
    protocol: tcp udp
    command: connect udpassociate
}
```

Create a test user and validate the config:

```sh
sudo alighieri user add testuser --userlist /etc/alighieri/users   # prompts for a password
sudo alighieri --check /etc/alighieri/alighieri.conf               # validate (no side effects)
```

## Step 3 — Run it

Binding port 443 needs privilege, so for a quick test run it as root:

```sh
sudo alighieri /etc/alighieri/alighieri.conf
```

For a persistent, hardened setup, run it under **systemd** instead. The
[`scripts/alighieri.sh`](../scripts/alighieri.sh) lifecycle manager installs a
sandboxed unit and, when it sees `tls.acme.*` in the config (or any `internal:`
port below 1024), automatically grants `CAP_NET_BIND_SERVICE` so the non-root
service can bind 443 and provisions a writable `StateDirectory=` for the ACME
cache. So with ACME configured you can simply:

The release tarballs used in Step 1 do not bundle the lifecycle script. If you
are not running from a source checkout, download the standalone helper and use
`./alighieri.sh` in place of `./scripts/alighieri.sh`; pass
`--binary /path/to/extracted/alighieri` to install that prebuilt binary without
requiring a Rust toolchain:

```sh
curl -fsSLo alighieri.sh https://raw.githubusercontent.com/wiresock/alighieri/main/scripts/alighieri.sh
chmod +x alighieri.sh
```

```sh
sudo ./scripts/alighieri.sh        # or `install` to reconfigure an existing unit
```

(If you hand-write your own unit, replicate the three settings the installer
uses: `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`,
`AmbientCapabilities=CAP_NET_BIND_SERVICE`, and `StateDirectory=alighieri` — an
ambient capability has no effect unless it is also in the bounding set, which a
hardened unit otherwise empties.)

## Step 4 — Watch the certificate get issued

Issuance starts at boot (it does **not** wait for a client). Within a few seconds
you should see ACME progress logged as `acme: ...` lines (account registration,
the order, and the obtained/cached certificate):

```
INFO listening with TLS
INFO acme: ...        # account / order / certificate events
```

and the cache directory fills in:

```sh
ls -la /var/lib/alighieri/acme   # account + certificate files appear
```

If instead you see repeated `acme error: ...` lines, jump to Troubleshooting.

## Step 5 — Proxy a request through the TLS listener

The listener currently has an untrusted staging certificate. Test it through a
local TLS terminator that is explicitly limited to this staging step. With
**stunnel** (on your client machine):

```ini
# stunnel.conf
# stunnel has no inline comments: a "# ..." after a value is read as part of
# the value, so keep any notes on their own line like these.
[alighieri]
client = yes
accept = 127.0.0.1:1080
connect = proxy.example.com:443
verifyChain = no
```

`accept` is the local plaintext SOCKS port; `connect` is the TLS listener.
`verifyChain = no` accepts the untrusted **staging** certificate — Step 6 turns
verification on for the production cert.

```sh
stunnel stunnel.conf
# Then point any normal SOCKS5 client at the local port:
curl --socks5-hostname 127.0.0.1:1080 -U testuser:YOURPASS https://ifconfig.me
```

That should print the **VPS's IP**, proving the request was relayed through the
proxy over TLS. (`socat TCP-LISTEN:1080,fork,reuseaddr OPENSSL:proxy.example.com:443,verify=0`
is a quick one-liner alternative to stunnel.)

This walkthrough exercises TCP CONNECT. SOCKS5 authentication and the control
connection use TLS, but UDP ASSOCIATE relay datagrams travel through separate
UDP sockets and are not encapsulated in the TLS stream. If you enable UDP for a
public deployment, configure a fixed `udp.portrange`, open that inbound UDP
range, and rely on the application protocol (for example QUIC) for any UDP
payload encryption it requires.

## Step 6 — Switch to a real (trusted) certificate

Once the staging flow works, get a production certificate:

1. In the config set `tls.acme.staging: off` (or delete the line).
2. Remove the staging cache so it requests fresh from production:
   `sudo rm -rf /var/lib/alighieri/acme/*`
3. Restart Alighieri and watch the log issue a new cert.

Now the certificate is publicly trusted, so clients can validate its chain and
hostname normally.

[ProxiFyre 2.4.0 or later](https://github.com/wiresock/proxifyre/releases/tag/v2.4.0)
can now connect directly with normal certificate validation. Its default SOCKS5
transport is plaintext, so explicitly select TLS in `app-config.json`:

```json
{
  "logLevel": "Error",
  "proxies": [
    {
      "appNames": ["chrome"],
      "socks5ProxyEndpoint": "proxy.example.com:443",
      "username": "testuser",
      "password": "REPLACE_WITH_USER_ADD_PASSWORD",
      "socks5Transport": "TLS",
      "tlsServerName": "proxy.example.com",
      "tlsAllowInvalidCertificate": false,
      "supportedProtocols": ["TCP", "UDP"],
      "supportedAddressFamilies": ["IPv4", "IPv6"]
    }
  ],
  "excludes": []
}
```

Remove `UDP` when UDP ASSOCIATE is disabled. This guide's rule omits `to:`, so
it permits both IPv4 and IPv6 destinations; the upstream ProxiFyre endpoint
still uses the domain's A record. The wizard's stricter profile instead uses
`supportedAddressFamilies: ["IPv4"]` to match its IPv4-only destination ACL.
Replace `appNames`, the domain, username, and password; the password is the one
entered at `alighieri user add`. Do not set `tlsAllowInvalidCertificate` to
`true`; this direct configuration is for the production certificate obtained
in this step.

For the stunnel wrapper, turn on verification in `stunnel.conf`:
`verifyChain = yes` checks the chain and `checkHost` checks the hostname (the
chain alone does not), pointed at a CA bundle (paths below):

```ini
# stunnel.conf
[alighieri]
client = yes
accept = 127.0.0.1:1080
connect = proxy.example.com:443
verifyChain = yes
checkHost = proxy.example.com
CAfile = /etc/ssl/certs/ca-certificates.crt
```

`verifyChain = yes` *requires* a CA source. stunnel is built on OpenSSL and does
**not**, by default, use the OS trust store (the macOS Keychain or Windows
CryptoAPI), so point `CAfile`/`CApath` at a bundle or it refuses to start
(`Either "CAengine", "CAfile" or "CApath" has to be configured`):

- Debian/Ubuntu — `/etc/ssl/certs/ca-certificates.crt`
- Fedora/RHEL — `/etc/pki/tls/certs/ca-bundle.crt`
- macOS — `/etc/ssl/cert.pem`, or Homebrew's `cert.pem` under
  `/opt/homebrew/etc/...` (Apple Silicon) or `/usr/local/etc/...` (Intel)
- Windows — the `ca-certs.pem` in stunnel's install directory (or
  `CAengine = capi` to use the Windows certificate store instead)

(For the socat alternative, drop the `verify=0`.) Restarting Alighieri again
should **load the cached cert without re-issuing** — confirm the log shows no
new order.

## Troubleshooting

- **`acme error` / order keeps failing** — Let's Encrypt could not reach the
  listener on 443. Check: `dig +short proxy.example.com` is the VPS IP; the
  cloud security group and host firewall allow inbound 443; nothing else holds
  443 (`sudo ss -ltnp 'sport = :443'`).
- **`Permission denied` binding 443** — run as root, or grant
  `CAP_NET_BIND_SERVICE`.
- **`address already in use`** — another service (nginx/apache) is on 443; stop
  it. Alighieri must own 443 to answer the challenge.
- **Rate limited** — you exhausted production limits by re-issuing. Wait, or go
  back to staging. This is exactly why Step 2 starts in staging and the cache
  dir is persisted (so restarts reuse the cert instead of re-requesting).
- **TLS handshake fails from a plaintext client** — expected: the listener is
  TLS-only when `tls.*` is set. Use the stunnel/socat wrapper above.
- **`acme error … connection` but 443 is reachable** — the validation reached
  the proxy but was rejected before the challenge. With `proxyprotocol` enabled,
  a validation connection that arrives **without** a trusted PROXY header (e.g.
  Let's Encrypt connecting directly, rather than through a PROXY-protocol load
  balancer doing TCP passthrough) is rejected by the admission gate — the proxy
  warns when ACME and `proxyprotocol` are both set. A very tight
  `ratelimit.connectionrate`/`ratelimit.concurrentconnections` can reject the
  validation connections too.

## Security note

This config gates access with username/password so it is not an open relay, but
a public SOCKS proxy is still a target. Use a strong password, consider
restricting `client` rules to known source ranges, keep the `deny-loopback`
rule, and review the per-client abuse limits (`ratelimit.*`) before leaving it
running.
