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
2. A DNS **A record** for a domain you control, pointing directly at the VPS —
   e.g. `proxy.example.com → 203.0.113.10` — and **propagated**. Verify
   `dig +short proxy.example.com` contains the VPS public IPv4 address rather
   than unrelated proxy or CDN addresses. If Cloudflare manages the zone, set
   the record to **DNS only** (gray cloud), not standard **Proxied** mode
   (orange cloud); specialized Cloudflare TCP proxy products are outside this
   guide. Publish **AAAA** only when Alighieri also accepts IPv6 TCP 443 at that
   address and compatible rules have been separately configured and tested.
   [Let's Encrypt prefers IPv6](https://letsencrypt.org/ca/docs/ipv6-support/)
   when both records exist, so an unreachable or wrong AAAA record can break
   validation. Alighieri supports IPv6 generally, but the wizard's ready-made
   `0.0.0.0:443` listener and `to: 0.0.0.0/0` destination ACL are deliberately
   IPv4-only for this walkthrough.
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
cd alighieri-vX.Y.Z-x86_64-unknown-linux-gnu  # use the directory you extracted
sudo ./scripts/alighieri.sh install --binary ./alighieri --no-start
alighieri --version
```

The preparation command installs the binary, creates the dedicated
`alighieri` account and service directories, and writes the unit without
enabling or starting it. The authenticated service is started only after the
userlist and final configuration are ready below.

(Or use the container image — see the README "Container image" section — and run
it with `--network host` so it can bind 443 and be reached on it.)

## Running the wizard on a remote VPS

After Step 1, you can generate the ready-made public profile without exposing
the loopback-only wizard. From the operator's local computer, open one SSH
session with local forwarding:

```sh
ssh -o ExitOnForwardFailure=yes \
    -L 8080:127.0.0.1:8080 \
    user@vps-address
```

Inside that same SSH session, on the VPS:

```sh
sudo alighieri config wizard \
    --listen 127.0.0.1:8080 \
    --output /etc/alighieri/alighieri.conf
```

Keep the SSH session open and paste the tokenized URL printed by Alighieri into
the local browser. Because local port 8080 is forwarded to VPS loopback port
8080, the printed `http://127.0.0.1:8080/?token=...` URL works locally. Keep the
wizard bound to `127.0.0.1`, do **not** open TCP 8080 in the VPS firewall, and
do not post or share the tokenized URL. If 8080 is occupied, choose another
matching port in both the `ssh -L` command and `--listen`.

Choose **Public SOCKS5-over-TLS (ProxiFyre)** in the wizard and follow its
completion page to create the userlist and install the service. The hand-written
configuration below remains a generic ACME exercise and intentionally supports
options beyond that narrower IPv4-only profile. If you use the wizard path, do
not overwrite its generated configuration in Step 2.

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
sudo chown root:alighieri -- /etc/alighieri/users
sudo chmod 640 -- /etc/alighieri/users
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

Linux release archives bundle the version-matched lifecycle helper and default
config. From the extracted archive root used in Step 1, install the bundled
binary and explicitly select the configuration created above:

```sh
sudo ./scripts/alighieri.sh install --binary ./alighieri \
  --config /etc/alighieri/alighieri.conf
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

This walkthrough exercises TCP CONNECT. SOCKS5 authentication, the control
connection, and relayed TCP traffic use TLS, but UDP ASSOCIATE relay datagrams
travel through separate UDP sockets and are not encapsulated in the TLS stream.
If you enable UDP for a public deployment, configure a fixed `udp.portrange`,
open that inbound UDP range, and rely on the application protocol (for example
QUIC) for any UDP payload encryption it requires.

## Step 6 — Switch to a real (trusted) certificate

Once the staging flow works, get a production certificate:

1. In the config set `tls.acme.staging: off` (or delete the line).
2. Remove the staging cache so it requests fresh from production:
   `sudo rm -rf /var/lib/alighieri/acme/*`
3. Restart Alighieri and watch the log issue a new cert.

Now the certificate is publicly trusted, so clients can validate its chain and
hostname normally.

Install [ProxiFyre 2.5.0 or later](https://github.com/wiresock/proxifyre/releases/latest)
using the current architecture-matched online `*-setup.exe`. Windows may show
**Unknown publisher** because the first-party installer is unsigned;
before approving elevation, verify the download against its matching `.sha256`
sidecar from the official release. Normal Windows certificate-chain and
hostname validation should now succeed; a production ACME certificate needs
neither an invalid-certificate bypass nor a fingerprint pin. A staging
certificate is deliberately untrusted, so finish the server-side staging
exercise and switch to production before this client test.

Use the [ProxiFyre GUI](https://github.com/wiresock/proxifyre/blob/main/docs/gui.md)
as the recommended editor:

| Setting | Value |
| --- | --- |
| Proxy type | SOCKS5 |
| Server and port | `proxy.example.com:443` |
| Username and password | the values created with `alighieri user add` |
| Transport | TLS |
| TLS server name | `proxy.example.com` (or the default from the endpoint hostname) |
| Certificate validation | enabled; keep **Allow invalid certificate** disabled |
| Certificate pin | not required for the publicly trusted production certificate |
| Protocols | TCP, plus UDP only when UDP ASSOCIATE is enabled |
| Destination families | IPv4 and IPv6 for this guide's generic dual-family rule; IPv4 only for the ready-made wizard profile |

Open ProxiFyre from the Start Menu, add a routing rule for one Windows
application, enter the values above, and select TLS. Keep normal certificate
and hostname validation enabled. Select the protocols enabled in Alighieri and
the address families allowed by the chosen server rule. Choose **Validate**,
then **Apply & Restart**, and confirm that the header reports **Running**. Use
the **Logs** tab for connection or routing-rule diagnosis. See the official
[configuration reference](https://github.com/wiresock/proxifyre/blob/main/docs/configuration.md)
for advanced fields.

<details>
<summary>Advanced/manual app-config.json</summary>

For automation, managed deployment, or intentional manual editing, use the
equivalent configuration below. Replace `appNames`, the domain, username, and
password; the password is the one entered at `alighieri user add`. Remove `UDP`
when UDP ASSOCIATE is disabled. Manual configuration must explicitly select TLS
because the format otherwise defaults to plaintext SOCKS5. The installed
directory normally requires elevation; credentials remain plaintext in this
file, so restrict access to it and restart `ProxiFyreService` after manual
changes.

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

</details>

This guide's generic rule omits `to:`, so it permits both IPv4 and IPv6
destinations; the upstream ProxiFyre endpoint still requires the domain's A
record. The wizard's stricter profile instead uses
`supportedAddressFamilies: ["IPv4"]` to match its IPv4-only destination ACL.
Keep `tlsAllowInvalidCertificate` false.

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

- **Wizard reports `bind: address already in use`** — another local process is
  using port 8080 on the VPS. Choose another VPS loopback port and use that
  same port in both `ssh -L PORT:127.0.0.1:PORT` and
  `--listen 127.0.0.1:PORT`.
- **SSH forwarding fails** — keep `-o ExitOnForwardFailure=yes` so SSH reports
  the failure immediately, then check that the client-side local port is free
  and the SSH server permits TCP forwarding. Do not work around it by opening
  the wizard publicly.
- **The tokenized URL stopped working** — the SSH connection must remain open
  for the lifetime of the one-shot wizard. Reconnect, start a new wizard, and
  use its newly printed tokenized URL.
- **The browser cannot reach the VPS's `127.0.0.1`** — VPS loopback is local to
  the VPS. Open the printed `127.0.0.1` URL on the operator's computer only
  while the matching SSH local-forwarding session is active.
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
