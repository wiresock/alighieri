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
2. A DNS **A record** (and **AAAA** if you use IPv6) for a domain you control,
   pointing at the VPS — e.g. `proxy.example.com → 203.0.113.10` — and
   **propagated** (`dig +short proxy.example.com` returns the VPS IP).
3. Inbound **TCP 443 open** in both the cloud firewall/security group *and* the
   host firewall (`ufw allow 443/tcp`), with **nothing else listening on 443**
   (stop nginx/apache/etc.).
4. Outbound **TCP 443** allowed (Alighieri talks to the Let's Encrypt API).

Throughout, replace `proxy.example.com` and `you@example.com` with your own.

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

# Block proxying to loopback/link-local (SSRF mitigation), allow the rest.
client pass "clients" { from: 0.0.0.0/0 to: 0.0.0.0/0 }
socks block "deny-loopback" { from: 0.0.0.0/0 to: 127.0.0.0/8 }
socks pass "allow" {
    from: 0.0.0.0/0 to: 0.0.0.0/0
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

For a persistent, hardened setup instead, use the systemd installer
(`sudo ./scripts/alighieri.sh`); to run as a non-root service on 443, grant the
unit `AmbientCapabilities=CAP_NET_BIND_SERVICE`.

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

No mainstream SOCKS client speaks SOCKS5-over-TLS directly, so wrap it on the
client with a local TLS terminator. With **stunnel** (on your client machine):

```ini
# stunnel.conf
[alighieri]
client     = yes
accept     = 127.0.0.1:1080            # local plaintext SOCKS port
connect    = proxy.example.com:443     # the TLS listener
verifyChain = no                       # STAGING cert is untrusted; see Step 6
checkHost  = proxy.example.com
```

```sh
stunnel stunnel.conf
# Then point any normal SOCKS5 client at the local port:
curl --socks5-hostname 127.0.0.1:1080 -U testuser:YOURPASS https://ifconfig.me
```

That should print the **VPS's IP**, proving the request was relayed through the
proxy over TLS. (`socat TCP-LISTEN:1080,fork,reuseaddr OPENSSL:proxy.example.com:443,verify=0`
is a quick one-liner alternative to stunnel.)

## Step 6 — Switch to a real (trusted) certificate

Once the staging flow works, get a production certificate:

1. In the config set `tls.acme.staging: off` (or delete the line).
2. Remove the staging cache so it requests fresh from production:
   `sudo rm -rf /var/lib/alighieri/acme/*`
3. Restart Alighieri and watch the log issue a new cert.

Now the certificate is publicly trusted, so the client can verify it normally —
set `verifyChain = yes` and `CAfile = /etc/ssl/certs/ca-certificates.crt` in
stunnel (or drop `verify=0` from socat). Restarting Alighieri again should
**load the cached cert without re-issuing** — confirm the log shows no new order.

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

## Security note

This config gates access with username/password so it is not an open relay, but
a public SOCKS proxy is still a target. Use a strong password, consider
restricting `client` rules to known source ranges, keep the `deny-loopback`
rule, and review the per-client abuse limits (`ratelimit.*`) before leaving it
running.
