# Benchmarks

The `loadgen` example is the project's end-to-end load generator. It measures
the three numbers that matter for the data path and prints either a
human-readable summary or, with `--json`, a single line suitable for tracking
across commits.

## Scenarios

```sh
cargo run --release --example loadgen -- throughput [--connections N] [--payload BYTES]
cargo run --release --example loadgen -- handshakes [--auth none|plain|argon2]
cargo run --release --example loadgen -- udp [--payload BYTES]
```

- `throughput` — N concurrent CONNECT streams pump fixed-size chunks through
  the proxy to an echo server and back. All streams are established before the
  measurement window opens, so the result reflects steady-state relaying, not
  connection setup. Reported as payload bytes per second per direction (both
  directions carry that rate simultaneously).
- `handshakes` — workers repeatedly perform a full connection setup (TCP
  connect, greeting, optional RFC 1929 authentication (bench/benchpass), CONNECT, teardown) and
  report completed setups per second plus latency percentiles. Socket-level
  failures (ephemeral-port exhaustion) are counted separately from SOCKS-level
  failures so environment limits are not mistaken for proxy verdicts.
- `udp` — one UDP ASSOCIATE association; datagrams are blasted at maximum rate
  through the relay to a UDP echo and counted on return. `received_pps` is the
  sustained round-trip capacity; `delivered %` shows drop behaviour under
  overload (an unthrottled sender is expected to overrun the relay).

Common options: `--connections`, `--duration`, `--payload`, `--json`.

## Methodology notes

- By default the proxy under test is self-hosted in-process (with an
  in-process echo server) so a single command produces a number. Proxy, echo,
  and load generator share one tokio runtime, which understates absolute
  numbers slightly but keeps runs reproducible. For isolated measurements,
  start a release proxy separately on the same host and pass `--proxy ADDR`;
  the generator's echo servers bind to loopback, so a proxy on another
  machine cannot reach them.
- The self-hosted proxy installs a `warn`-level tracing subscriber, so
  per-connection `info!` events are filtered as in a quietly configured
  deployment. Set `RUST_LOG=info` to include logging costs.
- Run scenarios as separate invocations and let the OS recover between
  connection-churn runs. On Windows, a handshake run consumes two ephemeral
  ports per setup and closed sockets linger in TIME_WAIT; back-to-back runs
  starve each other and show up as `socket errors` (WSAEADDRINUSE). The
  harness prints a hint when this happens.
- `--iotimeout SECS` sets `iotimeout` in the self-hosted config, to compare
  relays with and without per-read idle timers.
- `--auth plain|argon2` authenticates with the fixed credentials
  `bench`/`benchpass`. The self-hosted proxy provisions a matching userlist
  automatically; an externally started `--proxy` instance must be configured
  with that user for authenticated scenarios to succeed.

## Baseline (2026-06-12)

Environment: 12th Gen Intel Core i7-1260P, 32 GiB RAM, Windows 11 Pro,
rustc 1.96.0, commit `bea2c97`, self-hosted mode, release profile.

| Scenario | Configuration | Result |
| --- | --- | --- |
| throughput | 1 connection, 64 KiB chunks, 10 s | 237 MiB/s (1.99 Gbit/s) per direction |
| throughput | 8 connections, 64 KiB chunks, 10 s | 951 MiB/s (7.97 Gbit/s) per direction |
| handshakes | auth=none, 32 workers, 3 s | 960/s, p50 33 ms, p95 55 ms |
| handshakes | auth=plain, 32 workers, 5 s | 41.5/s, p50 764 ms, p95 983 ms |
| handshakes | auth=argon2, 32 workers, 5 s | 37.8/s, p50 811 ms, p95 1013 ms |
| udp | 512 B payloads, blast, 10 s | 34,500 pps offered → 6,017 pps round-trip (17.4% delivered) |
Interpretation against the performance roadmap:

- Authentication is the dominant control-plane cost: enabling
  username/password drops connection setup from ~960/s to ~40/s (≈24×) with
  sub-second p50 setup latency, because every connection pays an Argon2id
  verification gated four-wide. Plaintext credentials are just as slow as
  Argon2 entries by design (a dummy Argon2 verification equalises timing), so
  only a verified-credential cache recovers this, not weaker storage.
- The UDP relay saturates near ~6K round-trip packets/sec under blast load;
  per-packet allocation, the per-packet rule-hit lock, and per-packet timer
  churn in the relay loop are the suspected costs to attack first.
- TCP relay throughput scales near-linearly from 1 to 8 streams on this
  8-core machine; no contention cliff is visible at this concurrency. Each
  relayed byte crosses four loopback socket hops in this setup, so absolute
  numbers are conservative.

When a change lands that targets one of these numbers, re-run the matching
scenario with the same parameters and update this table alongside the change.

## Verified-credential cache (2026-06-12)

`auth.cachettl` (default 300 s) caches successful credential verifications as
keyed tags so repeat handshakes skip the full Argon2 cost. Measured with
`handshakes --auth argon2 --connections 32 --duration 5`:

| Configuration | Result |
| --- | --- |
| `--auth-cachettl 0` (cache disabled) | 86/s, p50 375 ms |
| default cache (300 s) | 1,473/s, p50 17 ms |

With the cache enabled, authenticated connection setup reaches the same
OS connection-churn ceiling as the no-auth scenario — authentication is no
longer the bottleneck. Uncached runs vary roughly 40–90/s with CPU thermal
state; both ends sit far below the cached rate. The cache only stores
successes, so failed attempts (brute force, username probing) still pay the
full Argon2 cost.

## Concurrent UDP associate directions (2026-06-12)

The UDP associate relay previously processed both directions in one
serialized loop, so every relayed packet paid a full recv+send round before
the next event was served, and inbound bursts starved the return path. The
two directions now run as separate tasks. Measured with
`udp --duration 5` (512 B payloads, blast):

| Configuration | Result |
| --- | --- |
| single serialized loop | ~4,800 pps round-trip, ~18.5% delivered |
| concurrent directions | ~19,800 pps round-trip, ~76% delivered |

A payload sweep (64 B vs 4 KiB at near-identical pps) showed the path is
per-packet bound, not bandwidth bound; per-packet allocation and timer
churn fixes alone moved nothing, while direction concurrency yielded ~4×.
The remaining ceiling is one syscall pair per datagram per direction —
batched I/O (`recvmmsg`/`sendmmsg`, Windows RIO) is the next step if UDP
packet rate becomes a priority.

## Background log writer (2026-06-12)

Log records were formatted and written synchronously on the data path
through a process-global writer. Measured against an out-of-process release
proxy with file logging (`handshakes --proxy … --connections 16
--duration 3`):

| Configuration | Result |
| --- | --- |
| sync writer, `RUST_LOG=info`, file sink | 1,004/s — 37% below the `RUST_LOG=warn` control (1,593/s) |
| async writer, `RUST_LOG=info`, file sink | indistinguishable from the control (interleaved pairs: 1,399 vs 1,394/s and 1,700 vs 1,394/s under thermal drift) |

Records are still formatted inline but queued to a dedicated writer thread
(8,192-record queue). A full queue drops records and the writer reports the
running drop count in-band — the data plane never blocks on console or file
I/O. A guard held in `main` (and the service entry point) flushes the queue
on shutdown.
