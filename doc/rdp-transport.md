# RDP Dynamic Virtual Channel transport

Status: implemented Windows MVP, with real two-machine RDP validation remaining
manual. The implementation is enabled by the optional Cargo feature `rdp`;
direct egress remains the default.

## Purpose and scope

The RDP transport lets a local Alighieri SOCKS listener use the network stack of
the Windows machine at the far end of an existing Microsoft Remote Desktop
session. It opens no TCP or UDP listener on the remote machine. The remote
control and data path is a named RDP Dynamic Virtual Channel (DVC).

The MVP supports Microsoft `mstsc.exe`, TCP CONNECT, IPv4, IPv6, hostnames with
remote DNS, simultaneous streams, TCP half-close, bounded flow control, and
recovery after a DVC reconnect. UDP, a Windows service agent, multi-user RDS
selection, GUI configuration, stream resumption, compression, traffic shaping,
and an extra encryption layer are out of scope.

The repository uses `doc/` rather than `docs/`, so this document lives beside
the existing operator and protocol documentation.

## Architecture

```text
application
    |
    | SOCKS5
    v
alighieri.exe (console process, egress: rdp)
    |
    | same-user, local-only named pipe; ALRD protocol
    v
alighieri-rdp-transport.exe
    |  out-of-process COM LocalServer
    |  IWTSPlugin / IWTSListenerCallback / IWTSVirtualChannelCallback
    v
mstsc.exe == existing encrypted RDP connection == remote Windows session
    |
    | WTSVirtualChannelOpenEx(..., WTS_CHANNEL_OPTION_DYNAMIC)
    v
alighieri-rdp-agent.exe
    |
    | remote DNS and outbound TCP
    v
destination
```

The main process owns SOCKS negotiation, authentication, ACL decisions,
throttling, metrics, and relay timeouts. A process-wide RDP connector multiplexes
logical streams over one healthy protocol generation. The platform-independent
core knows only that it can remotely resolve and open an async byte stream; it
does not know about COM, WTS handles, `mstsc`, or registry keys.

The local transport is deliberately a separate process. It is the registered
COM LocalServer and contains only COM/DVC lifecycle, bounded byte bridging, and
registration logic. A plugin failure therefore does not run inside or terminate
`mstsc.exe`. COM callbacks copy validated callback-scoped bytes into bounded
queues and return immediately. Protocol parsing and network relay never run on a
COM callback thread.

The remote agent is an ordinary executable in the interactive RDP user session,
not a service. It is the only component that calls WTS channel APIs and opens
destination sockets.

## Integration with Alighieri

The current direct CONNECT path is retained as the fast default. The narrow
integration seam is the outbound resolve/connect operation immediately before
the existing bidirectional relay. Direct egress continues to produce a Tokio
`TcpStream`; RDP egress produces a logical stream implementing `AsyncRead` and
`AsyncWrite`. The existing generic relay supplies idle timeout, byte counts,
throttling, and correct half-close behavior.

The original hostname is retained for hostname ACLs and logs. For a hostname,
the RDP agent resolves first and returns a bounded address list. Alighieri then
applies its existing DNS family order, `dns.deny` categories, hostname/IP ACLs,
and `dns.tryall` policy before asking the agent to connect to a selected IP.
This two-phase sequence is intentional: resolving and connecting in one remote
operation would let a TCP SYN reach an address that the local ACL rejects.

UDP ASSOCIATE is rejected when `egress: rdp` is selected. It is never allowed to
fall back to direct egress, which would silently leak traffic through the local
machine. The existing `external` source-bind setting applies only to direct
egress; a concrete `external` value with RDP egress is a configuration error in
the MVP.

The version 0.5 plugin SDK exposes a concrete `TcpStream` to stream
interceptors. RDP streams therefore bypass data-plane stream interception in
this MVP rather than breaking the published SDK. Generalising that public type
belongs in an intentional 0.6 API change. Ordinary builds and direct egress are
unchanged.

## DVC and IPC lifecycle

The registered LocalServer implements `IWTSPlugin::Initialize`, retains the
channel manager/listener, and creates the listener `alighieri::rdp::v1`.
`OnNewChannelConnection` accepts at most one active agent channel for the MVP and
returns a new per-channel callback. It then creates the local named-pipe server;
Alighieri's reconnecting client attaches when that bridge becomes available and
ALRD negotiation starts.

The named pipe is local-only, rejects remote clients, and uses a protected DACL
for the creating account plus SYSTEM. The first-instance flag detects an existing
name and fails closed rather than attaching to a pre-created server. The fixed
MVP pipe name is not scoped by logon SID or Windows session, so one local helper
and compatible RDP channel is supported at a time and another process running as
the same account is inside the IPC trust boundary. Windows Service validation
rejects RDP mode because the service runs as `LocalService` in session 0;
cross-session service-to-user brokering needs a separate security design.

`IWTSVirtualChannel::Write` is asynchronous and copies its input. A dedicated
COM-initialised MTA writer actor owns the channel proxy, serializes writes, and
uses a bounded queue. DVC writes on both the COM and WTS sides are split to at
most 1,590 bytes because Microsoft's API documentation is more conservative
than some samples. DVC callback bytes are treated as arbitrary stream chunks;
ALRD framing does not depend on DVC write boundaries.

The remote agent gives one actor exclusive ownership of the WTS channel because
`WTSVirtualChannelRead`/`Write` are not thread-safe. Raw WTS reads contain an
eight-byte `CHANNEL_PDU_HEADER`; the actor validates its declared length and
FIRST/LAST sequence, caps reassembly, and only then feeds bytes to the ALRD
decoder. Consecutive outbound writes are batch-limited so reads and their
flow-control updates continue to make progress.

On `Disconnected`, `Terminated`, `OnClose`, WTS I/O failure, malformed DVC PDU,
or pipe loss, the current generation is cancelled. All logical streams fail and
all remote sockets are dropped. No stream or flow-control state is carried into
the replacement generation; its stream IDs begin at 1 with fresh credit. TCP
streams are not resumable. Both the local
transport and the remote agent remain alive where practical, retry the DVC/pipe,
perform a new HELLO, and accept only new SOCKS requests.

## ALRD version 1 wire format

All integers are unsigned little-endian unless stated otherwise. Every frame has
this fixed 16-byte header:

```text
offset  size  field
0       4     magic = ASCII "ALRD"
4       1     protocol version = 1
5       1     message type
6       2     flags (must be zero in version 1)
8       4     stream_id (zero only for session messages)
12      4     payload_len
16      n     payload
```

The decoder never allocates from `payload_len` until it has checked the magic,
version, type, flags, session-versus-stream ID class, and
`payload_len <= 65,536`. Its aggregate undecoded buffer is capped at two maximum
frames. After bounded frame decoding, the mux validates the frame against its
per-stream protocol state before processing it. Unknown type/version/flags, an
invalid stream ID, a truncated fixed field after a complete frame, or a length
beyond the cap is a fatal generation error.

Version 1 constants are:

```text
maximum frame payload          65,536 bytes
maximum DATA payload           16,384 bytes
maximum hostname               253 bytes
maximum RESOLVE_OK addresses   16
maximum diagnostic text        256 bytes
initial receive window         262,144 bytes per stream
maximum concurrent streams     128
bounded ordered frame queue    512 frames per direction
bounded session-control queue  256 frames per direction
all logical stream buffers     64 MiB maximum per mux endpoint
ordered DATA payload queue     8 MiB maximum per mux endpoint
decoded DATA payload queue     4 MiB maximum per mux endpoint
```

Peers negotiate the smaller advertised DATA size, receive window, and stream
limit. Values outside the version-1 bounds reject the HELLO.

### Address encoding

Only resolved IP socket addresses cross OPEN boundaries:

```text
IPv4: family:u8=1, port:u16, address:[u8;4]
IPv6: family:u8=2, port:u16, address:[u8;16], scope_id:u32
```

IPv4-mapped IPv6 addresses are canonicalised to IPv4 before policy and encoding.
IPv6 flow information is normalised to zero; the scope ID is preserved so
link-local candidates remain usable and distinct. Hostnames occur only in
RESOLVE and are validated as UTF-8 with Alighieri's DNS label/total-length rules.

### Messages

| Value | Message | Stream | Payload and rule |
| ---: | --- | ---: | --- |
| 1 | HELLO | 0 | `role:u8, min_version:u8, max_version:u8, reserved:u8=0, max_data:u32, receive_window:u32, max_streams:u32, generation_nonce:u64` |
| 2 | RESOLVE | nonzero | `port:u16, name_len:u16, hostname:name_len`; local-to-agent only |
| 3 | RESOLVE_OK | same | `count:u16, address[count]`; candidates only, no socket is opened |
| 4 | OPEN | same | one IP address selected and already authorised by local Alighieri |
| 5 | OPEN_OK | same | remote socket's bound socket address; stream becomes OPEN |
| 6 | OPEN_ERROR | same | `code:u8, text_len:u16, text`; a candidate-specific connect error returns a resolved stream to the retryable state, while a resolution error is terminal |
| 7 | DATA | same | 1..negotiated `max_data` bytes; legal only while that send half is open and credit is available |
| 8 | SHUTDOWN_WRITE | same | empty; sender will send no further DATA, recipient shuts down the corresponding socket write half after queued bytes |
| 9 | CLOSE | same | `reason:u8`; aborts/finalises both halves and makes the ID stale |
| 10 | WINDOW_UPDATE | same | `credit:u32`, nonzero; returned only after the receiving application consumes bytes |
| 11 | PING | 0 | `nonce:u64` |
| 12 | PONG | 0 | identical nonce |

HELLO roles are `1=local Alighieri` and `2=remote agent`; the opposite role is
required. A generation is ready after both valid HELLOs. Local-initiated stream
IDs are monotonically increasing odd `u32` values, start at 1, are never reused,
and exhaustion requires a new generation.

RESOLVE failures use OPEN_ERROR. Error codes are `1=general`, `2=policy denied`,
`3=network unreachable`, `4=host/DNS unreachable`, `5=connection refused`,
`6=timeout`, `7=address type unsupported`, and `8=resource limit`. Diagnostic
text is UTF-8, bounded, intended for tracing, and is never exposed verbatim to a
SOCKS client.

CLOSE reasons are `0=normal`, `1=cancelled`, `2=protocol`, `3=I/O`, and
`4=resource limit`. Crossed CLOSE frames are treated as the two peers'
acknowledgements, and a late agent-side CLOSE for an already allocated ID is
ignored to make timeout cancellation race-safe. DATA, OPEN, credit, or shutdown
for an unknown/stale ID is a protocol error, and IDs cannot be reused within a
generation.

### Stream state

```text
Allocated
  -> Resolving -> Resolved
  -> Opening -> Open
  -> HalfClosedLocal / HalfClosedRemote
  -> Closed
```

A domain stream must complete RESOLVE before OPEN, and OPEN must name one of the
returned candidates. An IP-literal stream may move directly to OPEN. A failed
candidate can return to Resolved so `dns.tryall` can attempt another candidate.
Duplicate RESOLVE/OPEN, OPEN_OK for the wrong state, DATA before OPEN, DATA after
SHUTDOWN_WRITE, zero/overflowing WINDOW_UPDATE, and duplicate live IDs are
rejected. Dropping an established logical stream normally sends CLOSE(Normal);
timed-out or abandoned resolve/open work sends CLOSE(Cancelled), while relay I/O
failures send CLOSE(I/O).

## Flow control, backpressure, and fairness

Each side advertises the number of DATA bytes it is prepared to buffer per
stream. A sender deducts bytes before enqueueing DATA and cannot proceed without
credit. A receiver returns credit only as the local consumer reads or writes the
bytes, not merely when a frame is parsed. Credit addition is checked for integer
overflow and cannot exceed the negotiated window.

Inbound queues are bounded per stream and in aggregate by the negotiated stream
count and window. DATA, SHUTDOWN_WRITE, WINDOW_UPDATE, and CLOSE for a stream use
one ordered writer queue so lifecycle frames cannot overtake its data. PING/PONG
use a small session-control queue, but the writer limits control bursts before
servicing ordered traffic. Independent per-stream workers and credit windows
bound one stream's default burst to its 262,144-byte window (16 maximum DATA
frames), after which it must wait for consumption and returned credit. Queue
saturation applies backpressure; a peer that violates its advertised window or
queue/state bounds loses the generation instead of causing unbounded allocation
or tasks.

At most 128 logical streams and 128 concurrent resolve/connect operations exist;
each open stream has exactly two bounded workers and at most one relay task.
Resolution returns at most 16 deduplicated addresses. At maximum negotiated
limits, logical inbound/outbound buffers account for 64 MiB of payload capacity,
the ordered writer queue for 8 MiB, and the decoded reader queue for 4 MiB per
mux endpoint, plus small fixed decoder and bookkeeping overhead. The separate
COM and WTS bridges also use fixed-capacity queues.

## Timeouts and health

Alighieri's configured `dns.timeout` and `connecttimeout` bound how long the
local caller waits, while the agent independently caps each remote resolve and
connect operation at 30 seconds. The effective setup deadline is therefore the
shorter bound. `iotimeout` remains the established logical-relay idle policy.

Each newly attached channel must exchange valid ALRD HELLO messages within 10
seconds. A timeout discards that generation so a silent or incompatible peer
cannot occupy the transport indefinitely.

Each side sends a PING every 15 seconds while no previous ping is outstanding.
The matching PONG must arrive within 45 seconds; an unexpected nonce is a
protocol error. A missed health deadline tears down the generation. Keepalive is
transport health, not TCP stream idle policy.

## Configuration and commands

Default configuration remains direct:

```text
egress: direct
```

RDP console mode is selected explicitly in a build made with `--features rdp`:

```text
internal: 127.0.0.1 port = 1080
egress: rdp
socksmethod: none
client pass { from: 127.0.0.1/32 to: 127.0.0.1/32 }
socks pass { from: 127.0.0.1/32 to: 0.0.0.0/0 command: connect }
socks pass { from: 127.0.0.1/32 to: ::/0 command: connect }
```

`egress` is restart-only. `egress: rdp` is rejected on non-Windows builds, when
the feature is absent, or when a concrete `external` source address is
configured. Windows Service configuration validation also rejects RDP mode: the
managed `LocalService` process runs in session 0 under a different account and
cannot use the interactive user's protected pipe. Starting the interactive
console without a compatible RDP channel is allowed: the SOCKS listener stays
available, CONNECT returns an appropriate failure until a healthy generation
appears, and tracing reports the state transition.

The local helper commands are:

```powershell
.\alighieri-rdp-transport.exe --register             # HKCU, no elevation
.\alighieri-rdp-transport.exe --unregister
.\alighieri-rdp-transport.exe --register --machine   # HKLM, elevated
.\alighieri-rdp-transport.exe --unregister --machine
.\alighieri-rdp-transport.exe -Embedding             # normally launched by COM
```

The remote agent runs in the connected user's RDP desktop:

```powershell
.\alighieri-rdp-agent.exe
.\alighieri-rdp-agent.exe --deny-loopback --deny-private --deny-link-local
```

Agent deny switches are additive and default off so legitimate access to remote
LAN/loopback resources is not silently broken. The local Alighieri DNS deny
policy and SOCKS ACL are still applied to every returned candidate. Operators
should explicitly deny or allow cloud metadata ranges appropriate to their
environment; `--deny-link-local` covers common link-local metadata endpoints but
not every provider-specific private address.

## Registration and deployment

Per-user registration writes:

```text
HKCU\Software\Classes\CLSID\{508D8D20-12D7-4C2E-AB9C-79A38C5B6701}\LocalServer32
    (Default)       = "<absolute path>\alighieri-rdp-transport.exe"
    ServerExecutable = <exact unquoted absolute path>

HKCU\Software\Microsoft\Terminal Server Client\Default\AddIns\AlighieriRdpTransport
    Name = "{508D8D20-12D7-4C2E-AB9C-79A38C5B6701}"
```

Machine registration uses the same paths under HKLM and needs elevation. The
executable verifies absolute paths and quotes the COM command. Register before
starting `mstsc.exe`; restart already-running RDP clients after register or
unregister. Unregistration removes only the exact Alighieri AddIn and CLSID
trees. Machine A needs `alighieri.exe` and `alighieri-rdp-transport.exe` from the
release archive matching A's architecture. Machine B needs only
`alighieri-rdp-agent.exe` from the same Alighieri release, but from the archive
matching B's x86-64 or ARM64 architecture, started inside the intended
interactive RDP session.

A Windows release containing this feature carries:

```text
alighieri.exe
alighieri-rdp-transport.exe
alighieri-rdp-agent.exe
doc/rdp-transport.md
```

## Security considerations

The DVC is protected by RDP transport security, so ALRD adds no redundant
encryption. It does not treat the peer as trusted: every header, length, enum,
hostname, address count, address family, state transition, stream ID, credit,
and nonce is validated before use. All peer-controlled allocation, concurrency,
and diagnostic text is bounded. Malformed input must return errors, never panic.

RDP authentication answers who may establish the desktop session; it does not
make unrestricted remote network egress harmless. The agent can reach whatever
the logged-in Windows user can reach, including loopback, private LANs, and
possibly metadata services. Alighieri ACLs and DNS deny categories remain the
primary policy, with optional agent-side defence in depth. The agent never
listens on a network port.

The local named pipe is not a network boundary. It rejects remote clients, uses
a protected creating-account/SYSTEM DACL, and fails closed if its fixed name
already exists. Access is account-scoped rather than logon-session-scoped;
loosening that boundary for a service or multi-session broker is not permitted
without explicit authentication and session selection.

## Testing

Platform-neutral automated tests cover:

- every frame encode/decode and fragmented/coalesced input;
- maximum and over-maximum lengths, address counts, hostnames, and diagnostics;
- unknown types/versions/flags, integer overflow, malformed UTF-8, and trailing data;
- stream-ID ordering/staleness and invalid transitions;
- strict advertised credit, flow-control replenishment/overflow, negotiated DATA
  limits, and a transfer larger than one receive window;
- crossed clean close followed by a new stream and TCP half-close;
- deterministic resolve failure, connect failure, simultaneous streams, abrupt
  transport loss, and a fresh reconnect generation with no stale state;
- in-memory duplex integration proving independent multiplexed progress.

Windows-only unit tests cover DVC PDU reassembly, bounded WTS write batching,
captured HRESULT mapping, connector shutdown signaling, registry path and pipe
security-string invariants, and argument parsing. Tests that require a real RDP
stack are manual only.

Manual end-to-end procedure:

1. On machine A, build all three binaries with
   `cargo build --release --locked --features rdp --bins`. The commands below
   use the resulting checkout paths; extracted release archives can use their
   archive-root binaries directly.
2. Run `.\target\release\alighieri-rdp-transport.exe --register` before starting
   `mstsc.exe`, and keep that registered executable path stable.
3. Connect from A to Windows machine B with `mstsc.exe`.
4. Copy `.\target\release\alighieri-rdp-agent.exe` to B and run the copied
   `.\alighieri-rdp-agent.exe` inside that RDP session.
5. On A, start `.\target\release\alighieri.exe` with the RDP configuration and
   point an application at its SOCKS listener.
6. Connect to an IP, an IPv6 address, and a hostname; verify with a destination
   service that the source address belongs to B.
7. Run several simultaneous long transfers and a small interactive stream;
   confirm the interactive stream continues to make progress.
8. Exercise client and server half-close, failed DNS, refusal, policy denial,
   max streams, and idle timeout.
9. Disconnect/reconnect RDP. Existing streams must fail and sockets on B must
   close; new SOCKS requests must work after a fresh generation without
   restarting Alighieri or the agent.
10. Unregister the helper and confirm a newly started `mstsc.exe` no longer
    activates it.

Ordinary `cargo test`, default builds, Linux builds, and `--all-features`
non-Windows checks remain mandatory. The RDP feature is built and tested on
Windows x86-64 and is additionally cross-built for Windows ARM64.

## Known MVP limitations and later work

- Microsoft `mstsc.exe` only; other RDP clients may not load this COM AddIn.
- One active compatible DVC/interactive user per local helper.
- Console-mode Alighieri only; the existing `LocalService` deployment cannot
  securely select an interactive user's DVC yet.
- No UDP, stream resumption, agent service, GUI, or multi-user RDS management.
- The current 0.5 plugin data-plane interceptor cannot wrap an RDP upstream.
- Remote DNS is not cached in the MVP; each hostname request uses the remote
  machine's current resolver result.
- Installer integration, Authenticode signing, service brokering, explicit
  metadata CIDRs, richer transport metrics, and automated two-VM RDP testing are
  follow-up work.

## References and differences from SocksOverRDP

Microsoft's current samples and API documentation are normative for the Windows
integration:

- [RDP DVC plugin samples](https://github.com/microsoft/rdp-dvc-plugin-samples)
- [Rust DVC sample](https://github.com/microsoft/rdp-dvc-plugin-samples/tree/main/Simple/rust)
- [DVC implementation details](https://learn.microsoft.com/windows/win32/termserv/dvc-implementation-details)
- [DVC plugin registration](https://learn.microsoft.com/windows/win32/termserv/dvc-plug-in-registration)
- [IWTSVirtualChannel::Write](https://learn.microsoft.com/windows/win32/api/tsvirtualchannels/nf-tsvirtualchannels-iwtsvirtualchannel-write)
- [WTSVirtualChannelOpenEx](https://learn.microsoft.com/windows/win32/api/wtsapi32/nf-wtsapi32-wtsvirtualchannelopenex)
- [CHANNEL_PDU_HEADER](https://learn.microsoft.com/windows/win32/api/pchannel/ns-pchannel-channel_pdu_header)

[SocksOverRDP](https://github.com/nccgroup/SocksOverRDP) is a useful behavioural
reference and is MIT licensed, but ALRD is not wire-compatible. SocksOverRDP
loads an unmanaged DLL in-process, transports an entire SOCKS negotiation, uses
native thread IDs and a close bit for multiplexing, and lacks versioning,
explicit errors, half-close, credits, bounded resources, health checks, and
automatic reopen. Alighieri instead keeps SOCKS and ACL logic in its main
process, uses an out-of-process Rust LocalServer, transports authorised logical
streams, and defines explicit bounded lifecycle and flow-control state.
