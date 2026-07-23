# Alighieri plugin SDK

Alighieri's `plugins` feature is an in-process Rust SDK for custom policy,
inspection, and relay behavior. Plugins are **statically linked into a custom
host binary** and registered before the server starts. The stock `alighieri`
binary does not scan for or dynamically load plugins, shared libraries, or
configuration-selected modules.

A custom host combines with Alighieri under the project's licensing terms.
Before distributing or operating one, review
[`LICENSING.md`](../LICENSING.md), including the AGPL network-use obligations
and the commercial-license option.

## Set up a custom host

Enable the SDK and add Tokio for the host runtime:

```toml
[dependencies]
alighieri = { version = "0.4", features = ["plugins"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread", "signal", "time"] }
```

The SDK re-exports its `async_trait` attribute, so a plugin does not need a
separate direct dependency on `async-trait`.

This host loads the normal Alighieri configuration, registers an ordered plugin
set, preserves configuration reloads, and uses the standard shutdown path:

```rust
use std::{path::PathBuf, sync::Arc};

use alighieri::{
    config::Config,
    errors::Result,
    plugin::{async_trait, FlowCtx, FlowDecision, Plugin, PluginHost},
    runtime::{
        reload_signal_channel, run_bound_server_reloading_until_shutdown,
        shutdown_signal,
    },
    server::Server,
};

struct Audit;

#[async_trait]
impl Plugin for Audit {
    fn name(&self) -> &str {
        "audit"
    }

    async fn on_flow(&self, ctx: &mut FlowCtx<'_>) -> FlowDecision {
        ctx.tags.insert("audited");
        FlowDecision::Continue
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let config_path = PathBuf::from("alighieri.conf");
    let config = Config::load(&config_path)?;
    let plugins = PluginHost::new(vec![Arc::new(Audit)]);
    let server = Server::bind(config).await?.with_plugins(plugins);

    run_bound_server_reloading_until_shutdown(
        server,
        config_path,
        shutdown_signal(),
        reload_signal_channel(),
    )
    .await
}
```

`Server::with_plugins` must be called after `Server::bind` and before
`Server::run` (or a runtime helper that runs the bound server). The registry is
restart-only; a configuration reload does not replace compiled-in plugins.

## Control plane

`Plugin::on_flow` observes an admitted TCP `CONNECT` flow after DNS and ACL
checks and after the target is connected. It can add tags for later plugins or
return `FlowDecision::Deny`:

```rust
use alighieri::plugin::{async_trait, FlowCtx, FlowDecision, Plugin};

struct PrivateTargetGuard;

#[async_trait]
impl Plugin for PrivateTargetGuard {
    fn name(&self) -> &str {
        "private-target-guard"
    }

    async fn on_flow(&self, ctx: &mut FlowCtx<'_>) -> FlowDecision {
        ctx.tags.insert("policy-checked");
        if ctx.dest.ip().is_loopback() {
            FlowDecision::Deny("loopback targets are not allowed")
        } else {
            FlowDecision::Continue
        }
    }
}
```

The core DNS-deny policy and ACL remain the primary authorization boundary. A
plugin receives the already resolved destination and cannot retarget the flow.
In version 0.4, `on_flow` and the paired `on_flow_end` notification apply to TCP
`CONNECT`; UDP uses the hooks described below.

## TCP interception

`Plugin::intercept` may return a `StreamInterceptor` to own a TCP relay. The
client side supports bounded, non-destructive peeking. If the interceptor
decides not to inspect the flow, `plugin::splice` replays any peeked prefix and
uses the normal timeout and shaping behavior:

```rust
use std::{io, time::Duration};

use alighieri::plugin::{
    self, async_trait, FlowCtx, FlowStats, Plugin, StreamArgs, StreamInterceptor,
};

struct PrefixInterceptor;

#[async_trait]
impl StreamInterceptor for PrefixInterceptor {
    async fn run(
        self: Box<Self>,
        mut args: StreamArgs,
    ) -> io::Result<FlowStats> {
        let prefix = tokio::time::timeout(
            Duration::from_secs(1),
            args.client.peek(5),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "peek timed out"))??;

        if prefix == b"hello" {
            eprintln!("observed the example prefix");
        }

        plugin::splice(args).await
    }
}

struct PrefixPlugin;

#[async_trait]
impl Plugin for PrefixPlugin {
    fn name(&self) -> &str {
        "prefix"
    }

    fn intercept(
        &self,
        _ctx: &FlowCtx<'_>,
    ) -> Option<Box<dyn StreamInterceptor>> {
        Some(Box::new(PrefixInterceptor))
    }
}
```

For an inspect-and-re-originate implementation, pass the SDK-owned
`StreamArgs::throttle` handle to `plugin::relay` so Alighieri continues to apply
its shaping guarantees. Plugins normally treat the client stream and throttle
as opaque capabilities:

- `PeekableClientStream` wraps the SDK-owned `ClientStream`.
- `Throttle` is an SDK-owned handle; `Throttle::unlimited()` is available for
  external tests, while production handles come from the server.
- `ClientStream::from_tcp` and `PeekableClientStream::new` can construct a
  loopback-backed client side in an external plugin test.

`peek` buffers at most `MAX_PEEK` (16 KiB). Apply a deadline as above because a
client can stall before supplying the requested prefix. Treat all intercepted
bytes as untrusted and return errors rather than panicking; Alighieri's release
profile uses `panic = "abort"`.

## UDP datagram decisions

For lightweight filtering, leave the association on the core relay and
implement `Plugin::on_datagram`. The hook runs after the core's validation and
authorization checks. Any plugin returning `Drop` prevents that datagram from
being forwarded:

```rust
use alighieri::plugin::{
    async_trait, DatagramCtx, DatagramVerdict, Direction, Plugin,
};

struct QuicGuard;

#[async_trait]
impl Plugin for QuicGuard {
    fn name(&self) -> &str {
        "quic-guard"
    }

    fn on_datagram(&self, ctx: &DatagramCtx<'_>) -> DatagramVerdict {
        if matches!(ctx.dir, Direction::ClientToTarget)
            && ctx.payload.first().is_some_and(|byte| byte & 0x80 != 0)
        {
            DatagramVerdict::Drop
        } else {
            DatagramVerdict::Forward
        }
    }
}
```

The hook is reactive: it receives a payload and verdict context but cannot
originate or rewrite a datagram. Addresses are canonicalized, and the core
retains source locking, SOCKS framing, fragment rejection, DNS/ACL enforcement,
contacted-remote checks, shaping, and idle accounting.

## UDP association takeover

A plugin that needs its own QUIC or HTTP/3 stack can return a
`DatagramInterceptor` from `intercept_association`. It drives SDK-owned
`ClientDatagrams` and `UpstreamOriginator` facades rather than raw relay
sockets. The simplest interceptor transparently splices the association:

```rust
use std::io;

use alighieri::plugin::{
    self, async_trait, AssociateCtx, AssociationArgs, DatagramInterceptor,
    FlowStats, Plugin,
};

struct TransparentAssociation;

#[async_trait]
impl DatagramInterceptor for TransparentAssociation {
    async fn run(
        self: Box<Self>,
        args: AssociationArgs,
    ) -> io::Result<FlowStats> {
        plugin::splice_association(args).await
    }
}

struct AssociationPlugin;

#[async_trait]
impl Plugin for AssociationPlugin {
    fn name(&self) -> &str {
        "association"
    }

    fn intercept_association(
        &self,
        _ctx: &AssociateCtx<'_>,
    ) -> Option<Box<dyn DatagramInterceptor>> {
        Some(Box::new(TransparentAssociation))
    }
}
```

For external tests, construct the facade graph over bound loopback
`tokio::net::UdpSocket` values:

1. `ClientDatagrams::for_interceptor(socket, client_ip, client_endpoint)`
   creates the validated, header-stripping client leg.
2. `UpstreamOriginator::for_interceptor(socket, outbound_dual, strict_reply,
   authorizer)` creates the destination-authorizing origin leg. The
   `DatagramAuthorizer` callback is the only way to obtain an
   `UpstreamTarget`.
3. `AssociationArgs::for_interceptor(client, upstream, io_timeout)` assembles
   the interceptor input.

These testing constructors supply isolated defaults; production injects the
server's configured DNS-deny policy, ACL, metrics, activity clock, and
throttling. A taken-over association bypasses `on_datagram`, and the core still
ends it when the control connection closes or the association idles out.

## Composition and stability

`PluginHost` evaluates plugins in the order supplied to `PluginHost::new`:

- tags from `on_flow` accumulate and are visible to later plugins;
- the first `FlowDecision::Deny` ends control-plane evaluation;
- the first `Some` returned from `intercept` owns the TCP relay;
- the first `Some` returned from `intercept_association` owns the UDP
  association;
- without association takeover, any `DatagramVerdict::Drop` drops the datagram;
- `on_flow_end` is a best-effort fan-out and must not be the only place durable
  audit data is written.

An empty host is the fast path. The `plugins` feature is off by default, so a
stock build includes neither dispatch code nor its optional macro dependency.

The documented SDK follows the `0.4.x` compatibility policy: patch releases
preserve compatible APIs, and intentional breaking changes require `0.5.0`.
Context and vocabulary types are non-exhaustive or opaque so fields, variants,
and implementation details can evolve. Match non-exhaustive enums with a
wildcard arm and construct non-exhaustive contexts through their public
constructors in tests.
