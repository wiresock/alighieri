//! The plugin SDK (`alighieri::plugin`) — the interface first-party plugins
//! implement to observe and act on proxied flows.
//!
//! This is the open-source plugin *interface*. It is compiled only under the
//! `plugins` Cargo feature (off by default), so a stock build carries no plugin
//! code, no extra dependencies, and no added attack surface.
//!
//! The surface splits into a transport-agnostic **control plane** — the
//! [`Plugin`] hooks that observe / allow / deny / tag a flow — and a
//! transport-typed **data plane**: a [`StreamInterceptor`] that owns a TCP relay
//! (where TLS-MITM will live), and a per-datagram [`DatagramVerdict`] returned
//! from [`Plugin::on_datagram`] (where the core keeps the UDP loop and all its
//! association invariants). [`PluginHost`] holds the registered plugins and
//! defines how their results combine.
//!
//! Two design rules keep the interface durable:
//!
//! - **Facades, not engine internals.** [`FlowCtx`] exposes [`RuleInfo`] (a
//!   stable view of the ACL decision), an SDK-owned [`TagSet`], and copies — not
//!   the engine's `RuleDecision`, `Throttle`, or config types — so the engine can
//!   refactor its guts without breaking private plugin crates.
//! - **Evolvable types.** Every public type with public fields or variants (the
//!   argument/context types — [`FlowCtx`], [`StreamArgs`], [`DatagramCtx`],
//!   [`FlowDecision`], [`DatagramVerdict`], [`Direction`], …) is
//!   `#[non_exhaustive]`; types with private fields ([`TagSet`], [`RuleInfo`],
//!   [`PluginHost`], [`Peekable`]) evolve through their methods. Either way, fields
//!   and variants can be added without a breaking release.
//!
//! All three data-plane paths are wired into the connection path: the control
//! plane and the stream interceptor ([`StreamArgs`], [`PeekableClientStream`],
//! [`splice`]/[`relay`]) at the TCP CONNECT handoff, and the per-datagram
//! [`DatagramVerdict`] on both directions of the UDP relay — where the core keeps
//! the loop and its association invariants, acting on the verdict itself. Every
//! argument type is `#[non_exhaustive]`, so growing it (e.g. an explicit
//! throttle-wrapped target, or a UDP association-level control plane) is not a
//! breaking change for plugins, which only *receive* these types.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::acl::RuleDecision;
use crate::client_stream::ClientStream;

// Small, stable engine types that are part of the SDK's vocabulary. Unlike
// `RuleDecision` (hidden behind the `RuleInfo` facade), these are safe to expose
// directly: they are the SOCKS/rule primitives a plugin reasons about, and — for
// `Throttle` — an opaque handle the interceptor only forwards to `splice`/`relay`.
pub use crate::acl::Verdict;
pub use crate::config::Protocol;
pub use crate::socks5::Command;
pub use crate::throttle::Throttle;

// ---------------------------------------------------------------------------
// Control-plane context and facades
// ---------------------------------------------------------------------------

/// An SDK-owned set of string tags attached to a flow by the control plane.
///
/// Tags accumulate across plugins: each plugin's [`Plugin::on_flow`] sees the
/// tags added by earlier plugins and may add its own. This is a facade type, not
/// a re-export of any engine structure.
#[derive(Debug, Clone, Default)]
pub struct TagSet {
    tags: std::collections::BTreeSet<String>,
}

impl TagSet {
    /// Creates an empty tag set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a tag, returning `true` if it was newly inserted.
    pub fn insert(&mut self, tag: impl Into<String>) -> bool {
        self.tags.insert(tag.into())
    }

    /// Reports whether `tag` is present.
    pub fn contains(&self, tag: &str) -> bool {
        self.tags.contains(tag)
    }

    /// Iterates the tags in sorted order.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.tags.iter().map(String::as_str)
    }

    /// The number of tags.
    pub fn len(&self) -> usize {
        self.tags.len()
    }

    /// Reports whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.tags.is_empty()
    }
}

/// A stable, read-only view of the ACL decision that admitted a flow.
///
/// A **facade** over the engine's `RuleDecision`: it exposes only the verdict,
/// the matching rule's source line, and its name, so the engine can evolve
/// `RuleDecision` (e.g. its per-rule bandwidth fields) without breaking plugins.
#[derive(Debug, Clone)]
pub struct RuleInfo {
    verdict: Verdict,
    source_line: Option<usize>,
    rule_name: Option<Arc<str>>,
}

impl RuleInfo {
    /// Builds a `RuleInfo` from its parts. Mainly for plugin authors constructing a
    /// [`FlowCtx`] in their own unit tests; the engine builds one via
    /// [`From<&RuleDecision>`](RuleInfo#impl-From<%26RuleDecision>).
    pub fn new(verdict: Verdict, source_line: Option<usize>, rule_name: Option<Arc<str>>) -> Self {
        RuleInfo {
            verdict,
            source_line,
            rule_name,
        }
    }

    /// The verdict of the matching rule (`Pass`, or `Block` for deny-by-default).
    pub fn verdict(&self) -> Verdict {
        self.verdict
    }

    /// The 1-based config line of the matching rule, if any.
    pub fn source_line(&self) -> Option<usize> {
        self.source_line
    }

    /// The operator-assigned name of the matching rule, if any.
    pub fn rule_name(&self) -> Option<&str> {
        self.rule_name.as_deref()
    }
}

impl From<&RuleDecision> for RuleInfo {
    fn from(d: &RuleDecision) -> Self {
        RuleInfo {
            verdict: d.verdict,
            source_line: d.source_line,
            rule_name: d.rule_name.clone(),
        }
    }
}

/// The transport-agnostic per-flow context passed to the control-plane hooks.
///
/// Built by the engine after ACL/DNS admission and after the target is
/// connected, so a plugin can observe / allow / deny / tag — but not change the
/// destination (`dest` is already connected).
#[derive(Debug)]
#[non_exhaustive]
pub struct FlowCtx<'a> {
    /// The connecting client's address.
    pub client: SocketAddr,
    /// The proxy's own accepting address.
    pub proxy: SocketAddr,
    /// The SOCKS request command.
    pub command: Command,
    /// The transport of the flow.
    pub protocol: Protocol,
    /// The hostname the client requested, if it sent a domain rather than an IP.
    pub dest_host: Option<&'a str>,
    /// The canonical resolved target address.
    pub dest: SocketAddr,
    /// A facade over the ACL decision that admitted the flow.
    pub rule: RuleInfo,
    /// Tags attached to the flow; accumulate across plugins.
    pub tags: TagSet,
}

impl<'a> FlowCtx<'a> {
    /// Builds a `FlowCtx` from its parts. The engine constructs one internally; this
    /// lets plugin authors build one in their own unit tests (the type is
    /// `#[non_exhaustive]`, so struct-literal construction is not available to them).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client: SocketAddr,
        proxy: SocketAddr,
        command: Command,
        protocol: Protocol,
        dest_host: Option<&'a str>,
        dest: SocketAddr,
        rule: RuleInfo,
        tags: TagSet,
    ) -> Self {
        FlowCtx {
            client,
            proxy,
            command,
            protocol,
            dest_host,
            dest,
            rule,
            tags,
        }
    }
}

/// The control-plane verdict returned by [`Plugin::on_flow`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FlowDecision {
    /// Let the flow proceed (possibly after adding tags).
    Continue,
    /// Deny the flow, with a short static reason for logs/audit.
    ///
    /// There is deliberately no `Retarget` variant in v1: redirecting a flow must
    /// re-run DNS-deny + ACL against the new destination (or a plugin becomes an
    /// SSRF / rule-bypass primitive), which is a separate pre-connect concern.
    Deny(&'static str),
}

/// Byte counts for a completed (or intercepted) flow.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct FlowStats {
    /// Bytes relayed from the client toward the target.
    pub to_target: u64,
    /// Bytes relayed from the target toward the client.
    pub to_client: u64,
}

impl FlowStats {
    /// Creates stats from the two directional byte counts.
    pub fn new(to_target: u64, to_client: u64) -> Self {
        FlowStats {
            to_target,
            to_client,
        }
    }

    /// Total bytes relayed in both directions.
    pub fn total(&self) -> u64 {
        self.to_target.saturating_add(self.to_client)
    }
}

// ---------------------------------------------------------------------------
// Data plane: stream interception (TCP)
// ---------------------------------------------------------------------------

/// Owns a TCP relay after a plugin opts in via [`Plugin::intercept`]. This is
/// where TLS-MITM lives: the interceptor consumes the flow, relays (or terminates
/// and re-originates) it, and returns [`FlowStats`].
///
/// For the pass-through decision, call [`splice`]; to relay two streams under the
/// proxy's shaping and idle-timeout guarantees (e.g. the decrypted halves on the
/// inspect path), call [`relay`].
#[async_trait]
pub trait StreamInterceptor: Send {
    /// Takes over the relay for one flow and runs it to completion.
    async fn run(self: Box<Self>, args: StreamArgs) -> io::Result<FlowStats>;
}

/// Everything a [`StreamInterceptor`] needs to honor the proxy's guarantees.
///
/// The client side arrives as a [`PeekableClientStream`] so an interceptor can
/// read the first bytes (a TLS ClientHello) and then either consume them (MITM) or
/// replay-and-splice (pass-through). The target is already TCP-connected and
/// ACL/DNS-vetted. `throttle` carries the flow's shaping buckets; hand the whole
/// `StreamArgs` to [`splice`], or pass `throttle` to [`relay`], so shaping and the
/// idle timeout stay enforced by the core rather than the plugin.
#[non_exhaustive]
pub struct StreamArgs {
    /// The client side, buffered so the ClientHello can be peeked non-destructively.
    pub client: PeekableClientStream,
    /// The connected, ACL/DNS-vetted target.
    pub target: TcpStream,
    /// The canonical resolved target address.
    pub dst: SocketAddr,
    /// The idle timeout the interceptor must honor.
    pub io_timeout: Duration,
    /// The flow's shaping buckets (per-client and/or per-rule), or `None`.
    pub throttle: Option<Throttle>,
}

impl StreamArgs {
    /// Builds a `StreamArgs` from its parts — for plugin authors constructing one in
    /// their own tests (the type is `#[non_exhaustive]`). The engine builds it at the
    /// relay handoff.
    pub fn new(
        client: PeekableClientStream,
        target: TcpStream,
        dst: SocketAddr,
        io_timeout: Duration,
        throttle: Option<Throttle>,
    ) -> Self {
        StreamArgs {
            client,
            target,
            dst,
            io_timeout,
            throttle,
        }
    }
}

/// The client side of an intercepted flow: a [`ClientStream`] with a peek buffer
/// so an interceptor can inspect the first bytes without consuming them.
pub type PeekableClientStream = Peekable<ClientStream>;

/// An `AsyncRead`/`AsyncWrite` wrapper that can buffer ("peek") the first bytes of
/// a stream without consuming them: a later read — or a [`splice`] — replays the
/// peeked bytes first, then continues from the underlying stream.
pub struct Peekable<S> {
    inner: S,
    /// Peeked-but-not-yet-read bytes; `buf[pos..]` is still pending.
    buf: Vec<u8>,
    pos: usize,
}

impl<S> Peekable<S> {
    /// Wraps `inner` with an empty peek buffer.
    pub fn new(inner: S) -> Self {
        Peekable {
            inner,
            buf: Vec::new(),
            pos: 0,
        }
    }
}

/// The largest prefix [`Peekable::peek`] will buffer: one maximum TLS record
/// (16 KiB), which holds any realistic ClientHello / QUIC Initial. `peek` clamps
/// `want` to this, so the primitive cannot be driven to unbounded allocation
/// regardless of caller discipline.
pub const MAX_PEEK: usize = 16 * 1024;

impl<S: AsyncRead + Unpin> Peekable<S> {
    /// Buffers up to `want` bytes (capped at [`MAX_PEEK`]) from the stream *without
    /// consuming them* and returns the buffered prefix. Subsequent reads (and
    /// `peek`s) still see these bytes.
    ///
    /// Returns fewer than `want` bytes at end of stream **or** when `want` exceeds
    /// [`MAX_PEEK`]. It otherwise blocks until `want` bytes arrive, so a caller must
    /// impose its own deadline if the peer may stall (e.g. wrap the call in a
    /// timeout).
    pub async fn peek(&mut self, want: usize) -> io::Result<&[u8]> {
        let want = want.min(MAX_PEEK);
        // Reclaim any already-consumed prefix so an interleaved read/peek pattern
        // does not accumulate dead bytes ahead of the pending region.
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        let mut chunk = [0u8; 4096];
        while self.buf.len() < want {
            let n = self.inner.read(&mut chunk).await?;
            if n == 0 {
                break; // end of stream
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
        let end = want.min(self.buf.len());
        Ok(&self.buf[..end])
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Peekable<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // A zero-capacity read is a successful no-op, not EOF, and must not depend on
        // the inner stream's readiness — handle it up front so neither the buffered
        // branch nor the inner poll can misreport it while peeked bytes are pending.
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let this = &mut *self;
        // Drain any peeked bytes first, then fall through to the underlying stream.
        if this.pos < this.buf.len() {
            let pending = &this.buf[this.pos..];
            let n = pending.len().min(out.remaining());
            out.put_slice(&pending[..n]);
            this.pos += n;
            if this.pos == this.buf.len() {
                this.buf.clear();
                this.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, out)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Peekable<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Relays `client` and `target` in both directions under the proxy's idle-timeout
/// and shaping guarantees, returning the byte counts as [`FlowStats`]. This is the
/// pass-through relay behind [`splice`], and it also serves the inspect path
/// (relaying the two decrypted halves under the same guarantees).
pub async fn relay<C, R>(
    client: C,
    target: R,
    io_timeout: Duration,
    throttle: Option<Throttle>,
) -> io::Result<FlowStats>
where
    C: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
{
    let (up, down) = crate::relay::relay_generic(client, target, io_timeout, throttle).await?;
    Ok(FlowStats::new(up, down))
}

/// The opaque pass-through relay: an interceptor that peeks and decides "not this
/// one" replays the peeked bytes and splices with this. Byte-for-byte equivalent
/// to the core's TCP relay.
pub async fn splice(args: StreamArgs) -> io::Result<FlowStats> {
    let StreamArgs {
        client,
        target,
        io_timeout,
        throttle,
        ..
    } = args;
    relay(client, target, io_timeout, throttle).await
}

// ---------------------------------------------------------------------------
// Data plane: per-datagram verdict (UDP / QUIC)
// ---------------------------------------------------------------------------

/// The direction a datagram is travelling on the UDP path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Direction {
    /// Client → target (the request path).
    ClientToTarget,
    /// Target → client (the reply path).
    TargetToClient,
}

/// The verdict a plugin returns for a single datagram.
///
/// v1 is `Forward` / `Drop` only. A payload-rewriting verdict is deferred to a
/// later datagram-endpoint capability; the enum is `#[non_exhaustive]` so it can
/// return without a breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum DatagramVerdict {
    /// Pass the datagram through unchanged.
    #[default]
    Forward,
    /// Drop the datagram (QUIC-block selects this for chosen hosts).
    Drop,
}

/// Per-datagram context passed to [`Plugin::on_datagram`].
///
/// Deliberately minimal: the core keeps the association state (endpoint lock,
/// contacted-remotes / strict-reply, per-datagram DNS-deny, fragment drop,
/// dual-stack mapping, idle accounting) and surfaces only what a verdict needs.
/// The plugin returns a [`DatagramVerdict`]; it never touches the sockets.
#[derive(Debug)]
#[non_exhaustive]
pub struct DatagramCtx<'a> {
    /// Which direction this datagram is travelling.
    pub dir: Direction,
    /// The datagram's remote peer, as a **canonical** address in both directions
    /// (an IPv4-in-IPv6 `::ffff:` reply from a dual-stack socket is unmapped), so a
    /// plugin can correlate request and reply with a plain `==`. On `ClientToTarget`
    /// it is the DNS/ACL-vetted destination; on `TargetToClient` it is the reply
    /// source.
    pub dst: SocketAddr,
    /// The UDP payload (e.g. a QUIC Initial).
    pub payload: &'a [u8],
    /// Read-only view of the flow tags. **Empty in v1**: UDP has no
    /// [`Plugin::on_flow`] yet (see its docs), so nothing populates them. The field
    /// is present for when a UDP association-level control plane lands.
    pub tags: &'a TagSet,
}

impl<'a> DatagramCtx<'a> {
    /// Builds a `DatagramCtx` from its parts — for plugin authors constructing one in
    /// their own tests (the type is `#[non_exhaustive]`). The engine builds it in the
    /// UDP relay loop.
    pub fn new(dir: Direction, dst: SocketAddr, payload: &'a [u8], tags: &'a TagSet) -> Self {
        DatagramCtx {
            dir,
            dst,
            payload,
            tags,
        }
    }
}

// ---------------------------------------------------------------------------
// The Plugin trait
// ---------------------------------------------------------------------------

/// A first-party plugin. Registered plugins are held by [`PluginHost`] as
/// `Arc<dyn Plugin>` and invoked at the connection seams.
///
/// Every hook has a default no-op body, so a plugin implements only the ones it
/// needs. Cardinal rule for implementors: **return errors, do not `unwrap` on
/// wire input.** A plugin runs in-process with the proxy, and the default release
/// profile is `panic = "abort"`, so a panic on malformed input takes the whole
/// process down; treat all client/target bytes as untrusted.
#[async_trait]
pub trait Plugin: Send + Sync {
    /// A short, stable name for logs, metrics, and config selection.
    fn name(&self) -> &str;

    /// Control-plane hook run once per flow, after ACL/DNS admission and after the
    /// target is connected. Across plugins the first [`FlowDecision::Deny`] wins;
    /// tags accumulate. Default: `Continue`.
    ///
    /// v1 invokes this for **TCP CONNECT** flows only. A UDP ASSOCIATE has no
    /// single target and so no association-level control plane yet, so `on_flow`
    /// does not fire for UDP; per-datagram UDP decisions use
    /// [`Plugin::on_datagram`].
    async fn on_flow(&self, _ctx: &mut FlowCtx<'_>) -> FlowDecision {
        FlowDecision::Continue
    }

    /// TCP stream takeover (where TLS-MITM lives). The first plugin to return
    /// `Some` owns the relay for that flow; `None` leaves it untouched.
    fn intercept(&self, _ctx: &FlowCtx<'_>) -> Option<Box<dyn StreamInterceptor>> {
        None
    }

    /// Per-datagram hook on the UDP path (where QUIC-block lives). The core keeps
    /// the datagram loop and all its association invariants; the plugin only
    /// returns a verdict. Any plugin returning [`DatagramVerdict::Drop`] drops the
    /// datagram. It is **reactive** — it cannot originate a datagram. Fires on
    /// both directions (see [`DatagramCtx::dir`]). Default: `Forward`.
    fn on_datagram(&self, _ctx: &DatagramCtx<'_>) -> DatagramVerdict {
        DatagramVerdict::Forward
    }

    /// Best-effort end-of-flow notification (TCP CONNECT flows in v1, paired with
    /// [`Plugin::on_flow`]). NOT guaranteed on abort/panic, so durable audit must be
    /// written at flow *start*, not here.
    async fn on_flow_end(&self, _ctx: &FlowCtx<'_>, _stats: &FlowStats) {}
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// Holds the registered plugins and defines how their results combine.
///
/// The registry order **is** the evaluation order (the engine builds it from the
/// left-to-right `plugins.enable` config order, independent of any per-plugin
/// config block order). An empty host is the default; the engine checks
/// [`PluginHost::is_empty`] before building a [`FlowCtx`], so a stock deployment
/// pays nothing on the hot path.
#[derive(Clone, Default)]
pub struct PluginHost {
    plugins: Vec<Arc<dyn Plugin>>,
}

impl PluginHost {
    /// Builds a host from an ordered list of plugins (evaluation order).
    pub fn new(plugins: Vec<Arc<dyn Plugin>>) -> Self {
        PluginHost { plugins }
    }

    /// Reports whether no plugins are registered (the zero-cost fast path).
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    /// The number of registered plugins.
    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    /// Runs [`Plugin::on_flow`] across all plugins in order. The first plugin to
    /// return [`FlowDecision::Deny`] wins and stops evaluation; tags added by
    /// earlier plugins are preserved (visible to later plugins and the engine).
    pub async fn on_flow(&self, ctx: &mut FlowCtx<'_>) -> FlowDecision {
        for plugin in &self.plugins {
            if let FlowDecision::Deny(reason) = plugin.on_flow(ctx).await {
                return FlowDecision::Deny(reason);
            }
        }
        FlowDecision::Continue
    }

    /// Offers the flow to each plugin's [`Plugin::intercept`] in order; the first
    /// plugin to return `Some` owns the stream relay. A stream can only be owned
    /// once.
    pub fn intercept(&self, ctx: &FlowCtx<'_>) -> Option<Box<dyn StreamInterceptor>> {
        self.plugins.iter().find_map(|plugin| plugin.intercept(ctx))
    }

    /// Runs [`Plugin::on_datagram`] across all plugins. If any plugin returns
    /// [`DatagramVerdict::Drop`], the datagram is dropped; otherwise it is
    /// forwarded. Because the core owns the loop, this composes safely across
    /// plugins with no single owner.
    pub fn on_datagram(&self, ctx: &DatagramCtx<'_>) -> DatagramVerdict {
        for plugin in &self.plugins {
            if plugin.on_datagram(ctx) == DatagramVerdict::Drop {
                return DatagramVerdict::Drop;
            }
        }
        DatagramVerdict::Forward
    }

    /// Fans out the best-effort [`Plugin::on_flow_end`] notification to every
    /// plugin.
    pub async fn on_flow_end(&self, ctx: &FlowCtx<'_>, stats: &FlowStats) {
        for plugin in &self.plugins {
            plugin.on_flow_end(ctx, stats).await;
        }
    }
}

impl std::fmt::Debug for PluginHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginHost")
            .field(
                "plugins",
                &self.plugins.iter().map(|p| p.name()).collect::<Vec<_>>(),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;

    // --- fixtures ---------------------------------------------------------

    /// A `StreamArgs` backed by a real loopback TCP pair, for exercising an
    /// interceptor's `run` without a full connection.
    async fn loopback_stream_args() -> StreamArgs {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (target, _) = listener.accept().await.unwrap();
        StreamArgs {
            client: PeekableClientStream::new(ClientStream::Tcp(client)),
            target,
            dst: addr,
            io_timeout: Duration::from_secs(30),
            throttle: None,
        }
    }

    fn decision() -> RuleDecision {
        RuleDecision {
            verdict: Verdict::Pass,
            source_line: Some(7),
            rule_name: Some(Arc::from("test-rule")),
            bandwidth: None,
        }
    }

    fn flow_ctx(tags: TagSet) -> FlowCtx<'static> {
        FlowCtx {
            client: "10.0.0.1:5000".parse().unwrap(),
            proxy: "10.0.0.2:1080".parse().unwrap(),
            command: Command::Connect,
            protocol: Protocol::Tcp,
            dest_host: Some("example.com"),
            dest: "93.184.216.34:443".parse().unwrap(),
            rule: RuleInfo::from(&decision()),
            tags,
        }
    }

    fn datagram_ctx<'a>(tags: &'a TagSet, payload: &'a [u8]) -> DatagramCtx<'a> {
        DatagramCtx {
            dir: Direction::ClientToTarget,
            dst: "1.1.1.1:443".parse().unwrap(),
            payload,
            tags,
        }
    }

    // --- test plugins -----------------------------------------------------

    struct Tagger(&'static str);
    #[async_trait]
    impl Plugin for Tagger {
        fn name(&self) -> &str {
            "tagger"
        }
        async fn on_flow(&self, ctx: &mut FlowCtx<'_>) -> FlowDecision {
            ctx.tags.insert(self.0);
            FlowDecision::Continue
        }
    }

    struct Denier(&'static str);
    #[async_trait]
    impl Plugin for Denier {
        fn name(&self) -> &str {
            "denier"
        }
        async fn on_flow(&self, _ctx: &mut FlowCtx<'_>) -> FlowDecision {
            FlowDecision::Deny(self.0)
        }
    }

    struct IdInterceptor(u64);
    #[async_trait]
    impl StreamInterceptor for IdInterceptor {
        async fn run(self: Box<Self>, _args: StreamArgs) -> io::Result<FlowStats> {
            // Encode the owning plugin's id in the stats so a test can tell which
            // plugin won the single-owner race.
            Ok(FlowStats::new(self.0, 0))
        }
    }

    struct Owner(u64);
    #[async_trait]
    impl Plugin for Owner {
        fn name(&self) -> &str {
            "owner"
        }
        fn intercept(&self, _ctx: &FlowCtx<'_>) -> Option<Box<dyn StreamInterceptor>> {
            Some(Box::new(IdInterceptor(self.0)))
        }
    }

    struct Passer;
    #[async_trait]
    impl Plugin for Passer {
        fn name(&self) -> &str {
            "passer"
        }
    }

    struct DatagramPlugin(DatagramVerdict);
    #[async_trait]
    impl Plugin for DatagramPlugin {
        fn name(&self) -> &str {
            "datagram"
        }
        fn on_datagram(&self, _ctx: &DatagramCtx<'_>) -> DatagramVerdict {
            self.0
        }
    }

    struct EndCounter(Arc<AtomicUsize>);
    #[async_trait]
    impl Plugin for EndCounter {
        fn name(&self) -> &str {
            "end-counter"
        }
        async fn on_flow_end(&self, _ctx: &FlowCtx<'_>, _stats: &FlowStats) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    // --- tests ------------------------------------------------------------

    #[test]
    fn rule_info_is_a_facade_over_the_decision() {
        let info = RuleInfo::from(&decision());
        assert_eq!(info.verdict(), Verdict::Pass);
        assert_eq!(info.source_line(), Some(7));
        assert_eq!(info.rule_name(), Some("test-rule"));
    }

    #[test]
    fn flow_stats_total_saturates() {
        assert_eq!(FlowStats::new(3, 4).total(), 7);
        assert_eq!(FlowStats::new(u64::MAX, 1).total(), u64::MAX);
    }

    #[tokio::test]
    async fn peek_buffers_without_consuming() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut writer, reader) = tokio::io::duplex(64);
        writer.write_all(b"hello world").await.unwrap();
        let mut peekable = Peekable::new(reader);
        // Peeking twice returns the same bytes; nothing is consumed.
        assert_eq!(peekable.peek(5).await.unwrap(), b"hello");
        assert_eq!(peekable.peek(5).await.unwrap(), b"hello");
        // A subsequent read still sees the peeked bytes first, in order.
        let mut out = vec![0u8; 11];
        peekable.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"hello world");
    }

    #[tokio::test]
    async fn peek_is_capped_at_max_peek() {
        use tokio::io::AsyncWriteExt;
        let (mut writer, reader) = tokio::io::duplex(MAX_PEEK * 2);
        writer.write_all(&vec![0u8; MAX_PEEK + 100]).await.unwrap();
        let mut peekable = Peekable::new(reader);
        // An over-large `want` is clamped so the buffer cannot grow without limit.
        assert_eq!(peekable.peek(usize::MAX).await.unwrap().len(), MAX_PEEK);
    }

    #[tokio::test]
    async fn empty_host_is_the_zero_cost_default() {
        let host = PluginHost::default();
        assert!(host.is_empty());
        assert_eq!(host.len(), 0);

        let mut ctx = flow_ctx(TagSet::new());
        assert_eq!(host.on_flow(&mut ctx).await, FlowDecision::Continue);
        assert!(host.intercept(&ctx).is_none());

        let tags = TagSet::new();
        let dctx = datagram_ctx(&tags, b"quic");
        assert_eq!(host.on_datagram(&dctx), DatagramVerdict::Forward);

        // Fanning out to no plugins is a harmless no-op.
        host.on_flow_end(&ctx, &FlowStats::default()).await;
    }

    #[tokio::test]
    async fn on_flow_first_deny_wins_and_short_circuits() {
        let host = PluginHost::new(vec![
            Arc::new(Tagger("before")),
            Arc::new(Denier("blocked")),
            Arc::new(Tagger("after")),
        ]);
        let mut ctx = flow_ctx(TagSet::new());

        assert_eq!(host.on_flow(&mut ctx).await, FlowDecision::Deny("blocked"));
        assert!(
            ctx.tags.contains("before"),
            "a plugin before the denier still tags"
        );
        assert!(
            !ctx.tags.contains("after"),
            "the first Deny short-circuits, so later plugins do not run"
        );
    }

    #[tokio::test]
    async fn tags_accumulate_across_plugins() {
        let host = PluginHost::new(vec![Arc::new(Tagger("a")), Arc::new(Tagger("b"))]);
        let mut ctx = flow_ctx(TagSet::new());

        assert_eq!(host.on_flow(&mut ctx).await, FlowDecision::Continue);
        assert!(ctx.tags.contains("a") && ctx.tags.contains("b"));
        assert_eq!(ctx.tags.len(), 2);
    }

    #[tokio::test]
    async fn intercept_first_some_wins() {
        let host = PluginHost::new(vec![
            Arc::new(Passer),
            Arc::new(Owner(1)),
            Arc::new(Owner(2)),
        ]);
        let ctx = flow_ctx(TagSet::new());

        let interceptor = host
            .intercept(&ctx)
            .expect("an owner should claim the flow");
        let stats = interceptor.run(loopback_stream_args().await).await.unwrap();
        assert_eq!(stats.to_target, 1, "the first owner (id 1) wins the race");

        let none = PluginHost::new(vec![Arc::new(Passer)]);
        assert!(
            none.intercept(&ctx).is_none(),
            "no owner means the relay is left untouched"
        );
    }

    #[test]
    fn on_datagram_drop_by_any_plugin_wins() {
        let tags = TagSet::new();
        let dctx = datagram_ctx(&tags, b"payload");

        let forward_only =
            PluginHost::new(vec![Arc::new(DatagramPlugin(DatagramVerdict::Forward))]);
        assert_eq!(forward_only.on_datagram(&dctx), DatagramVerdict::Forward);

        let with_drop = PluginHost::new(vec![
            Arc::new(DatagramPlugin(DatagramVerdict::Forward)),
            Arc::new(DatagramPlugin(DatagramVerdict::Drop)),
        ]);
        assert_eq!(with_drop.on_datagram(&dctx), DatagramVerdict::Drop);
    }

    #[tokio::test]
    async fn on_flow_end_fans_out_to_all() {
        let calls = Arc::new(AtomicUsize::new(0));
        let host = PluginHost::new(vec![
            Arc::new(EndCounter(calls.clone())),
            Arc::new(EndCounter(calls.clone())),
        ]);
        let ctx = flow_ctx(TagSet::new());

        host.on_flow_end(&ctx, &FlowStats::new(10, 20)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
