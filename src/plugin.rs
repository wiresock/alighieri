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
//! - **`#[non_exhaustive]` everywhere.** New fields/variants can be added without
//!   a breaking release.
//!
//! This first increment is the control plane, the dispatch rules, and the
//! verdict/trait surface. The stream and datagram *data-plane argument* types
//! ([`StreamArgs`] and friends) are intentionally minimal here and grow in a
//! later increment when the hooks are wired into the connection path; because
//! they are `#[non_exhaustive]` and plugins only *receive* them, filling them in
//! is not a breaking change.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::acl::RuleDecision;

// Small, stable engine enums that are part of the SDK's vocabulary. Unlike
// `RuleDecision` (hidden behind the `RuleInfo` facade), these are safe to expose
// directly: they are the SOCKS/rule primitives a plugin reasons about.
pub use crate::acl::Verdict;
pub use crate::config::Protocol;
pub use crate::socks5::Command;

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
/// where TLS-MITM will live: the interceptor consumes the flow, relays (or
/// terminates and re-originates) it, and returns [`FlowStats`].
#[async_trait]
pub trait StreamInterceptor: Send {
    /// Takes over the relay for one flow and runs it to completion.
    async fn run(self: Box<Self>, args: StreamArgs) -> io::Result<FlowStats>;
}

/// Everything a [`StreamInterceptor`] needs to honor the proxy's guarantees.
///
/// This is a forward declaration. The v1 stream data plane — the buffered,
/// peekable client side and the throttle-wrapped target, so shaping and idle
/// enforcement stay in the core — lands when the `intercept` hook is wired into
/// the connection path. Because the type is `#[non_exhaustive]` and plugins only
/// *receive* it, adding those fields later is not a breaking change.
#[non_exhaustive]
pub struct StreamArgs {
    /// The canonical resolved target address.
    pub dst: SocketAddr,
    /// The idle timeout the interceptor must honor.
    pub io_timeout: Duration,
}

// ---------------------------------------------------------------------------
// Data plane: per-datagram verdict (UDP / QUIC)
// ---------------------------------------------------------------------------

/// The direction a datagram is travelling on the UDP path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    /// The datagram's remote peer. On `ClientToTarget`, new destinations are
    /// already DNS/ACL-vetted by the core; on `TargetToClient`, it is the reply
    /// source.
    pub dst: SocketAddr,
    /// The UDP payload (e.g. a QUIC Initial).
    pub payload: &'a [u8],
    /// Read-only view of the flow tags set by [`Plugin::on_flow`].
    pub tags: &'a TagSet,
}

// ---------------------------------------------------------------------------
// The Plugin trait
// ---------------------------------------------------------------------------

/// A first-party plugin. Registered plugins are held by [`PluginHost`] as
/// `Arc<dyn Plugin>` and invoked at the connection seams.
///
/// Every hook has a default no-op body, so a plugin implements only the ones it
/// needs. The SDK docs' cardinal rule for implementors: **return errors, do not
/// `unwrap` on wire input** — see the panic-isolation notes in the design.
#[async_trait]
pub trait Plugin: Send + Sync {
    /// A short, stable name for logs, metrics, and config selection.
    fn name(&self) -> &str;

    /// Control-plane hook, once per flow (TCP and UDP), after ACL/DNS admission
    /// and after the target is connected. Across plugins the first
    /// [`FlowDecision::Deny`] wins; tags accumulate. Default: `Continue`.
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

    /// Best-effort end-of-flow notification. NOT guaranteed on abort/panic, so
    /// durable audit must be written at flow *start*, not here.
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

    // --- fixtures ---------------------------------------------------------

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

        let interceptor = host.intercept(&ctx).expect("an owner should claim the flow");
        let stats = interceptor
            .run(StreamArgs {
                dst: ctx.dest,
                io_timeout: Duration::from_secs(30),
            })
            .await
            .unwrap();
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

        let forward_only = PluginHost::new(vec![Arc::new(DatagramPlugin(DatagramVerdict::Forward))]);
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
