#![cfg(feature = "plugins")]

//! Compile and facade coverage from the same perspective as an external plugin
//! crate. This test deliberately imports only `alighieri::plugin`.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use alighieri::plugin::{
    self, async_trait, AssociateCtx, AssociationArgs, ClientDatagrams, ClientStream, Command,
    DatagramAuthorizer, DatagramCtx, DatagramInterceptor, DatagramVerdict, Direction, FlowCtx,
    FlowDecision, FlowStats, PeekableClientStream, Plugin, PluginHost, Protocol, RuleInfo,
    StreamArgs, StreamInterceptor, TagSet, Throttle, UpstreamOriginator, Verdict,
};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

struct TestStreamInterceptor;

#[async_trait]
impl StreamInterceptor for TestStreamInterceptor {
    async fn run(self: Box<Self>, args: StreamArgs) -> io::Result<FlowStats> {
        assert!(args.throttle.as_ref().is_some_and(Throttle::is_unlimited));
        Ok(FlowStats::new(1, 2))
    }
}

struct TestDatagramInterceptor;

#[async_trait]
impl DatagramInterceptor for TestDatagramInterceptor {
    async fn run(self: Box<Self>, args: AssociationArgs) -> io::Result<FlowStats> {
        assert!(!args.upstream.is_dual_stack());
        assert!(args.client.local_addr()?.ip().is_loopback());
        Ok(FlowStats::new(3, 4))
    }
}

struct TestPlugin;

#[async_trait]
impl Plugin for TestPlugin {
    fn name(&self) -> &str {
        "external-sdk-test"
    }

    async fn on_flow(&self, ctx: &mut FlowCtx<'_>) -> FlowDecision {
        ctx.tags.insert("observed");
        FlowDecision::Continue
    }

    fn intercept(&self, _ctx: &FlowCtx<'_>) -> Option<Box<dyn StreamInterceptor>> {
        Some(Box::new(TestStreamInterceptor))
    }

    fn intercept_association(
        &self,
        _ctx: &AssociateCtx<'_>,
    ) -> Option<Box<dyn DatagramInterceptor>> {
        Some(Box::new(TestDatagramInterceptor))
    }

    fn on_datagram(&self, ctx: &DatagramCtx<'_>) -> DatagramVerdict {
        if ctx.payload.is_empty() {
            DatagramVerdict::Drop
        } else {
            DatagramVerdict::Forward
        }
    }

    async fn on_flow_end(&self, _ctx: &FlowCtx<'_>, stats: &FlowStats) {
        assert_eq!(stats.total(), 3);
    }
}

fn flow_ctx() -> FlowCtx<'static> {
    FlowCtx::new(
        "127.0.0.1:50000".parse().unwrap(),
        "127.0.0.1:1080".parse().unwrap(),
        Command::Connect,
        Protocol::Tcp,
        Some("example.test"),
        "192.0.2.1:443".parse().unwrap(),
        RuleInfo::new(Verdict::Pass, Some(7), Some(Arc::<str>::from("sdk-test"))),
        TagSet::new(),
    )
}

fn associate_ctx(relay_addr: SocketAddr) -> AssociateCtx<'static> {
    AssociateCtx::new(
        "127.0.0.1:50000".parse().unwrap(),
        "127.0.0.1:1080".parse().unwrap(),
        Command::UdpAssociate,
        Protocol::Udp,
        relay_addr,
        None,
        None,
        TagSet::new(),
    )
}

async fn stream_args() -> StreamArgs {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (client, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
    let client = ClientStream::from_tcp(client.unwrap());
    let (target, _) = accepted.unwrap();
    let throttle = Throttle::unlimited();
    assert!(throttle.is_unlimited());
    StreamArgs::new(
        PeekableClientStream::new(client),
        target,
        addr,
        Duration::from_secs(1),
        Some(throttle),
    )
}

async fn association_args() -> (AssociationArgs, SocketAddr) {
    let relay = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let relay_addr = relay.local_addr().unwrap();
    let outbound = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let client = ClientDatagrams::for_interceptor(relay, IpAddr::from([127, 0, 0, 1]), None);
    let authorize: DatagramAuthorizer = Arc::new(|_, _, port| port != 0);
    let upstream = UpstreamOriginator::for_interceptor(outbound, false, true, authorize);
    let target = upstream
        .authorize(None, "192.0.2.1:443".parse().unwrap())
        .expect("the external authorizer should admit the test target");
    assert_eq!(target.dst(), "192.0.2.1:443".parse().unwrap());
    (
        AssociationArgs::for_interceptor(client, upstream, Duration::from_secs(1)),
        relay_addr,
    )
}

#[tokio::test]
async fn external_plugin_can_use_the_complete_curated_sdk() {
    let host = PluginHost::new(vec![Arc::new(TestPlugin)]);
    assert_eq!(host.len(), 1);

    let mut flow = flow_ctx();
    assert_eq!(host.on_flow(&mut flow).await, FlowDecision::Continue);
    assert!(flow.tags.contains("observed"));

    let stream = host
        .intercept(&flow)
        .expect("the test plugin claims the stream");
    assert_eq!(
        stream.run(stream_args().await).await.unwrap(),
        FlowStats::new(1, 2)
    );
    host.on_flow_end(&flow, &FlowStats::new(1, 2)).await;

    let tags = TagSet::new();
    let datagram = DatagramCtx::new(
        Direction::ClientToTarget,
        "192.0.2.1:443".parse().unwrap(),
        b"payload",
        &tags,
    );
    assert_eq!(host.on_datagram(&datagram), DatagramVerdict::Forward);

    let (args, relay_addr) = association_args().await;
    let datagram = host
        .intercept_association(&associate_ctx(relay_addr))
        .expect("the test plugin claims the association");
    assert_eq!(datagram.run(args).await.unwrap(), FlowStats::new(3, 4));

    // The free functions remain part of the facade too. Type-check their
    // signatures without starting long-running relays.
    let _ = plugin::splice;
    let _ = plugin::splice_association;
    let _ = plugin::relay::<tokio::io::DuplexStream, tokio::io::DuplexStream>;
}
