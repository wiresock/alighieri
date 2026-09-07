//! Remote-session WTS Dynamic Virtual Channel actor.

use std::io;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};
use windows::core::{Error as WindowsError, PCSTR};
use windows::Win32::Foundation::{
    ERROR_BROKEN_PIPE, ERROR_IO_INCOMPLETE, ERROR_PIPE_NOT_CONNECTED, ERROR_TIMEOUT, HANDLE,
    WIN32_ERROR,
};
use windows::Win32::System::RemoteDesktop::{
    WTSVirtualChannelClose, WTSVirtualChannelOpenEx, WTSVirtualChannelRead, WTSVirtualChannelWrite,
    WTS_CHANNEL_OPTION_DYNAMIC, WTS_CURRENT_SESSION,
};

use crate::rdp::mux::{self, AgentPolicy};

use super::pdu::DvcReassembler;
use super::transport::CHANNEL_NAME;

const CHANNEL_NAME_NUL: &[u8] = b"alighieri::rdp::v1\0";
const ACTOR_QUEUE_CAPACITY: usize = 512;
const BRIDGE_CAPACITY: usize = 128 * 1024;
const READ_BUFFER_SIZE: usize = 64 * 1024;
const READ_TIMEOUT_MS: u32 = 50;
const DVC_WRITE_CHUNK: usize = 1_590;
/// Bound consecutive writes so full-duplex reads and their flow-control frames
/// cannot be starved by a continuously replenished outbound queue.
const OUTBOUND_WRITE_BATCH: usize = 8;
const RECONNECT_DELAY: Duration = Duration::from_secs(1);

/// Runs the remote agent in the current interactive RDP session. It retries a
/// lost/missing channel and creates a fresh ALRD generation on every reconnect.
pub async fn run_agent() -> io::Result<()> {
    let Some(policy) = parse_policy(std::env::args().skip(1))? else {
        return Ok(());
    };
    info!(channel = CHANNEL_NAME, "starting Alighieri RDP agent");

    loop {
        let bridge = match open_bridge().await {
            Ok(bridge) => bridge,
            Err(error) => {
                debug!(%error, "RDP Dynamic Virtual Channel is not available yet");
                tokio::select! {
                    result = tokio::signal::ctrl_c() => return result,
                    _ = tokio::time::sleep(RECONNECT_DELAY) => continue,
                }
            }
        };
        info!(
            channel = CHANNEL_NAME,
            "RDP Dynamic Virtual Channel connected"
        );
        tokio::select! {
            result = tokio::signal::ctrl_c() => return result,
            result = bridge.run(policy.clone()) => {
                match result {
                    Ok(()) => debug!("RDP agent generation ended"),
                    Err(error) => warn!(%error, "RDP agent generation was lost"),
                }
            }
        }
        tokio::time::sleep(RECONNECT_DELAY).await;
    }
}

fn parse_policy(arguments: impl IntoIterator<Item = String>) -> io::Result<Option<AgentPolicy>> {
    let mut policy = AgentPolicy::default();
    for argument in arguments {
        match argument.to_ascii_lowercase().as_str() {
            "--deny-loopback" | "/deny-loopback" => policy.deny_loopback = true,
            "--deny-private" | "/deny-private" => policy.deny_private = true,
            "--deny-link-local" | "/deny-link-local" => policy.deny_link_local = true,
            "--help" | "-h" | "/?" => {
                println!("Usage: alighieri-rdp-agent.exe [options]");
                println!("  --deny-loopback    Reject remote loopback destinations");
                println!("  --deny-private     Reject RFC1918/unique-local destinations");
                println!("  --deny-link-local  Reject IPv4/IPv6 link-local destinations");
                return Ok(None);
            }
            unknown => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown agent option '{unknown}'"),
                ));
            }
        }
    }
    Ok(Some(policy))
}

// The generation owns the abortable async pump even if the native actor never
// returns from a WTS call and therefore cannot publish its stop notification.
struct BridgePump(tokio::task::JoinHandle<()>);

impl BridgePump {
    async fn stop(&mut self) {
        self.0.abort();
        // Reap cancellation before reconnecting, so the old duplex and the
        // pump's queue endpoints have actually been dropped, not just marked.
        let _ = (&mut self.0).await;
    }
}

impl Drop for BridgePump {
    fn drop(&mut self) {
        // Also covers Ctrl+C, cancellation of run_agent, and an unpolled run.
        self.0.abort();
    }
}

struct AgentBridge {
    stream: DuplexStream,
    pump: BridgePump,
}

impl AgentBridge {
    async fn run(self, policy: AgentPolicy) -> Result<(), mux::MuxError> {
        let Self { stream, mut pump } = self;
        let result = mux::run_agent_session(stream, policy).await;
        pump.stop().await;
        result
    }
}

async fn open_bridge() -> io::Result<AgentBridge> {
    let (mux_side, actor_side) = tokio::io::duplex(BRIDGE_CAPACITY);
    let (outbound_tx, outbound_rx) = mpsc::channel(ACTOR_QUEUE_CAPACITY);
    let (inbound_tx, inbound_rx) = mpsc::channel(ACTOR_QUEUE_CAPACITY);
    let (ready_tx, ready_rx) = oneshot::channel();
    let (stopped_tx, stopped_rx) = oneshot::channel();
    std::thread::Builder::new()
        .name("alighieri-rdp-wts".into())
        .spawn(move || wts_actor(outbound_rx, inbound_tx, ready_tx, stopped_tx))?;

    ready_rx
        .await
        .map_err(|_| io::Error::other("WTS actor stopped before initialization"))??;
    let pump = BridgePump(tokio::spawn(pump_bridge(
        actor_side,
        outbound_tx,
        inbound_rx,
        stopped_rx,
    )));
    Ok(AgentBridge {
        stream: mux_side,
        pump,
    })
}

async fn pump_bridge(
    bridge: DuplexStream,
    outbound: mpsc::Sender<Vec<u8>>,
    mut inbound: mpsc::Receiver<Vec<u8>>,
    stopped: oneshot::Receiver<()>,
) {
    let (mut reader, mut writer) = tokio::io::split(bridge);
    let to_channel = async {
        let mut buffer = [0u8; 16 * 1024];
        loop {
            let count = reader.read(&mut buffer).await?;
            if count == 0 {
                return Ok::<(), io::Error>(());
            }
            outbound
                .send(buffer[..count].to_vec())
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "WTS actor closed"))?;
        }
    };
    let from_channel = async {
        while let Some(data) = inbound.recv().await {
            writer.write_all(&data).await?;
        }
        writer.shutdown().await
    };
    tokio::select! {
        // Queue closure cannot wake a pump blocked on duplex I/O. Observe
        // actor death independently and drop both duplex halves immediately,
        // including when the stop notification predates this task's first poll.
        _ = stopped => debug!("WTS actor stopped; cancelling both bridge pumps"),
        result = to_channel => if let Err(error) = result { debug!(%error, "WTS outbound bridge stopped"); },
        result = from_channel => if let Err(error) = result { debug!(%error, "WTS inbound bridge stopped"); },
    }
}

fn wts_actor(
    outbound: mpsc::Receiver<Vec<u8>>,
    inbound: mpsc::Sender<Vec<u8>>,
    ready: oneshot::Sender<io::Result<()>>,
    stopped: oneshot::Sender<()>,
) {
    wts_actor_with_channel(outbound, inbound, ready, stopped, || {
        open_channel().map(NativeWtsChannel)
    });
}

// Keep the actor's real control flow testable without a live RDP session. Only
// the native API boundary is substituted; queueing, reassembly and exit paths
// (including stop-before-close ordering) are shared with production. Channel
// implementations release their owned resource in Drop.
trait WtsChannel {
    fn read(&mut self, buffer: &mut [u8]) -> windows::core::Result<usize>;
    fn write(&mut self, data: &[u8]) -> io::Result<()>;
}

struct NativeWtsChannel(HANDLE);

impl Drop for NativeWtsChannel {
    fn drop(&mut self) {
        close_channel(self.0);
    }
}

struct ActorChannel<C> {
    channel: C,
    stopped: Option<oneshot::Sender<()>>,
}

impl<C> Drop for ActorChannel<C> {
    fn drop(&mut self) {
        // Drop runs before the channel field's destructor, including during
        // unwinding. Publish termination before a potentially blocking close;
        // queue-endpoint destruction alone would publish it too late.
        if let Some(stopped) = self.stopped.take() {
            let _ = stopped.send(());
        }
    }
}

impl WtsChannel for NativeWtsChannel {
    fn read(&mut self, buffer: &mut [u8]) -> windows::core::Result<usize> {
        let mut count = 0u32;
        // SAFETY: the channel handle is owned exclusively by this actor thread;
        // the mutable buffer and count out pointer remain live for the call.
        unsafe { WTSVirtualChannelRead(self.0, READ_TIMEOUT_MS, buffer, &mut count) }?;
        Ok(count as usize)
    }

    fn write(&mut self, data: &[u8]) -> io::Result<()> {
        write_channel(self.0, data)
    }
}

fn wts_actor_with_channel<C: WtsChannel>(
    mut outbound: mpsc::Receiver<Vec<u8>>,
    inbound: mpsc::Sender<Vec<u8>>,
    ready: oneshot::Sender<io::Result<()>>,
    stopped: oneshot::Sender<()>,
    open: impl FnOnce() -> io::Result<C>,
) {
    let channel = match open() {
        Ok(channel) => channel,
        Err(error) => {
            let _ = ready.send(Err(error));
            return;
        }
    };
    let mut owner = ActorChannel {
        channel,
        stopped: Some(stopped),
    };
    if ready.send(Ok(())).is_err() {
        return;
    }

    let mut reassembler = DvcReassembler::new();
    let mut read_buffer = vec![0u8; READ_BUFFER_SIZE];
    loop {
        match drain_outbound_batch(&mut outbound, |data| owner.channel.write(data)) {
            Ok(OutboundQueueState::Open) => {}
            Ok(OutboundQueueState::Closed) => break,
            Err(error) => {
                debug!(%error, "WTS channel write failed");
                break;
            }
        }

        let count = match owner.channel.read(&mut read_buffer) {
            Ok(count) => count,
            Err(error) => {
                // A no-data result is the actor's scheduling tick, not a session
                // failure. WTS can report a finite read timeout as either
                // ERROR_TIMEOUT or ERROR_IO_INCOMPLETE.
                // Inspect the error already captured by windows-rs rather than
                // consulting the thread-local last-error value a second time.
                if is_wts_read_poll_tick(&error) {
                    continue;
                }
                let win32 = win32_error_code(&error);
                debug!(%error, ?win32, "WTS channel read failed");
                break;
            }
        };
        if count == 0 {
            break;
        }
        if count > read_buffer.len() {
            warn!(count, "WTS returned an impossible read length");
            break;
        }
        match reassembler.push(&read_buffer[..count]) {
            Ok(Some(message)) => {
                if let Err(error) = forward_inbound(&inbound, message) {
                    warn!(%error, "WTS inbound bridge stopped");
                    break;
                }
            }
            Ok(None) => {}
            Err(error) => {
                warn!(%error, "malformed WTS DVC PDU sequence");
                break;
            }
        }
    }
}

fn forward_inbound(inbound: &mpsc::Sender<Vec<u8>>, message: Vec<u8>) -> io::Result<()> {
    // This actor also writes WINDOW_UPDATE and CLOSE traffic. Waiting for the
    // mux to drain inbound data can therefore deadlock both directions. Losing
    // any bytes would corrupt framing, so overload ends the entire generation.
    inbound.try_send(message).map_err(|error| match error {
        mpsc::error::TrySendError::Full(_) => {
            io::Error::new(io::ErrorKind::WouldBlock, "WTS receive queue is full")
        }
        mpsc::error::TrySendError::Closed(_) => {
            io::Error::new(io::ErrorKind::BrokenPipe, "WTS receive bridge closed")
        }
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutboundQueueState {
    Open,
    Closed,
}

fn drain_outbound_batch(
    outbound: &mut mpsc::Receiver<Vec<u8>>,
    mut write: impl FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<OutboundQueueState> {
    for _ in 0..OUTBOUND_WRITE_BATCH {
        match outbound.try_recv() {
            Ok(data) => write(&data)?,
            Err(mpsc::error::TryRecvError::Empty) => return Ok(OutboundQueueState::Open),
            Err(mpsc::error::TryRecvError::Disconnected) => {
                return Ok(OutboundQueueState::Closed);
            }
        }
    }

    if outbound.is_closed() && outbound.is_empty() {
        Ok(OutboundQueueState::Closed)
    } else {
        Ok(OutboundQueueState::Open)
    }
}

fn open_channel() -> io::Result<HANDLE> {
    // SAFETY: channel name is static ASCII with a trailing NUL. The returned
    // handle never leaves the single owner actor thread.
    let channel = unsafe {
        WTSVirtualChannelOpenEx(
            WTS_CURRENT_SESSION,
            PCSTR(CHANNEL_NAME_NUL.as_ptr()),
            WTS_CHANNEL_OPTION_DYNAMIC,
        )
    }
    .map_err(windows_error)?;
    if channel.is_invalid() || channel.0.is_null() {
        Err(io::Error::other("WTS returned an invalid DVC handle"))
    } else {
        Ok(channel)
    }
}

fn write_channel(channel: HANDLE, data: &[u8]) -> io::Result<()> {
    for chunk in data.chunks(DVC_WRITE_CHUNK) {
        let mut written = 0u32;
        // SAFETY: the actor exclusively owns `channel`; WTS copies the live
        // chunk before returning and initializes `written`.
        unsafe { WTSVirtualChannelWrite(channel, chunk, &mut written) }.map_err(windows_error)?;
        if written as usize != chunk.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!("WTS wrote {written} of {} DVC bytes", chunk.len()),
            ));
        }
    }
    Ok(())
}

fn close_channel(channel: HANDLE) {
    // SAFETY: called exactly once by the actor that owns the channel handle.
    if let Err(error) = unsafe { WTSVirtualChannelClose(channel) } {
        if !is_win32_error(&error, ERROR_BROKEN_PIPE)
            && !is_win32_error(&error, ERROR_PIPE_NOT_CONNECTED)
        {
            let win32 = win32_error_code(&error);
            debug!(%error, ?win32, "failed to close WTS DVC handle");
        }
    }
}

fn is_win32_error(error: &WindowsError, expected: WIN32_ERROR) -> bool {
    win32_error_code(error) == Some(expected.0)
}

fn is_wts_read_poll_tick(error: &WindowsError) -> bool {
    is_win32_error(error, ERROR_TIMEOUT) || is_win32_error(error, ERROR_IO_INCOMPLETE)
}

fn win32_error_code(error: &WindowsError) -> Option<u32> {
    let hresult = error.code().0 as u32;
    (hresult & 0xffff_0000 == 0x8007_0000).then_some(hresult & 0x0000_ffff)
}

fn windows_error(error: WindowsError) -> io::Error {
    match win32_error_code(&error) {
        Some(code) => io::Error::from_raw_os_error(code as i32),
        None => io::Error::other(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rdp::protocol::{Frame, FrameDecoder, Hello, Role};
    use std::future::Future;
    use std::sync::{Arc, Condvar, Mutex};
    use tokio::net::TcpListener;
    use windows::core::HRESULT;

    struct BlockedWriteChannel {
        entered: Option<oneshot::Sender<()>>,
        release: Arc<(Mutex<bool>, Condvar)>,
    }

    impl WtsChannel for BlockedWriteChannel {
        fn read(&mut self, _buffer: &mut [u8]) -> windows::core::Result<usize> {
            panic!("the primed write must run before any read");
        }

        fn write(&mut self, _data: &[u8]) -> io::Result<()> {
            self.entered.take().unwrap().send(()).unwrap();
            let (released, wake) = &*self.release;
            let mut released = released.lock().unwrap();
            while !*released {
                released = wake.wait(released).unwrap();
            }
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }
    }

    // Always release and join the fake native worker, even if a test fails.
    // Production native calls are not claimed to support this test-only escape.
    struct BlockedActor {
        release: Arc<(Mutex<bool>, Condvar)>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl Drop for BlockedActor {
        fn drop(&mut self) {
            let (released, wake) = &*self.release;
            *released.lock().unwrap_or_else(|error| error.into_inner()) = true;
            wake.notify_one();
            let _ = self.thread.take().unwrap().join();
        }
    }

    async fn bridge_with_blocked_native_write() -> (AgentBridge, BlockedActor) {
        let (mut stream, actor_side) = tokio::io::duplex(1);
        let (outbound_tx, outbound_rx) = mpsc::channel(1);
        let (inbound_tx, inbound_rx) = mpsc::channel(1);
        let (ready_tx, ready_rx) = oneshot::channel();
        let (stopped_tx, stopped_rx) = oneshot::channel();
        let (entered_tx, entered_rx) = oneshot::channel();
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let channel = BlockedWriteChannel {
            entered: Some(entered_tx),
            release: release.clone(),
        };
        outbound_tx.try_send(vec![0]).unwrap();
        let thread = std::thread::spawn(move || {
            wts_actor_with_channel(outbound_rx, inbound_tx, ready_tx, stopped_tx, || {
                Ok(channel)
            });
        });
        let actor = BlockedActor {
            release,
            thread: Some(thread),
        };
        tokio::time::timeout(Duration::from_secs(3), ready_rx)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(3), entered_rx)
            .await
            .unwrap()
            .unwrap();
        // The real actor is now parked in write(), retaining both queue ends
        // and the stop sender. Fill its queue before starting the pump.
        outbound_tx.try_send(vec![1]).unwrap();
        let pump = BridgePump(tokio::spawn(pump_bridge(
            actor_side,
            outbound_tx,
            inbound_rx,
            stopped_rx,
        )));
        // Capacity is one: completing this write proves the pump read its first
        // byte, then parked on the full outbound queue. Its reverse direction
        // has no inbound data and waits on recv, not duplex I/O.
        tokio::time::timeout(Duration::from_secs(3), stream.write_all(&[2, 3]))
            .await
            .unwrap()
            .unwrap();
        (AgentBridge { stream, pump }, actor)
    }

    #[tokio::test]
    async fn dead_mux_requires_pump_abort_while_native_write_is_blocked() {
        let (AgentBridge { stream, mut pump }, actor) = bridge_with_blocked_native_write().await;
        drop(stream);
        assert!(tokio::time::timeout(Duration::from_millis(20), &mut pump.0)
            .await
            .is_err());
        tokio::time::timeout(Duration::from_secs(3), pump.stop())
            .await
            .expect("abort must reap the pump without waiting for native Write");
        assert!(pump.0.is_finished());
        assert!(!actor.thread.as_ref().unwrap().is_finished());
    }

    #[tokio::test]
    async fn mux_timeout_reaps_pump_before_returning_while_native_write_is_blocked() {
        let (bridge, actor) = bridge_with_blocked_native_write().await;
        let pump = bridge.pump.0.abort_handle();
        tokio::time::pause();
        let mut session = Box::pin(bridge.run(AgentPolicy::default()));
        // Poll the real session to install its handshake timeout before moving
        // virtual time. It cannot write HELLO through the saturated bridge.
        assert!(
            std::future::poll_fn(|cx| std::task::Poll::Ready(session.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        tokio::time::advance(Duration::from_secs(11)).await;
        let result = tokio::time::timeout(Duration::from_secs(3), session)
            .await
            .expect("session return must not await native Write");
        assert!(matches!(result, Err(mux::MuxError::Timeout)));
        assert!(pump.is_finished(), "reconnect must not retain the old pump");
        assert!(!actor.thread.as_ref().unwrap().is_finished());
    }

    #[tokio::test]
    async fn dropping_generation_aborts_pump_even_if_session_was_never_polled() {
        for poll_session in [false, true] {
            let (bridge, actor) = bridge_with_blocked_native_write().await;
            let pump = bridge.pump.0.abort_handle();
            let mut session = Box::pin(bridge.run(AgentPolicy::default()));
            if poll_session {
                assert!(std::future::poll_fn(|cx| std::task::Poll::Ready(
                    session.as_mut().poll(cx)
                ))
                .await
                .is_pending());
            }
            drop(session);
            tokio::time::timeout(Duration::from_secs(3), async {
                while !pump.is_finished() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("cancelling a generation must abort its pump");
            assert!(!actor.thread.as_ref().unwrap().is_finished());
        }
    }

    enum ActorRead {
        Bytes(Vec<u8>),
        Count(usize),
        Error(WIN32_ERROR),
    }

    struct TestWtsChannel<'a> {
        scenario: &'static str,
        read: Option<ActorRead>,
        fail_write: bool,
        stopped: &'a mut oneshot::Receiver<()>,
        closes: &'a mut usize,
    }

    impl WtsChannel for TestWtsChannel<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> windows::core::Result<usize> {
            match self.read.take().expect("unexpected actor read") {
                ActorRead::Bytes(data) => {
                    buffer[..data.len()].copy_from_slice(&data);
                    Ok(data.len())
                }
                ActorRead::Count(count) => Ok(count),
                ActorRead::Error(error) => {
                    Err(WindowsError::from_hresult(HRESULT::from_win32(error.0)))
                }
            }
        }

        fn write(&mut self, _data: &[u8]) -> io::Result<()> {
            assert!(self.fail_write, "unexpected actor write");
            self.fail_write = false;
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }
    }

    impl Drop for TestWtsChannel<'_> {
        fn drop(&mut self) {
            // This runs at entry to the close API, not after the actor returns.
            // Removing the owner's stop notification must fail even though
            // dropping the sender would eventually wake the pump after close.
            assert_eq!(self.stopped.try_recv(), Ok(()), "{}", self.scenario);
            assert!(self.read.is_none(), "{} exited before read", self.scenario);
            assert!(!self.fail_write, "{} exited before write", self.scenario);
            *self.closes += 1;
        }
    }

    #[test]
    fn actor_exit_paths_signal_stop_before_close() {
        for scenario in [
            "initialization cancelled",
            "outbound closed",
            "write failure",
            "read failure",
            "read EOF",
            "oversized read",
            "malformed PDU",
            "inbound full",
            "inbound closed",
        ] {
            let (outbound_tx, outbound_rx) = mpsc::channel(1);
            let (inbound_tx, inbound_rx) = mpsc::channel(1);
            let (ready_tx, ready_rx) = oneshot::channel();
            let (stopped_tx, mut stopped_rx) = oneshot::channel();
            let mut outbound_tx = Some(outbound_tx);
            let mut inbound_rx = Some(inbound_rx);
            let mut ready_rx = Some(ready_rx);
            let mut closes = 0;
            let mut channel = TestWtsChannel {
                scenario,
                read: None,
                fail_write: false,
                stopped: &mut stopped_rx,
                closes: &mut closes,
            };
            match scenario {
                "initialization cancelled" => drop(ready_rx.take()),
                "outbound closed" => drop(outbound_tx.take()),
                "write failure" => {
                    outbound_tx.as_ref().unwrap().try_send(vec![1]).unwrap();
                    channel.fail_write = true;
                }
                "read failure" => channel.read = Some(ActorRead::Error(ERROR_BROKEN_PIPE)),
                "read EOF" => channel.read = Some(ActorRead::Count(0)),
                "oversized read" => channel.read = Some(ActorRead::Count(READ_BUFFER_SIZE + 1)),
                "malformed PDU" => channel.read = Some(ActorRead::Bytes(vec![0])),
                "inbound full" | "inbound closed" => {
                    if scenario == "inbound full" {
                        inbound_tx.try_send(vec![0]).unwrap();
                    } else {
                        drop(inbound_rx.take());
                    }
                    // One complete WTS CHANNEL_PDU_HEADER + payload (FIRST|LAST).
                    channel.read = Some(ActorRead::Bytes(vec![1, 0, 0, 0, 3, 0, 0, 0, 42]));
                }
                _ => unreachable!(),
            }
            wts_actor_with_channel(outbound_rx, inbound_tx, ready_tx, stopped_tx, || {
                Ok(channel)
            });
            assert_eq!(closes, 1, "{scenario}");
            if let Some(mut ready_rx) = ready_rx {
                ready_rx.try_recv().unwrap().unwrap();
            }
        }
    }

    #[test]
    fn actor_open_failure_reports_error_and_drops_stop_sender() {
        let (_outbound_tx, outbound_rx) = mpsc::channel(1);
        let (inbound_tx, _inbound_rx) = mpsc::channel(1);
        let (ready_tx, mut ready_rx) = oneshot::channel();
        let (stopped_tx, mut stopped_rx) = oneshot::channel();
        wts_actor_with_channel::<TestWtsChannel<'_>>(
            outbound_rx,
            inbound_tx,
            ready_tx,
            stopped_tx,
            || Err(io::Error::from(io::ErrorKind::NotConnected)),
        );
        assert_eq!(
            ready_rx.try_recv().unwrap().unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
        assert_eq!(
            stopped_rx.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        );
    }

    struct PanickingWtsChannel<'a> {
        operation: &'static str,
        stopped: &'a mut oneshot::Receiver<()>,
        stop_at_close: &'a mut Option<Result<(), oneshot::error::TryRecvError>>,
        closes: &'a mut usize,
    }

    impl WtsChannel for PanickingWtsChannel<'_> {
        fn read(&mut self, _buffer: &mut [u8]) -> windows::core::Result<usize> {
            assert_eq!(self.operation, "read");
            panic!("injected actor read panic");
        }

        fn write(&mut self, _data: &[u8]) -> io::Result<()> {
            assert_eq!(self.operation, "write");
            panic!("injected actor write panic");
        }
    }

    impl Drop for PanickingWtsChannel<'_> {
        fn drop(&mut self) {
            // Record, do not assert while unwinding: a failed regression must
            // report normally instead of aborting on a second panic in Drop.
            *self.stop_at_close = Some(self.stopped.try_recv());
            *self.closes += 1;
        }
    }

    #[test]
    fn actor_panic_signals_stop_before_closing_channel_once() {
        for operation in ["read", "write"] {
            let (outbound_tx, outbound_rx) = mpsc::channel(1);
            let (inbound_tx, _inbound_rx) = mpsc::channel(1);
            let (ready_tx, mut ready_rx) = oneshot::channel();
            let (stopped_tx, mut stopped_rx) = oneshot::channel();
            if operation == "write" {
                outbound_tx.try_send(vec![1]).unwrap();
            }
            let mut stop_at_close = None;
            let mut closes = 0;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                wts_actor_with_channel(outbound_rx, inbound_tx, ready_tx, stopped_tx, || {
                    Ok(PanickingWtsChannel {
                        operation,
                        stopped: &mut stopped_rx,
                        stop_at_close: &mut stop_at_close,
                        closes: &mut closes,
                    })
                });
            }));
            let panic = result.expect_err("the actor must reach the injected panic");
            assert_eq!(
                panic.downcast_ref::<&str>(),
                Some(&match operation {
                    "read" => "injected actor read panic",
                    "write" => "injected actor write panic",
                    _ => unreachable!(),
                })
            );
            ready_rx.try_recv().unwrap().unwrap();
            assert_eq!(stop_at_close, Some(Ok(())), "{operation}");
            assert_eq!(closes, 1, "{operation}");
        }
    }

    #[tokio::test]
    async fn actor_death_cancels_pumps_parked_on_duplex_io() {
        let (mut mux_side, actor_side) = tokio::io::duplex(1);
        let (outbound_tx, outbound_rx) = mpsc::channel(1);
        let (inbound_tx, inbound_rx) = mpsc::channel(1);
        let (stopped_tx, stopped_rx) = oneshot::channel();
        let pump = tokio::spawn(pump_bridge(actor_side, outbound_tx, inbound_rx, stopped_rx));

        forward_inbound(&inbound_tx, vec![1; 64]).unwrap();
        // Reading one byte proves from_channel started its write. Its remaining
        // bytes cannot fit; to_channel has no duplex input and awaits a read.
        let mut byte = [0];
        tokio::time::timeout(Duration::from_secs(3), mux_side.read_exact(&mut byte))
            .await
            .unwrap()
            .unwrap();
        forward_inbound(&inbound_tx, vec![2; 64]).unwrap();
        assert_eq!(
            forward_inbound(&inbound_tx, vec![3]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        stopped_tx.send(()).unwrap();
        drop(inbound_tx);
        drop(outbound_rx);
        tokio::time::timeout(Duration::from_secs(3), pump)
            .await
            .expect("actor death must cancel duplex I/O, not wait for queue polling")
            .unwrap();
        let mut tail = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), mux_side.read_to_end(&mut tail))
            .await
            .expect("dropping the bridge must expose EOF to the mux")
            .unwrap();
        assert!(tail.len() <= 1);
    }

    #[tokio::test]
    async fn actor_stop_before_pump_start_is_not_lost() {
        let (mut mux_side, actor_side) = tokio::io::duplex(1);
        let (outbound_tx, _outbound_rx) = mpsc::channel(1);
        let (_inbound_tx, inbound_rx) = mpsc::channel(1);
        let (stopped_tx, stopped_rx) = oneshot::channel();
        // Dropping the sender also covers unexpected actor exit/unwinding.
        drop(stopped_tx);
        tokio::time::timeout(
            Duration::from_secs(3),
            pump_bridge(actor_side, outbound_tx, inbound_rx, stopped_rx),
        )
        .await
        .expect("a stop preceding the first pump poll must remain observable");
        assert_eq!(mux_side.read(&mut [0]).await.unwrap(), 0);
    }

    async fn receive_actor_frame(outbound: &mut mpsc::Receiver<Vec<u8>>) -> Frame {
        let mut decoder = FrameDecoder::new();
        loop {
            let bytes = tokio::time::timeout(Duration::from_secs(3), outbound.recv())
                .await
                .unwrap()
                .expect("agent must respond before actor shutdown");
            let mut frames = decoder.push(&bytes).unwrap();
            if !frames.is_empty() {
                // Setup sends one request at a time, before keepalive begins.
                assert_eq!(frames.len(), 1);
                assert_eq!(decoder.buffered_len(), 0);
                return frames.remove(0);
            }
        }
    }

    #[tokio::test]
    async fn actor_saturation_stops_agent_and_tcp_without_waiting_for_mux_timeout() {
        // Use the real bridge/mux composition with smaller queues to make
        // both-direction backpressure deterministic without megabytes of data.
        let (mux_side, actor_side) = tokio::io::duplex(64);
        let (outbound_tx, mut outbound_rx) = mpsc::channel(1);
        let (inbound_tx, inbound_rx) = mpsc::channel(1);
        let (stopped_tx, stopped_rx) = oneshot::channel();
        let pump = tokio::spawn(pump_bridge(actor_side, outbound_tx, inbound_rx, stopped_rx));
        let agent = tokio::spawn(mux::run_agent_session(mux_side, AgentPolicy::default()));
        forward_inbound(
            &inbound_tx,
            Frame::Hello(Hello::new(Role::Local, 1)).encode().unwrap(),
        )
        .unwrap();
        assert!(matches!(
            receive_actor_frame(&mut outbound_rx).await,
            Frame::Hello(_)
        ));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        forward_inbound(
            &inbound_tx,
            Frame::Open {
                stream_id: 1,
                address: listener.local_addr().unwrap(),
            }
            .encode()
            .unwrap(),
        )
        .unwrap();
        let (mut destination, _) = tokio::time::timeout(Duration::from_secs(3), listener.accept())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            receive_actor_frame(&mut outbound_rx).await,
            Frame::OpenOk { stream_id: 1, .. }
        ));

        // Stop consuming actor output. Enough PINGs fill the writer's control
        // queue and decoded-frame queue, leaving from_channel in write_all and
        // the reverse pump waiting for the actor to consume its bounded queue.
        let flood = Frame::Ping { nonce: 7 }.encode().unwrap().repeat(1024);
        forward_inbound(&inbound_tx, flood.clone()).unwrap();
        tokio::time::timeout(Duration::from_secs(3), inbound_tx.send(flood))
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            while outbound_rx.is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            forward_inbound(&inbound_tx, vec![0]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(!agent.is_finished());

        // Signal before closing WTS. Keep the fake actor's queue endpoints
        // alive: cleanup must not depend on the Windows close API returning.
        stopped_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(3), pump)
            .await
            .expect("actor death must promptly stop the duplex bridge")
            .unwrap();
        assert!(tokio::time::timeout(Duration::from_secs(3), agent)
            .await
            .expect("agent teardown must not wait for the 45-second mux timeout")
            .unwrap()
            .is_err());
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(3), destination.read(&mut [0]))
                .await
                .expect("agent teardown must close the destination TCP socket")
                .unwrap(),
            0
        );
        drop((inbound_tx, outbound_rx));
    }

    #[test]
    fn policy_arguments_are_explicit_and_help_exits() {
        let policy = parse_policy([
            "--deny-loopback".to_owned(),
            "--deny-private".to_owned(),
            "--deny-link-local".to_owned(),
        ])
        .unwrap()
        .unwrap();
        assert!(policy.deny_loopback && policy.deny_private && policy.deny_link_local);
        assert!(parse_policy(["--help".to_owned()]).unwrap().is_none());
        assert!(parse_policy(["--unknown".to_owned()]).is_err());
    }

    #[test]
    fn outbound_drain_is_bounded_and_detects_disconnect() {
        let (sender, mut receiver) = mpsc::channel(OUTBOUND_WRITE_BATCH + 1);
        for value in 0..=OUTBOUND_WRITE_BATCH {
            sender.try_send(vec![value as u8]).unwrap();
        }

        let mut written = Vec::new();
        let state = drain_outbound_batch(&mut receiver, |data| {
            written.push(data[0]);
            Ok(())
        })
        .unwrap();
        assert_eq!(state, OutboundQueueState::Open);
        assert_eq!(written.len(), OUTBOUND_WRITE_BATCH);
        assert_eq!(receiver.len(), 1);

        drop(sender);
        let state = drain_outbound_batch(&mut receiver, |data| {
            written.push(data[0]);
            Ok(())
        })
        .unwrap();
        assert_eq!(state, OutboundQueueState::Closed);
        assert_eq!(written.len(), OUTBOUND_WRITE_BATCH + 1);
    }

    #[test]
    fn full_inbound_queue_fails_without_waiting_for_the_consumer() {
        let (inbound, mut receiver) = mpsc::channel(1);
        forward_inbound(&inbound, b"first".to_vec()).unwrap();
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        let worker_inbound = inbound.clone();
        let worker = std::thread::spawn(move || {
            let result = forward_inbound(&worker_inbound, b"overflow".to_vec());
            let _ = result_tx.send(result.map_err(|error| error.kind()));
        });
        assert_eq!(
            result_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("the WTS actor must not block on a full inbound queue"),
            Err(io::ErrorKind::WouldBlock)
        );
        worker.join().unwrap();
        assert_eq!(receiver.try_recv().unwrap(), b"first");
        assert!(receiver.try_recv().is_err());
        drop(receiver);
        assert_eq!(
            forward_inbound(&inbound, Vec::new()).unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    #[test]
    fn hresult_mapping_uses_captured_win32_code() {
        let timeout = WindowsError::from_hresult(HRESULT::from_win32(ERROR_TIMEOUT.0));
        assert!(is_win32_error(&timeout, ERROR_TIMEOUT));
        assert_eq!(
            windows_error(timeout).raw_os_error(),
            Some(ERROR_TIMEOUT.0 as i32)
        );

        let generic = WindowsError::from_hresult(HRESULT(0x8000_4005_u32 as i32));
        assert_eq!(win32_error_code(&generic), None);
        assert_eq!(windows_error(generic).raw_os_error(), None);
    }

    #[test]
    fn wts_read_poll_tick_accepts_only_no_data_errors() {
        let timeout = WindowsError::from_hresult(HRESULT::from_win32(ERROR_TIMEOUT.0));
        let incomplete = WindowsError::from_hresult(HRESULT::from_win32(ERROR_IO_INCOMPLETE.0));
        let broken_pipe = WindowsError::from_hresult(HRESULT::from_win32(ERROR_BROKEN_PIPE.0));
        let generic = WindowsError::from_hresult(HRESULT(0x8000_4005_u32 as i32));

        assert!(is_wts_read_poll_tick(&timeout));
        assert!(is_wts_read_poll_tick(&incomplete));
        assert!(!is_wts_read_poll_tick(&broken_pipe));
        assert!(!is_wts_read_poll_tick(&generic));
    }
}
