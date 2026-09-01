//! Bounded ALRD session multiplexing shared by the local connector and agent.

use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex, Notify, OwnedSemaphorePermit, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{Instant, MissedTickBehavior};
use tracing::debug;

use super::protocol::{
    self, canonicalize_address, CloseReason, Frame, Hello, NegotiatedLimits, OpenErrorCode, Role,
    CONTROL_QUEUE_CAPACITY, DATA_QUEUE_CAPACITY, MAX_RESOLVE_ADDRESSES,
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(45);
const FRAME_WRITE_TIMEOUT: Duration = Duration::from_secs(45);
const READER_QUEUE_CAPACITY: usize = 256;
const WORKER_QUEUE_CAPACITY: usize = 256;
const SESSION_CONTROL_BURST: usize = 8;

static NEXT_GENERATION_NONCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub(crate) enum MuxError {
    #[error("RDP transport is not connected")]
    Unavailable,
    #[error("RDP transport operation timed out")]
    Timeout,
    #[error("RDP session closed: {0}")]
    SessionClosed(String),
    #[error("RDP protocol error: {0}")]
    Protocol(String),
    #[error("RDP transport I/O error: {0}")]
    Transport(String),
    #[error("RDP stream resource limit reached")]
    ResourceLimit,
    #[error("RDP stream ID space exhausted")]
    StreamIdExhausted,
    #[error("invalid RDP stream state: {0}")]
    InvalidState(&'static str),
    #[error("address {0} was not returned by remote resolution")]
    InvalidCandidate(SocketAddr),
    #[error("remote operation failed ({code:?}): {diagnostic}")]
    Remote {
        code: OpenErrorCode,
        diagnostic: String,
    },
}

impl MuxError {
    pub(crate) fn into_io(self) -> io::Error {
        let kind = match &self {
            Self::Unavailable | Self::SessionClosed(_) => io::ErrorKind::NotConnected,
            Self::Timeout
            | Self::Remote {
                code: OpenErrorCode::Timeout,
                ..
            } => io::ErrorKind::TimedOut,
            Self::ResourceLimit | Self::StreamIdExhausted => io::ErrorKind::OutOfMemory,
            Self::InvalidCandidate(_) | Self::InvalidState(_) | Self::Protocol(_) => {
                io::ErrorKind::InvalidData
            }
            Self::Remote {
                code: OpenErrorCode::ConnectionRefused,
                ..
            } => io::ErrorKind::ConnectionRefused,
            Self::Remote {
                code: OpenErrorCode::HostUnreachable,
                ..
            } => io::ErrorKind::HostUnreachable,
            Self::Remote {
                code: OpenErrorCode::NetworkUnreachable,
                ..
            } => io::ErrorKind::NetworkUnreachable,
            Self::Remote {
                code: OpenErrorCode::PolicyDenied,
                ..
            } => io::ErrorKind::PermissionDenied,
            Self::Remote {
                code: OpenErrorCode::AddressTypeUnsupported,
                ..
            } => io::ErrorKind::Unsupported,
            Self::Remote { .. } | Self::Transport(_) => io::ErrorKind::Other,
        };
        io::Error::new(kind, self)
    }
}

impl From<protocol::FrameIoError> for MuxError {
    fn from(error: protocol::FrameIoError) -> Self {
        match error {
            protocol::FrameIoError::Io(error) => Self::Transport(error.to_string()),
            protocol::FrameIoError::Protocol(error) => Self::Protocol(error.to_string()),
        }
    }
}

fn protocol_error(message: impl Into<String>) -> MuxError {
    MuxError::Protocol(message.into())
}

fn generation_nonce() -> u64 {
    let clock = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    clock
        ^ (u64::from(std::process::id()) << 32)
        ^ NEXT_GENERATION_NONCE.fetch_add(1, Ordering::Relaxed)
}

async fn handshake<T>(io: &mut T, role: Role) -> Result<NegotiatedLimits, MuxError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let local = Hello::new(role, generation_nonce());
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        protocol::write_frame(io, &Frame::Hello(local.clone())).await?;
        io.flush()
            .await
            .map_err(|error| MuxError::Transport(error.to_string()))?;
        let peer = match protocol::read_frame(io).await? {
            Frame::Hello(peer) => peer,
            frame => {
                return Err(protocol_error(format!(
                    "expected HELLO, received {:?}",
                    frame.message_type()
                )))
            }
        };
        local
            .negotiate(&peer)
            .map_err(|error| MuxError::Protocol(error.to_string()))
    })
    .await
    .map_err(|_| MuxError::Timeout)?
}

#[derive(Clone)]
pub(crate) struct ClientHandle {
    inner: Arc<ClientInner>,
}

struct ClientInner {
    commands: mpsc::Sender<ClientCommand>,
    slots: Arc<Semaphore>,
    admission: AsyncMutex<()>,
    next_stream_id: AtomicU32,
}

impl ClientHandle {
    pub(crate) async fn resolve(
        &self,
        hostname: &str,
        port: u16,
        timeout: Duration,
    ) -> Result<ResolvedTarget, MuxError> {
        let validation = Frame::Resolve {
            stream_id: 1,
            port,
            hostname: hostname.to_owned(),
        };
        validation
            .validate()
            .map_err(|error| MuxError::Protocol(error.to_string()))?;
        let deadline = Instant::now() + timeout;
        let permit = tokio::time::timeout_at(deadline, self.inner.slots.clone().acquire_owned())
            .await
            .map_err(|_| MuxError::Timeout)?
            .map_err(|_| MuxError::Unavailable)?;
        let admission = tokio::time::timeout_at(deadline, self.inner.admission.lock())
            .await
            .map_err(|_| MuxError::Timeout)?;
        let stream_id = self.allocate_stream_id()?;
        let hostname = hostname.to_owned();
        let (reply, response) = oneshot::channel();
        tokio::time::timeout_at(
            deadline,
            self.inner.commands.send(ClientCommand::Resolve {
                stream_id,
                hostname,
                port,
                reply,
            }),
        )
        .await
        .map_err(|_| MuxError::Timeout)?
        .map_err(|_| MuxError::Unavailable)?;
        drop(admission);
        match tokio::time::timeout_at(deadline, response).await {
            Ok(Ok(Ok(candidates))) => Ok(ResolvedTarget {
                handle: self.clone(),
                stream_id,
                candidates,
                permit: Some(permit),
                finished: false,
            }),
            Ok(Ok(Err(error))) => Err(error),
            Ok(Err(_)) => Err(MuxError::Unavailable),
            Err(_) => {
                self.close_best_effort(stream_id);
                Err(MuxError::Timeout)
            }
        }
    }

    pub(crate) async fn open_ip(
        &self,
        address: SocketAddr,
        timeout: Duration,
    ) -> Result<RdpStream, MuxError> {
        let address = canonicalize_address(address);
        Frame::Open {
            stream_id: 1,
            address,
        }
        .validate()
        .map_err(|error| MuxError::Protocol(error.to_string()))?;
        let deadline = Instant::now() + timeout;
        let permit = tokio::time::timeout_at(deadline, self.inner.slots.clone().acquire_owned())
            .await
            .map_err(|_| MuxError::Timeout)?
            .map_err(|_| MuxError::Unavailable)?;
        let admission = tokio::time::timeout_at(deadline, self.inner.admission.lock())
            .await
            .map_err(|_| MuxError::Timeout)?;
        let stream_id = self.allocate_stream_id()?;
        let (reply, response) = oneshot::channel();
        tokio::time::timeout_at(
            deadline,
            self.inner.commands.send(ClientCommand::OpenIp {
                stream_id,
                address,
                reply,
            }),
        )
        .await
        .map_err(|_| MuxError::Timeout)?
        .map_err(|_| MuxError::Unavailable)?;
        drop(admission);
        match tokio::time::timeout_at(deadline, response).await {
            Ok(Ok(Ok(mut stream))) => {
                stream.slot = Some(permit);
                Ok(stream)
            }
            Ok(Ok(Err(error))) => Err(error),
            Ok(Err(_)) => Err(MuxError::Unavailable),
            Err(_) => {
                self.close_best_effort(stream_id);
                Err(MuxError::Timeout)
            }
        }
    }

    fn allocate_stream_id(&self) -> Result<u32, MuxError> {
        self.inner
            .next_stream_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(2)
            })
            .map_err(|_| MuxError::StreamIdExhausted)
    }

    fn close_best_effort(&self, stream_id: u32) {
        let command = ClientCommand::Close { stream_id };
        match self.inner.commands.try_send(command) {
            Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                debug!(
                    stream_id,
                    "RDP cancellation queue is full; session cleanup will reclaim it"
                );
            }
        }
    }
}

pub(crate) struct ResolvedTarget {
    handle: ClientHandle,
    stream_id: u32,
    candidates: Vec<SocketAddr>,
    permit: Option<OwnedSemaphorePermit>,
    finished: bool,
}

impl ResolvedTarget {
    pub(crate) fn candidates(&self) -> &[SocketAddr] {
        &self.candidates
    }

    pub(crate) async fn open(
        &mut self,
        address: SocketAddr,
        timeout: Duration,
    ) -> Result<RdpStream, MuxError> {
        if self.finished {
            return Err(MuxError::InvalidState("resolved target was already opened"));
        }
        let address = canonicalize_address(address);
        if !self.candidates.contains(&address) {
            return Err(MuxError::InvalidCandidate(address));
        }
        let (reply, response) = oneshot::channel();
        let operation = async {
            self.handle
                .inner
                .commands
                .send(ClientCommand::Open {
                    stream_id: self.stream_id,
                    address,
                    reply,
                })
                .await
                .map_err(|_| MuxError::Unavailable)?;
            response.await.map_err(|_| MuxError::Unavailable)?
        };
        match tokio::time::timeout(timeout, operation).await {
            Ok(Ok(mut stream)) => {
                stream.slot = self.permit.take();
                self.finished = true;
                Ok(stream)
            }
            Ok(Err(error)) => {
                if !matches!(error, MuxError::Remote { .. }) {
                    self.finished = true;
                }
                Err(error)
            }
            Err(_) => {
                self.handle.close_best_effort(self.stream_id);
                self.finished = true;
                Err(MuxError::Timeout)
            }
        }
    }

    pub(crate) fn can_retry(&self) -> bool {
        !self.finished
    }
}

impl Drop for ResolvedTarget {
    fn drop(&mut self) {
        if !self.finished {
            self.handle.close_best_effort(self.stream_id);
        }
    }
}

enum ClientCommand {
    Resolve {
        stream_id: u32,
        hostname: String,
        port: u16,
        reply: oneshot::Sender<Result<Vec<SocketAddr>, MuxError>>,
    },
    Open {
        stream_id: u32,
        address: SocketAddr,
        reply: oneshot::Sender<Result<RdpStream, MuxError>>,
    },
    OpenIp {
        stream_id: u32,
        address: SocketAddr,
        reply: oneshot::Sender<Result<RdpStream, MuxError>>,
    },
    Close {
        stream_id: u32,
    },
}

struct StreamState {
    inbound: VecDeque<u8>,
    outbound: VecDeque<u8>,
    returned_credit: u32,
    receive_credit: u32,
    inbound_eof: bool,
    write_shutdown: bool,
    shutdown_sent: bool,
    dropped: bool,
    close_queued: bool,
    close_reason: CloseReason,
    remote_closed: bool,
    failure: Option<(io::ErrorKind, String)>,
    pending_outbound: usize,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
    flush_waker: Option<Waker>,
}

struct StreamShared {
    state: Mutex<StreamState>,
    capacity: usize,
    event: Notify,
    credit_event: Notify,
    peer_credit: CreditWindow,
    send_gate: AsyncMutex<()>,
    receive_credit_gate: AsyncMutex<()>,
}

impl StreamShared {
    fn new(window: u32) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(StreamState {
                inbound: VecDeque::with_capacity(window as usize),
                outbound: VecDeque::with_capacity(window as usize),
                returned_credit: 0,
                receive_credit: window,
                inbound_eof: false,
                write_shutdown: false,
                shutdown_sent: false,
                dropped: false,
                close_queued: false,
                close_reason: CloseReason::Normal,
                remote_closed: false,
                failure: None,
                pending_outbound: 0,
                read_waker: None,
                write_waker: None,
                flush_waker: None,
            }),
            capacity: window as usize,
            event: Notify::new(),
            credit_event: Notify::new(),
            peer_credit: CreditWindow::new(window),
            send_gate: AsyncMutex::new(()),
            receive_credit_gate: AsyncMutex::new(()),
        })
    }

    fn push_inbound(&self, payload: &[u8]) -> Result<(), MuxError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| protocol_error("stream buffer lock poisoned"))?;
        if state.inbound_eof || state.remote_closed {
            return Err(protocol_error("DATA arrived after peer write shutdown"));
        }
        if payload.len() > state.receive_credit as usize {
            return Err(protocol_error("peer sent DATA without receive credit"));
        }
        if payload.len() > self.capacity.saturating_sub(state.inbound.len()) {
            return Err(protocol_error(
                "peer exceeded the negotiated receive window",
            ));
        }
        state.receive_credit -= payload.len() as u32;
        state.inbound.extend(payload.iter().copied());
        if let Some(waker) = state.read_waker.take() {
            waker.wake();
        }
        Ok(())
    }

    fn finish_inbound(&self) -> Result<(), MuxError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| protocol_error("stream buffer lock poisoned"))?;
        if state.inbound_eof {
            return Err(protocol_error("duplicate SHUTDOWN_WRITE"));
        }
        state.inbound_eof = true;
        if let Some(waker) = state.read_waker.take() {
            waker.wake();
        }
        Ok(())
    }

    fn remote_close(&self, reason: CloseReason) {
        if let Ok(mut state) = self.state.lock() {
            state.remote_closed = true;
            state.inbound_eof = true;
            if reason != CloseReason::Normal {
                state.failure = Some((
                    io::ErrorKind::ConnectionReset,
                    format!("remote closed RDP stream: {reason:?}"),
                ));
            }
            state.outbound.clear();
            state.pending_outbound = 0;
            wake_all(&mut state);
        }
        self.peer_credit.close();
        self.event.notify_waiters();
        self.credit_event.notify_waiters();
    }

    fn session_failure(&self, error: &MuxError) {
        if let Ok(mut state) = self.state.lock() {
            state.remote_closed = true;
            state.inbound_eof = true;
            state.failure = Some((io::ErrorKind::ConnectionReset, error.to_string()));
            state.outbound.clear();
            state.pending_outbound = 0;
            wake_all(&mut state);
        }
        self.peer_credit.close();
        self.event.notify_waiters();
        self.credit_event.notify_waiters();
    }

    fn drop_local(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.dropped = true;
            state.outbound.clear();
            state.pending_outbound = 0;
            wake_all(&mut state);
        }
        self.peer_credit.close();
        self.event.notify_waiters();
        self.credit_event.notify_waiters();
    }

    fn set_close_reason(&self, reason: CloseReason) {
        if let Ok(mut state) = self.state.lock() {
            if state.close_reason == CloseReason::Normal {
                state.close_reason = reason;
            }
        }
    }

    async fn queue_close_once(
        &self,
        stream_id: u32,
        reason: CloseReason,
        ordered: &mpsc::Sender<Frame>,
    ) -> Result<bool, MuxError> {
        let _gate = self.send_gate.lock().await;
        {
            let mut state = self
                .state
                .lock()
                .map_err(|_| protocol_error("stream buffer lock poisoned"))?;
            if state.close_queued {
                return Ok(false);
            }
            state.close_queued = true;
        }
        ordered
            .send(Frame::Close { stream_id, reason })
            .await
            .map_err(|_| MuxError::Unavailable)?;
        Ok(true)
    }
}

fn wake_all(state: &mut StreamState) {
    if let Some(waker) = state.read_waker.take() {
        waker.wake();
    }
    if let Some(waker) = state.write_waker.take() {
        waker.wake();
    }
    if let Some(waker) = state.flush_waker.take() {
        waker.wake();
    }
}

struct CreditState {
    available: u32,
    closed: bool,
}

struct CreditWindow {
    maximum: u32,
    state: Mutex<CreditState>,
    notify: Notify,
}

impl CreditWindow {
    fn new(maximum: u32) -> Self {
        Self {
            maximum,
            state: Mutex::new(CreditState {
                available: maximum,
                closed: false,
            }),
            notify: Notify::new(),
        }
    }

    fn add(&self, credit: u32) -> Result<(), MuxError> {
        if credit == 0 {
            return Err(protocol_error("zero WINDOW_UPDATE"));
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| protocol_error("credit lock poisoned"))?;
        let Some(updated) = state.available.checked_add(credit) else {
            return Err(protocol_error("WINDOW_UPDATE overflow"));
        };
        if updated > self.maximum {
            return Err(protocol_error("WINDOW_UPDATE exceeds negotiated window"));
        }
        state.available = updated;
        drop(state);
        self.notify.notify_one();
        Ok(())
    }

    async fn take_up_to(&self, maximum: usize) -> Option<usize> {
        loop {
            let notified = self.notify.notified();
            if let Ok(mut state) = self.state.lock() {
                if state.closed {
                    return None;
                }
                if state.available != 0 {
                    let count = state.available.min(maximum as u32);
                    state.available -= count;
                    return Some(count as usize);
                }
            } else {
                return None;
            }
            notified.await;
        }
    }

    fn close(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.closed = true;
        }
        self.notify.notify_waiters();
    }
}

pub(crate) struct RdpStream {
    shared: Arc<StreamShared>,
    stream_id: u32,
    bound_address: SocketAddr,
    slot: Option<OwnedSemaphorePermit>,
}

impl std::fmt::Debug for RdpStream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RdpStream")
            .field("stream_id", &self.stream_id)
            .field("bound_address", &self.bound_address)
            .finish_non_exhaustive()
    }
}

impl RdpStream {
    #[cfg(test)]
    pub(crate) fn stream_id(&self) -> u32 {
        self.stream_id
    }

    pub(crate) fn bound_address(&self) -> SocketAddr {
        self.bound_address
    }

    pub(crate) fn set_close_reason(&self, reason: CloseReason) {
        self.shared.set_close_reason(reason);
    }
}

impl AsyncRead for RdpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut state = match self.shared.state.lock() {
            Ok(state) => state,
            Err(_) => return Poll::Ready(Err(io::Error::other("RDP stream lock poisoned"))),
        };
        if !state.inbound.is_empty() {
            let count = buffer.remaining().min(state.inbound.len());
            {
                let contiguous = state.inbound.make_contiguous();
                buffer.put_slice(&contiguous[..count]);
            }
            state.inbound.drain(..count);
            state.returned_credit += count as u32;
            drop(state);
            self.shared.credit_event.notify_one();
            return Poll::Ready(Ok(()));
        }
        if let Some((kind, message)) = state.failure.clone() {
            return Poll::Ready(Err(io::Error::new(kind, message)));
        }
        if state.inbound_eof || state.remote_closed {
            return Poll::Ready(Ok(()));
        }
        state.read_waker = Some(context.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for RdpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buffer.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut state = match self.shared.state.lock() {
            Ok(state) => state,
            Err(_) => return Poll::Ready(Err(io::Error::other("RDP stream lock poisoned"))),
        };
        if state.remote_closed || state.dropped {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "RDP stream is closed",
            )));
        }
        if state.write_shutdown {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "RDP stream write half is shut down",
            )));
        }
        let available = self.shared.capacity.saturating_sub(state.outbound.len());
        if available == 0 {
            state.write_waker = Some(context.waker().clone());
            return Poll::Pending;
        }
        let count = available.min(buffer.len());
        state.outbound.extend(buffer[..count].iter().copied());
        state.pending_outbound += count;
        drop(state);
        self.shared.event.notify_one();
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = match self.shared.state.lock() {
            Ok(state) => state,
            Err(_) => return Poll::Ready(Err(io::Error::other("RDP stream lock poisoned"))),
        };
        if let Some((kind, message)) = state.failure.clone() {
            return Poll::Ready(Err(io::Error::new(kind, message)));
        }
        if state.remote_closed || state.dropped {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "RDP stream is closed",
            )));
        }
        if state.pending_outbound == 0 {
            return Poll::Ready(Ok(()));
        }
        state.flush_waker = Some(context.waker().clone());
        Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = match self.shared.state.lock() {
            Ok(state) => state,
            Err(_) => return Poll::Ready(Err(io::Error::other("RDP stream lock poisoned"))),
        };
        if let Some((kind, message)) = state.failure.clone() {
            return Poll::Ready(Err(io::Error::new(kind, message)));
        }
        if state.remote_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "RDP stream is closed",
            )));
        }
        state.write_shutdown = true;
        if state.pending_outbound == 0 && state.shutdown_sent {
            return Poll::Ready(Ok(()));
        }
        state.flush_waker = Some(context.waker().clone());
        drop(state);
        self.shared.event.notify_one();
        Poll::Pending
    }
}

impl Drop for RdpStream {
    fn drop(&mut self) {
        self.shared.drop_local();
    }
}

struct StreamRecord {
    shared: Arc<StreamShared>,
}

enum WorkerEvent {
    LocalCloseQueued(u32),
    Stopped(u32),
}

fn spawn_stream(
    stream_id: u32,
    bound_address: SocketAddr,
    limits: NegotiatedLimits,
    ordered: mpsc::Sender<Frame>,
    events: mpsc::Sender<WorkerEvent>,
) -> (RdpStream, StreamRecord) {
    let shared = StreamShared::new(limits.receive_window);
    tokio::spawn(outbound_worker(
        stream_id,
        limits.max_data as usize,
        shared.clone(),
        ordered.clone(),
        events,
    ));
    tokio::spawn(credit_worker(stream_id, shared.clone(), ordered));
    (
        RdpStream {
            shared: shared.clone(),
            stream_id,
            bound_address,
            slot: None,
        },
        StreamRecord { shared },
    )
}

async fn outbound_worker(
    stream_id: u32,
    max_data: usize,
    shared: Arc<StreamShared>,
    ordered: mpsc::Sender<Frame>,
    events: mpsc::Sender<WorkerEvent>,
) {
    let mut local_close_queued = false;
    loop {
        let notified = shared.event.notified();
        let action = {
            let state = match shared.state.lock() {
                Ok(state) => state,
                Err(_) => break,
            };
            if state.remote_closed {
                OutboundAction::Stop
            } else if state.dropped {
                OutboundAction::Close
            } else if !state.outbound.is_empty() {
                OutboundAction::Data(state.outbound.len().min(max_data))
            } else if state.write_shutdown && !state.shutdown_sent {
                OutboundAction::Shutdown
            } else {
                OutboundAction::Wait
            }
        };
        match action {
            OutboundAction::Stop => break,
            OutboundAction::Close => {
                let reason = shared
                    .state
                    .lock()
                    .map(|state| state.close_reason)
                    .unwrap_or(CloseReason::Io);
                if let Ok(queued) = shared.queue_close_once(stream_id, reason, &ordered).await {
                    local_close_queued = queued;
                }
                break;
            }
            OutboundAction::Shutdown => {
                let _gate = shared.send_gate.lock().await;
                let should_send = match shared.state.lock() {
                    Ok(state) => {
                        !state.remote_closed
                            && !state.dropped
                            && state.write_shutdown
                            && !state.shutdown_sent
                    }
                    Err(_) => false,
                };
                if !should_send {
                    continue;
                }
                if ordered
                    .send(Frame::ShutdownWrite { stream_id })
                    .await
                    .is_err()
                {
                    break;
                }
                if let Ok(mut state) = shared.state.lock() {
                    state.shutdown_sent = true;
                    if state.pending_outbound == 0 {
                        if let Some(waker) = state.flush_waker.take() {
                            waker.wake();
                        }
                    }
                }
            }
            OutboundAction::Data(wanted) => {
                let Some(credit) = shared.peer_credit.take_up_to(wanted).await else {
                    break;
                };
                let _gate = shared.send_gate.lock().await;
                let payload = {
                    let mut state = match shared.state.lock() {
                        Ok(state) => state,
                        Err(_) => break,
                    };
                    if state.dropped || state.remote_closed {
                        break;
                    }
                    let count = credit.min(state.outbound.len());
                    let payload: Vec<u8> = state.outbound.drain(..count).collect();
                    if let Some(waker) = state.write_waker.take() {
                        waker.wake();
                    }
                    payload
                };
                if payload.is_empty() {
                    continue;
                }
                let count = payload.len();
                if ordered
                    .send(Frame::Data { stream_id, payload })
                    .await
                    .is_err()
                {
                    break;
                }
                if let Ok(mut state) = shared.state.lock() {
                    state.pending_outbound = state.pending_outbound.saturating_sub(count);
                    if state.pending_outbound == 0 {
                        if let Some(waker) = state.flush_waker.take() {
                            waker.wake();
                        }
                    }
                }
            }
            OutboundAction::Wait => notified.await,
        }
    }
    let event = if local_close_queued {
        WorkerEvent::LocalCloseQueued(stream_id)
    } else {
        WorkerEvent::Stopped(stream_id)
    };
    let _ = events.send(event).await;
}

enum OutboundAction {
    Data(usize),
    Shutdown,
    Close,
    Wait,
    Stop,
}

async fn credit_worker(stream_id: u32, shared: Arc<StreamShared>, ordered: mpsc::Sender<Frame>) {
    loop {
        let notified = shared.credit_event.notified();
        let _gate = shared.send_gate.lock().await;
        // Keep inbound DATA handling behind this gate until the corresponding
        // WINDOW_UPDATE is committed to the ordered writer queue and the local
        // advertised-credit counter is updated. This closes both possible
        // races: accepting bytes before advertising them, and rejecting bytes
        // that arrive immediately after the peer observes the update.
        let _receive_credit_gate = shared.receive_credit_gate.lock().await;
        let credit = match shared.state.lock() {
            Ok(mut state) => {
                if state.dropped || state.remote_closed {
                    return;
                }
                std::mem::take(&mut state.returned_credit)
            }
            Err(_) => return,
        };
        if credit != 0 {
            if ordered
                .send(Frame::WindowUpdate { stream_id, credit })
                .await
                .is_err()
            {
                return;
            }
            let mut state = match shared.state.lock() {
                Ok(state) => state,
                Err(_) => return,
            };
            let Some(updated) = state.receive_credit.checked_add(credit) else {
                return;
            };
            if updated > shared.capacity as u32 {
                return;
            }
            state.receive_credit = updated;
        }
        drop(_receive_credit_gate);
        drop(_gate);
        if credit == 0 {
            notified.await;
        }
    }
}

async fn frame_reader<R>(mut reader: R, frames: mpsc::Sender<Frame>) -> Result<(), MuxError>
where
    R: AsyncRead + Unpin,
{
    loop {
        let frame = protocol::read_frame(&mut reader).await?;
        frames
            .send(frame)
            .await
            .map_err(|_| MuxError::SessionClosed("session driver stopped".into()))?;
    }
}

async fn frame_writer<W>(
    mut writer: W,
    mut control: mpsc::Receiver<Frame>,
    mut ordered: mpsc::Receiver<Frame>,
) -> Result<(), MuxError>
where
    W: AsyncWrite + Unpin,
{
    enum Source {
        Control,
        Ordered,
    }

    let mut control_open = true;
    let mut ordered_open = true;
    let mut control_burst = 0usize;
    while control_open || ordered_open {
        let mut selected = None;
        if control_open && (control_burst < SESSION_CONTROL_BURST || !ordered_open) {
            match control.try_recv() {
                Ok(frame) => selected = Some((Some(frame), Source::Control)),
                Err(mpsc::error::TryRecvError::Disconnected) => control_open = false,
                Err(mpsc::error::TryRecvError::Empty) => {}
            }
        }
        if selected.is_none() && ordered_open {
            match ordered.try_recv() {
                Ok(frame) => selected = Some((Some(frame), Source::Ordered)),
                Err(mpsc::error::TryRecvError::Disconnected) => ordered_open = false,
                Err(mpsc::error::TryRecvError::Empty) => {}
            }
        }
        if selected.is_none() && control_open {
            match control.try_recv() {
                Ok(frame) => selected = Some((Some(frame), Source::Control)),
                Err(mpsc::error::TryRecvError::Disconnected) => control_open = false,
                Err(mpsc::error::TryRecvError::Empty) => {}
            }
        }
        if selected.is_none() {
            selected = match (control_open, ordered_open) {
                (true, true) if control_burst >= SESSION_CONTROL_BURST => Some(tokio::select! {
                    biased;
                    frame = ordered.recv() => (frame, Source::Ordered),
                    frame = control.recv() => (frame, Source::Control),
                }),
                (true, true) => Some(tokio::select! {
                    biased;
                    frame = control.recv() => (frame, Source::Control),
                    frame = ordered.recv() => (frame, Source::Ordered),
                }),
                (true, false) => Some((control.recv().await, Source::Control)),
                (false, true) => Some((ordered.recv().await, Source::Ordered)),
                (false, false) => None,
            };
        }
        let Some((frame, source)) = selected else {
            break;
        };
        let Some(frame) = frame else {
            match source {
                Source::Control => control_open = false,
                Source::Ordered => ordered_open = false,
            }
            continue;
        };
        match source {
            Source::Control => control_burst = control_burst.saturating_add(1),
            Source::Ordered => control_burst = 0,
        }
        tokio::time::timeout(
            FRAME_WRITE_TIMEOUT,
            protocol::write_frame(&mut writer, &frame),
        )
        .await
        .map_err(|_| MuxError::Timeout)??;
    }
    tokio::time::timeout(FRAME_WRITE_TIMEOUT, writer.shutdown())
        .await
        .map_err(|_| MuxError::Timeout)?
        .map_err(|error| MuxError::Transport(error.to_string()))?;
    Ok(())
}

pub(crate) async fn start_client_session<T>(
    mut io: T,
) -> Result<(ClientHandle, JoinHandle<Result<(), MuxError>>), MuxError>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let limits = handshake(&mut io, Role::Local).await?;
    let (reader, writer) = tokio::io::split(io);
    let (commands_tx, commands_rx) = mpsc::channel(CONTROL_QUEUE_CAPACITY);
    let (control_tx, control_rx) = mpsc::channel(CONTROL_QUEUE_CAPACITY);
    let (ordered_tx, ordered_rx) = mpsc::channel(DATA_QUEUE_CAPACITY);
    let (frames_tx, frames_rx) = mpsc::channel(READER_QUEUE_CAPACITY);
    let (events_tx, events_rx) = mpsc::channel(WORKER_QUEUE_CAPACITY);
    let reader_task = tokio::spawn(frame_reader(reader, frames_tx));
    let writer_task = tokio::spawn(frame_writer(writer, control_rx, ordered_rx));
    let task = tokio::spawn(drive_client(
        limits,
        commands_rx,
        control_tx,
        ordered_tx,
        frames_rx,
        events_tx,
        events_rx,
        reader_task,
        writer_task,
    ));
    let handle = ClientHandle {
        inner: Arc::new(ClientInner {
            commands: commands_tx,
            slots: Arc::new(Semaphore::new(limits.max_streams as usize)),
            admission: AsyncMutex::new(()),
            next_stream_id: AtomicU32::new(1),
        }),
    };
    Ok((handle, task))
}

enum ClientStreamState {
    Resolving {
        port: u16,
        reply: oneshot::Sender<Result<Vec<SocketAddr>, MuxError>>,
    },
    Resolved(Vec<SocketAddr>),
    Opening {
        candidates: Option<Vec<SocketAddr>>,
        reply: oneshot::Sender<Result<RdpStream, MuxError>>,
    },
    Open(StreamRecord),
    Closing,
}

#[allow(clippy::too_many_arguments)]
async fn drive_client(
    limits: NegotiatedLimits,
    mut commands: mpsc::Receiver<ClientCommand>,
    control: mpsc::Sender<Frame>,
    ordered: mpsc::Sender<Frame>,
    mut frames: mpsc::Receiver<Frame>,
    events_tx: mpsc::Sender<WorkerEvent>,
    mut events: mpsc::Receiver<WorkerEvent>,
    mut reader_task: JoinHandle<Result<(), MuxError>>,
    mut writer_task: JoinHandle<Result<(), MuxError>>,
) -> Result<(), MuxError> {
    let mut streams = BTreeMap::<u32, ClientStreamState>::new();
    let mut keepalive = tokio::time::interval(KEEPALIVE_INTERVAL);
    keepalive.set_missed_tick_behavior(MissedTickBehavior::Delay);
    keepalive.tick().await;
    let mut ping = None::<(u64, Instant)>;
    let result = loop {
        tokio::select! {
            biased;
            result = &mut reader_task => break join_result("reader", result),
            result = &mut writer_task => break join_result("writer", result),
            _ = keepalive.tick() => {
                if let Some((_, sent)) = ping {
                    if sent.elapsed() >= KEEPALIVE_TIMEOUT {
                        break Err(MuxError::Timeout);
                    }
                } else {
                    let nonce = generation_nonce();
                    control.send(Frame::Ping { nonce }).await
                        .map_err(|_| MuxError::Unavailable)?;
                    ping = Some((nonce, Instant::now()));
                }
            }
            Some(event) = events.recv() => handle_client_worker_event(event, &mut streams),
            Some(command) = commands.recv() => {
                if let Err(error) = handle_client_command(
                    command,
                    limits,
                    &mut streams,
                    &ordered,
                ).await {
                    break Err(error);
                }
            }
            Some(frame) = frames.recv() => {
                if let Err(error) = handle_client_frame(
                    frame,
                    limits,
                    &mut streams,
                    &control,
                    &ordered,
                    &events_tx,
                    &mut ping,
                ).await {
                    break Err(error);
                }
            }
            else => break Err(MuxError::SessionClosed("all session channels closed".into())),
        }
    };

    reader_task.abort();
    writer_task.abort();
    let failure = result
        .as_ref()
        .err()
        .cloned()
        .unwrap_or_else(|| MuxError::SessionClosed("RDP session ended".into()));
    fail_client_streams(streams, &failure);
    result
}

fn join_result(
    component: &'static str,
    result: Result<Result<(), MuxError>, tokio::task::JoinError>,
) -> Result<(), MuxError> {
    match result {
        Ok(result) => result,
        Err(error) => Err(MuxError::SessionClosed(format!(
            "{component} task failed: {error}"
        ))),
    }
}

async fn handle_client_command(
    command: ClientCommand,
    limits: NegotiatedLimits,
    streams: &mut BTreeMap<u32, ClientStreamState>,
    ordered: &mpsc::Sender<Frame>,
) -> Result<(), MuxError> {
    match command {
        ClientCommand::Resolve {
            stream_id,
            hostname,
            port,
            reply,
        } => {
            validate_local_stream_id(stream_id)?;
            if streams.len() >= limits.max_streams as usize {
                let _ = reply.send(Err(MuxError::ResourceLimit));
                return Ok(());
            }
            if streams.contains_key(&stream_id) {
                return Err(protocol_error("duplicate local stream ID"));
            }
            let frame = Frame::Resolve {
                stream_id,
                port,
                hostname,
            };
            frame
                .validate()
                .map_err(|error| MuxError::Protocol(error.to_string()))?;
            streams.insert(stream_id, ClientStreamState::Resolving { port, reply });
            if ordered.send(frame).await.is_err() {
                return Err(MuxError::Unavailable);
            }
        }
        ClientCommand::Open {
            stream_id,
            address,
            reply,
        } => {
            let Some(state) = streams.remove(&stream_id) else {
                let _ = reply.send(Err(MuxError::InvalidState("OPEN without RESOLVE")));
                return Ok(());
            };
            let ClientStreamState::Resolved(candidates) = state else {
                streams.insert(stream_id, state);
                let _ = reply.send(Err(MuxError::InvalidState("stream is not resolved")));
                return Ok(());
            };
            if !candidates.contains(&address) {
                streams.insert(stream_id, ClientStreamState::Resolved(candidates));
                let _ = reply.send(Err(MuxError::InvalidCandidate(address)));
                return Ok(());
            }
            streams.insert(
                stream_id,
                ClientStreamState::Opening {
                    candidates: Some(candidates),
                    reply,
                },
            );
            ordered
                .send(Frame::Open { stream_id, address })
                .await
                .map_err(|_| MuxError::Unavailable)?;
        }
        ClientCommand::OpenIp {
            stream_id,
            address,
            reply,
        } => {
            validate_local_stream_id(stream_id)?;
            if streams.len() >= limits.max_streams as usize {
                let _ = reply.send(Err(MuxError::ResourceLimit));
                return Ok(());
            }
            if streams.contains_key(&stream_id) {
                return Err(protocol_error("duplicate local stream ID"));
            }
            streams.insert(
                stream_id,
                ClientStreamState::Opening {
                    candidates: None,
                    reply,
                },
            );
            ordered
                .send(Frame::Open { stream_id, address })
                .await
                .map_err(|_| MuxError::Unavailable)?;
        }
        ClientCommand::Close { stream_id } => {
            if let Some(state) = streams.remove(&stream_id) {
                fail_client_state(state, MuxError::SessionClosed("operation cancelled".into()));
                streams.insert(stream_id, ClientStreamState::Closing);
                ordered
                    .send(Frame::Close {
                        stream_id,
                        reason: CloseReason::Cancelled,
                    })
                    .await
                    .map_err(|_| MuxError::Unavailable)?;
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_client_frame(
    frame: Frame,
    limits: NegotiatedLimits,
    streams: &mut BTreeMap<u32, ClientStreamState>,
    control: &mpsc::Sender<Frame>,
    ordered: &mpsc::Sender<Frame>,
    events: &mpsc::Sender<WorkerEvent>,
    ping: &mut Option<(u64, Instant)>,
) -> Result<(), MuxError> {
    match frame {
        Frame::ResolveOk {
            stream_id,
            addresses,
        } => {
            let (expected_port, reply) = match streams.remove(&stream_id) {
                Some(ClientStreamState::Resolving { port, reply }) => (port, reply),
                Some(ClientStreamState::Closing) => {
                    streams.insert(stream_id, ClientStreamState::Closing);
                    return Ok(());
                }
                Some(state) => {
                    streams.insert(stream_id, state);
                    return Err(protocol_error("RESOLVE_OK in the wrong stream state"));
                }
                None => return Err(protocol_error("RESOLVE_OK for an unknown stream")),
            };
            if addresses
                .iter()
                .any(|address| address.port() != expected_port)
            {
                let error =
                    protocol_error("RESOLVE_OK returned an address with an unexpected port");
                let _ = reply.send(Err(error.clone()));
                return Err(error);
            }
            if addresses.is_empty() {
                let _ = reply.send(Err(MuxError::Remote {
                    code: OpenErrorCode::HostUnreachable,
                    diagnostic: "remote resolution returned no addresses".into(),
                }));
            } else {
                streams.insert(stream_id, ClientStreamState::Resolved(addresses.clone()));
                if reply.send(Ok(addresses)).is_err() {
                    streams.remove(&stream_id);
                    streams.insert(stream_id, ClientStreamState::Closing);
                    ordered
                        .send(Frame::Close {
                            stream_id,
                            reason: CloseReason::Cancelled,
                        })
                        .await
                        .map_err(|_| MuxError::Unavailable)?;
                }
            }
        }
        Frame::OpenOk {
            stream_id,
            bound_address,
        } => {
            let reply = match streams.remove(&stream_id) {
                Some(ClientStreamState::Opening { reply, .. }) => reply,
                Some(ClientStreamState::Closing) => {
                    streams.insert(stream_id, ClientStreamState::Closing);
                    return Ok(());
                }
                Some(state) => {
                    streams.insert(stream_id, state);
                    return Err(protocol_error("OPEN_OK in the wrong stream state"));
                }
                None => return Err(protocol_error("OPEN_OK for an unknown stream")),
            };
            let (stream, record) = spawn_stream(
                stream_id,
                bound_address,
                limits,
                ordered.clone(),
                events.clone(),
            );
            streams.insert(stream_id, ClientStreamState::Open(record));
            if let Err(stream) = reply.send(Ok(stream)) {
                drop(stream);
            }
        }
        Frame::OpenError {
            stream_id,
            code,
            diagnostic,
        } => {
            let Some(state) = streams.remove(&stream_id) else {
                return Err(protocol_error("OPEN_ERROR for an unknown stream"));
            };
            let error = MuxError::Remote { code, diagnostic };
            match state {
                ClientStreamState::Resolving { reply, .. } => {
                    let _ = reply.send(Err(error));
                }
                ClientStreamState::Opening { candidates, reply } => {
                    let _ = reply.send(Err(error));
                    if let Some(candidates) = candidates {
                        streams.insert(stream_id, ClientStreamState::Resolved(candidates));
                    }
                }
                ClientStreamState::Closing => {
                    streams.insert(stream_id, ClientStreamState::Closing);
                }
                other => {
                    streams.insert(stream_id, other);
                    return Err(protocol_error("OPEN_ERROR in the wrong stream state"));
                }
            }
        }
        Frame::Data { stream_id, payload } => {
            if payload.len() > limits.max_data as usize {
                return Err(protocol_error("DATA exceeds negotiated max_data"));
            }
            match streams.get(&stream_id) {
                Some(ClientStreamState::Open(record)) => {
                    let _gate = record.shared.receive_credit_gate.lock().await;
                    record.shared.push_inbound(&payload)?;
                }
                Some(ClientStreamState::Closing) => {}
                Some(_) => return Err(protocol_error("DATA arrived before OPEN_OK")),
                None => return Err(protocol_error("DATA used an unknown stream ID")),
            }
        }
        Frame::ShutdownWrite { stream_id } => match streams.get(&stream_id) {
            Some(ClientStreamState::Open(record)) => record.shared.finish_inbound()?,
            Some(ClientStreamState::Closing) => {}
            Some(_) => return Err(protocol_error("SHUTDOWN_WRITE arrived before OPEN_OK")),
            None => return Err(protocol_error("SHUTDOWN_WRITE used an unknown stream ID")),
        },
        Frame::WindowUpdate { stream_id, credit } => match streams.get(&stream_id) {
            Some(ClientStreamState::Open(record)) => record.shared.peer_credit.add(credit)?,
            Some(ClientStreamState::Closing) => {}
            Some(_) => return Err(protocol_error("WINDOW_UPDATE arrived before OPEN_OK")),
            None => return Err(protocol_error("WINDOW_UPDATE used an unknown stream ID")),
        },
        Frame::Close { stream_id, reason } => {
            let Some(state) = streams.remove(&stream_id) else {
                return Err(protocol_error("CLOSE for an unknown stream"));
            };
            match state {
                ClientStreamState::Closing => {}
                ClientStreamState::Open(record) => {
                    record.shared.remote_close(reason);
                    record
                        .shared
                        .queue_close_once(stream_id, CloseReason::Normal, ordered)
                        .await?;
                }
                state => {
                    fail_client_state(
                        state,
                        MuxError::SessionClosed(format!("remote closed stream: {reason:?}")),
                    );
                    ordered
                        .send(Frame::Close {
                            stream_id,
                            reason: CloseReason::Normal,
                        })
                        .await
                        .map_err(|_| MuxError::Unavailable)?;
                }
            }
        }
        Frame::Ping { nonce } => {
            control
                .send(Frame::Pong { nonce })
                .await
                .map_err(|_| MuxError::Unavailable)?;
        }
        Frame::Pong { nonce } => match *ping {
            Some((expected, _)) if expected == nonce => *ping = None,
            _ => return Err(protocol_error("unexpected PONG nonce")),
        },
        Frame::Hello(_) | Frame::Resolve { .. } | Frame::Open { .. } => {
            return Err(protocol_error("unexpected peer message for local role"))
        }
    }
    Ok(())
}

fn handle_client_worker_event(event: WorkerEvent, streams: &mut BTreeMap<u32, ClientStreamState>) {
    match event {
        WorkerEvent::LocalCloseQueued(stream_id) => {
            if matches!(streams.get(&stream_id), Some(ClientStreamState::Open(_))) {
                streams.insert(stream_id, ClientStreamState::Closing);
            }
        }
        WorkerEvent::Stopped(stream_id) => {
            streams.remove(&stream_id);
        }
    }
}

fn validate_local_stream_id(stream_id: u32) -> Result<(), MuxError> {
    if stream_id == 0 || stream_id.is_multiple_of(2) {
        Err(protocol_error("local stream IDs must be nonzero and odd"))
    } else {
        Ok(())
    }
}

fn fail_client_streams(streams: BTreeMap<u32, ClientStreamState>, error: &MuxError) {
    for (_, state) in streams {
        fail_client_state(state, error.clone());
    }
}

fn fail_client_state(state: ClientStreamState, error: MuxError) {
    match state {
        ClientStreamState::Resolving { reply, .. } => {
            let _ = reply.send(Err(error));
        }
        ClientStreamState::Opening { reply, .. } => {
            let _ = reply.send(Err(error));
        }
        ClientStreamState::Open(record) => record.shared.session_failure(&error),
        ClientStreamState::Resolved(_) | ClientStreamState::Closing => {}
    }
}

/// Defence-in-depth restrictions enforced by the remote agent. They default to
/// permissive because Alighieri's local DNS policy and ACL remain authoritative.
#[derive(Debug, Clone)]
pub(crate) struct AgentPolicy {
    pub(crate) deny_loopback: bool,
    pub(crate) deny_private: bool,
    pub(crate) deny_link_local: bool,
    pub(crate) resolve_timeout: Duration,
    pub(crate) connect_timeout: Duration,
}

impl Default for AgentPolicy {
    fn default() -> Self {
        Self {
            deny_loopback: false,
            deny_private: false,
            deny_link_local: false,
            resolve_timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(30),
        }
    }
}

enum AgentStreamState {
    Resolving,
    Resolved(Vec<SocketAddr>),
    Opening { candidates: Option<Vec<SocketAddr>> },
    Open(StreamRecord),
    Cancelled,
    Closing,
}

enum AgentOperation {
    Resolved {
        stream_id: u32,
        result: io::Result<Vec<SocketAddr>>,
    },
    Opened {
        stream_id: u32,
        result: io::Result<TcpStream>,
    },
}

pub(crate) async fn run_agent_session<T>(mut io: T, policy: AgentPolicy) -> Result<(), MuxError>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let limits = handshake(&mut io, Role::Agent).await?;
    let (reader, writer) = tokio::io::split(io);
    let (control_tx, control_rx) = mpsc::channel(CONTROL_QUEUE_CAPACITY);
    let (ordered_tx, ordered_rx) = mpsc::channel(DATA_QUEUE_CAPACITY);
    let (frames_tx, frames_rx) = mpsc::channel(READER_QUEUE_CAPACITY);
    let (events_tx, events_rx) = mpsc::channel(WORKER_QUEUE_CAPACITY);
    let reader_task = tokio::spawn(frame_reader(reader, frames_tx));
    let writer_task = tokio::spawn(frame_writer(writer, control_rx, ordered_rx));
    drive_agent(
        limits,
        policy,
        control_tx,
        ordered_tx,
        frames_rx,
        events_tx,
        events_rx,
        reader_task,
        writer_task,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn drive_agent(
    limits: NegotiatedLimits,
    policy: AgentPolicy,
    control: mpsc::Sender<Frame>,
    ordered: mpsc::Sender<Frame>,
    mut frames: mpsc::Receiver<Frame>,
    events_tx: mpsc::Sender<WorkerEvent>,
    mut events: mpsc::Receiver<WorkerEvent>,
    mut reader_task: JoinHandle<Result<(), MuxError>>,
    mut writer_task: JoinHandle<Result<(), MuxError>>,
) -> Result<(), MuxError> {
    let mut streams = BTreeMap::<u32, AgentStreamState>::new();
    let mut operations = JoinSet::<AgentOperation>::new();
    let mut relays = JoinSet::<()>::new();
    let mut keepalive = tokio::time::interval(KEEPALIVE_INTERVAL);
    keepalive.set_missed_tick_behavior(MissedTickBehavior::Delay);
    keepalive.tick().await;
    let mut ping = None::<(u64, Instant)>;
    let mut highest_stream_id = 0u32;

    let result = loop {
        tokio::select! {
            biased;
            result = &mut reader_task => break join_result("reader", result),
            result = &mut writer_task => break join_result("writer", result),
            _ = keepalive.tick() => {
                if let Some((_, sent)) = ping {
                    if sent.elapsed() >= KEEPALIVE_TIMEOUT {
                        break Err(MuxError::Timeout);
                    }
                } else {
                    let nonce = generation_nonce();
                    control.send(Frame::Ping { nonce }).await
                        .map_err(|_| MuxError::Unavailable)?;
                    ping = Some((nonce, Instant::now()));
                }
            }
            Some(event) = events.recv() => handle_agent_worker_event(event, &mut streams),
            operation = operations.join_next(), if !operations.is_empty() => {
                match operation {
                    Some(Ok(operation)) => {
                        if let Err(error) = finish_agent_operation(
                            operation,
                            limits,
                            &mut streams,
                            &ordered,
                            &events_tx,
                            &mut relays,
                        ).await {
                            break Err(error);
                        }
                    }
                    Some(Err(error)) => break Err(MuxError::SessionClosed(format!(
                        "agent operation task failed: {error}"
                    ))),
                    None => {}
                }
            }
            relay = relays.join_next(), if !relays.is_empty() => {
                if let Some(Err(error)) = relay {
                    if error.is_panic() {
                        break Err(MuxError::SessionClosed(format!("relay task panicked: {error}")));
                    }
                }
            }
            Some(frame) = frames.recv() => {
                if let Err(error) = handle_agent_frame(
                    frame,
                    limits,
                    &policy,
                    &mut streams,
                    &control,
                    &ordered,
                    &mut operations,
                    &mut ping,
                    &mut highest_stream_id,
                ).await {
                    break Err(error);
                }
            }
            else => break Err(MuxError::SessionClosed("agent session channels closed".into())),
        }
    };

    reader_task.abort();
    writer_task.abort();
    operations.abort_all();
    relays.abort_all();
    let failure = result
        .as_ref()
        .err()
        .cloned()
        .unwrap_or_else(|| MuxError::SessionClosed("RDP session ended".into()));
    for (_, state) in streams {
        if let AgentStreamState::Open(record) = state {
            record.shared.session_failure(&failure);
        }
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn handle_agent_frame(
    frame: Frame,
    limits: NegotiatedLimits,
    policy: &AgentPolicy,
    streams: &mut BTreeMap<u32, AgentStreamState>,
    control: &mpsc::Sender<Frame>,
    ordered: &mpsc::Sender<Frame>,
    operations: &mut JoinSet<AgentOperation>,
    ping: &mut Option<(u64, Instant)>,
    highest_stream_id: &mut u32,
) -> Result<(), MuxError> {
    match frame {
        Frame::Resolve {
            stream_id,
            port,
            hostname,
        } => {
            validate_local_stream_id(stream_id)?;
            if streams.contains_key(&stream_id) {
                return Err(protocol_error("duplicate peer stream ID"));
            }
            register_peer_stream_id(stream_id, highest_stream_id)?;
            if streams.len() >= limits.max_streams as usize
                || operations.len() >= limits.max_streams as usize
            {
                send_open_error(
                    ordered,
                    stream_id,
                    OpenErrorCode::ResourceLimit,
                    "agent stream limit reached",
                )
                .await?;
                return Ok(());
            }
            streams.insert(stream_id, AgentStreamState::Resolving);
            let timeout = policy.resolve_timeout;
            let policy = policy.clone();
            operations.spawn(async move {
                let result = resolve_remote(hostname, port, timeout, &policy).await;
                AgentOperation::Resolved { stream_id, result }
            });
        }
        Frame::Open { stream_id, address } => {
            validate_local_stream_id(stream_id)?;
            let address = canonicalize_address(address);
            let candidates = match streams.remove(&stream_id) {
                Some(AgentStreamState::Resolved(candidates)) => {
                    if !candidates.contains(&address) {
                        streams.insert(stream_id, AgentStreamState::Resolved(candidates));
                        send_open_error(
                            ordered,
                            stream_id,
                            OpenErrorCode::PolicyDenied,
                            "OPEN address was not in RESOLVE_OK",
                        )
                        .await?;
                        return Ok(());
                    }
                    Some(candidates)
                }
                None => {
                    register_peer_stream_id(stream_id, highest_stream_id)?;
                    if streams.len() >= limits.max_streams as usize {
                        send_open_error(
                            ordered,
                            stream_id,
                            OpenErrorCode::ResourceLimit,
                            "agent stream limit reached",
                        )
                        .await?;
                        return Ok(());
                    }
                    None
                }
                Some(state) => {
                    streams.insert(stream_id, state);
                    return Err(protocol_error("OPEN in the wrong stream state"));
                }
            };
            if !agent_address_allowed(address.ip(), policy) {
                if let Some(candidates) = candidates {
                    streams.insert(stream_id, AgentStreamState::Resolved(candidates));
                }
                send_open_error(
                    ordered,
                    stream_id,
                    OpenErrorCode::PolicyDenied,
                    "address denied by remote agent policy",
                )
                .await?;
                return Ok(());
            }
            streams.insert(stream_id, AgentStreamState::Opening { candidates });
            let timeout = policy.connect_timeout;
            operations.spawn(async move {
                let result = match tokio::time::timeout(timeout, TcpStream::connect(address)).await
                {
                    Ok(result) => result,
                    Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "connect timed out")),
                };
                AgentOperation::Opened { stream_id, result }
            });
        }
        Frame::Data { stream_id, payload } => {
            if payload.len() > limits.max_data as usize {
                return Err(protocol_error("DATA exceeds negotiated max_data"));
            }
            match streams.get(&stream_id) {
                Some(AgentStreamState::Open(record)) => {
                    let _gate = record.shared.receive_credit_gate.lock().await;
                    record.shared.push_inbound(&payload)?;
                }
                Some(AgentStreamState::Closing) => {}
                Some(_) => return Err(protocol_error("DATA arrived before OPEN_OK")),
                None => return Err(protocol_error("DATA used an unknown stream ID")),
            }
        }
        Frame::ShutdownWrite { stream_id } => match streams.get(&stream_id) {
            Some(AgentStreamState::Open(record)) => record.shared.finish_inbound()?,
            Some(AgentStreamState::Closing) => {}
            Some(_) => return Err(protocol_error("SHUTDOWN_WRITE arrived before OPEN_OK")),
            None => return Err(protocol_error("SHUTDOWN_WRITE used an unknown stream ID")),
        },
        Frame::WindowUpdate { stream_id, credit } => match streams.get(&stream_id) {
            Some(AgentStreamState::Open(record)) => record.shared.peer_credit.add(credit)?,
            Some(AgentStreamState::Closing) => {}
            Some(_) => return Err(protocol_error("WINDOW_UPDATE arrived before OPEN_OK")),
            None => return Err(protocol_error("WINDOW_UPDATE used an unknown stream ID")),
        },
        Frame::Close { stream_id, reason } => {
            validate_local_stream_id(stream_id)?;
            let Some(state) = streams.remove(&stream_id) else {
                if stream_id <= *highest_stream_id {
                    // A local timeout can race a terminal OPEN_ERROR: the
                    // agent may have already removed the operation when the
                    // queued CLOSE arrives. Acknowledge the stale close so the
                    // client can retire its Closing tombstone.
                    ordered
                        .send(Frame::Close {
                            stream_id,
                            reason: CloseReason::Normal,
                        })
                        .await
                        .map_err(|_| MuxError::Unavailable)?;
                    return Ok(());
                }
                return Err(protocol_error("CLOSE for an unknown stream"));
            };
            match state {
                AgentStreamState::Closing => {}
                AgentStreamState::Open(record) => {
                    record.shared.remote_close(reason);
                    record
                        .shared
                        .queue_close_once(stream_id, CloseReason::Normal, ordered)
                        .await?;
                }
                AgentStreamState::Resolving | AgentStreamState::Opening { .. } => {
                    streams.insert(stream_id, AgentStreamState::Cancelled);
                    ordered
                        .send(Frame::Close {
                            stream_id,
                            reason: CloseReason::Normal,
                        })
                        .await
                        .map_err(|_| MuxError::Unavailable)?;
                }
                AgentStreamState::Resolved(_) => {
                    ordered
                        .send(Frame::Close {
                            stream_id,
                            reason: CloseReason::Normal,
                        })
                        .await
                        .map_err(|_| MuxError::Unavailable)?;
                }
                AgentStreamState::Cancelled => {}
            }
        }
        Frame::Ping { nonce } => {
            control
                .send(Frame::Pong { nonce })
                .await
                .map_err(|_| MuxError::Unavailable)?;
        }
        Frame::Pong { nonce } => match *ping {
            Some((expected, _)) if expected == nonce => *ping = None,
            _ => return Err(protocol_error("unexpected PONG nonce")),
        },
        Frame::Hello(_)
        | Frame::ResolveOk { .. }
        | Frame::OpenOk { .. }
        | Frame::OpenError { .. } => {
            return Err(protocol_error("unexpected peer message for agent role"));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn finish_agent_operation(
    operation: AgentOperation,
    limits: NegotiatedLimits,
    streams: &mut BTreeMap<u32, AgentStreamState>,
    ordered: &mpsc::Sender<Frame>,
    events: &mpsc::Sender<WorkerEvent>,
    relays: &mut JoinSet<()>,
) -> Result<(), MuxError> {
    match operation {
        AgentOperation::Resolved { stream_id, result } => {
            let Some(state) = streams.remove(&stream_id) else {
                return Ok(());
            };
            if matches!(state, AgentStreamState::Cancelled) {
                return Ok(());
            }
            if !matches!(state, AgentStreamState::Resolving) {
                return Err(protocol_error("resolution completed in the wrong state"));
            }
            match result {
                Ok(addresses) if !addresses.is_empty() => {
                    ordered
                        .send(Frame::ResolveOk {
                            stream_id,
                            addresses: addresses.clone(),
                        })
                        .await
                        .map_err(|_| MuxError::Unavailable)?;
                    streams.insert(stream_id, AgentStreamState::Resolved(addresses));
                }
                Ok(_) => {
                    send_open_error(
                        ordered,
                        stream_id,
                        OpenErrorCode::HostUnreachable,
                        "remote resolution returned no addresses",
                    )
                    .await?;
                }
                Err(error) => {
                    send_open_error(
                        ordered,
                        stream_id,
                        open_error_code(&error),
                        &error.to_string(),
                    )
                    .await?;
                }
            }
        }
        AgentOperation::Opened { stream_id, result } => {
            let Some(state) = streams.remove(&stream_id) else {
                return Ok(());
            };
            if matches!(state, AgentStreamState::Cancelled) {
                return Ok(());
            }
            let AgentStreamState::Opening { candidates } = state else {
                return Err(protocol_error("connect completed in the wrong state"));
            };
            match result {
                Ok(socket) => {
                    let bound_address = match socket.local_addr() {
                        Ok(address) => canonicalize_address(address),
                        Err(error) => {
                            send_open_error(
                                ordered,
                                stream_id,
                                OpenErrorCode::General,
                                &format!("query remote bound address: {error}"),
                            )
                            .await?;
                            return Ok(());
                        }
                    };
                    if let Err(error) = socket.set_nodelay(true) {
                        debug!(%error, %stream_id, "failed to set TCP_NODELAY on RDP agent socket");
                    }
                    ordered
                        .send(Frame::OpenOk {
                            stream_id,
                            bound_address,
                        })
                        .await
                        .map_err(|_| MuxError::Unavailable)?;
                    let (stream, record) = spawn_stream(
                        stream_id,
                        bound_address,
                        limits,
                        ordered.clone(),
                        events.clone(),
                    );
                    streams.insert(stream_id, AgentStreamState::Open(record));
                    relays.spawn(async move {
                        let mut stream = stream;
                        let mut socket = socket;
                        if let Err(error) = crate::relay::relay_generic(
                            &mut stream,
                            &mut socket,
                            Duration::ZERO,
                            None,
                        )
                        .await
                        {
                            stream.set_close_reason(CloseReason::Io);
                            debug!(%error, %stream_id, "RDP agent relay ended with an error");
                        }
                    });
                }
                Err(error) => {
                    send_open_error(
                        ordered,
                        stream_id,
                        open_error_code(&error),
                        &error.to_string(),
                    )
                    .await?;
                    if let Some(candidates) = candidates {
                        streams.insert(stream_id, AgentStreamState::Resolved(candidates));
                    }
                }
            }
        }
    }
    Ok(())
}

async fn resolve_remote(
    hostname: String,
    port: u16,
    timeout: Duration,
    policy: &AgentPolicy,
) -> io::Result<Vec<SocketAddr>> {
    let lookup = tokio::net::lookup_host((hostname.as_str(), port));
    let addresses = tokio::time::timeout(timeout, lookup)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "remote DNS timed out"))??;
    let mut result = Vec::new();
    for address in addresses {
        let address = canonicalize_address(address);
        if agent_address_allowed(address.ip(), policy) && !result.contains(&address) {
            result.push(address);
            if result.len() == MAX_RESOLVE_ADDRESSES {
                break;
            }
        }
    }
    Ok(result)
}

fn agent_address_allowed(ip: IpAddr, policy: &AgentPolicy) -> bool {
    if policy.deny_loopback && ip.is_loopback() {
        return false;
    }
    if policy.deny_link_local {
        let denied = match ip {
            IpAddr::V4(ip) => ip.is_link_local(),
            IpAddr::V6(ip) => ip.is_unicast_link_local(),
        };
        if denied {
            return false;
        }
    }
    if policy.deny_private {
        let denied = match ip {
            IpAddr::V4(ip) => ip.is_private(),
            IpAddr::V6(ip) => ip.is_unique_local(),
        };
        if denied {
            return false;
        }
    }
    true
}

fn handle_agent_worker_event(event: WorkerEvent, streams: &mut BTreeMap<u32, AgentStreamState>) {
    match event {
        WorkerEvent::LocalCloseQueued(stream_id) => {
            if matches!(streams.get(&stream_id), Some(AgentStreamState::Open(_))) {
                streams.insert(stream_id, AgentStreamState::Closing);
            }
        }
        WorkerEvent::Stopped(stream_id) => {
            streams.remove(&stream_id);
        }
    }
}

fn register_peer_stream_id(stream_id: u32, highest: &mut u32) -> Result<(), MuxError> {
    if stream_id <= *highest {
        return Err(protocol_error("peer reused or reordered a stream ID"));
    }
    *highest = stream_id;
    Ok(())
}

async fn send_open_error(
    ordered: &mpsc::Sender<Frame>,
    stream_id: u32,
    code: OpenErrorCode,
    diagnostic: &str,
) -> Result<(), MuxError> {
    let diagnostic = safe_diagnostic(diagnostic, protocol::MAX_DIAGNOSTIC_LEN);
    ordered
        .send(Frame::OpenError {
            stream_id,
            code,
            diagnostic,
        })
        .await
        .map_err(|_| MuxError::Unavailable)
}

fn safe_diagnostic(value: &str, maximum: usize) -> String {
    let value: String = value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect();
    truncate_utf8(&value, maximum)
}

fn truncate_utf8(value: &str, maximum: usize) -> String {
    if value.len() <= maximum {
        return value.to_owned();
    }
    let mut end = maximum;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

fn open_error_code(error: &io::Error) -> OpenErrorCode {
    match error.kind() {
        io::ErrorKind::ConnectionRefused => OpenErrorCode::ConnectionRefused,
        io::ErrorKind::TimedOut => OpenErrorCode::Timeout,
        io::ErrorKind::NetworkUnreachable => OpenErrorCode::NetworkUnreachable,
        io::ErrorKind::NotFound
        | io::ErrorKind::AddrNotAvailable
        | io::ErrorKind::HostUnreachable => OpenErrorCode::HostUnreachable,
        io::ErrorKind::Unsupported => OpenErrorCode::AddressTypeUnsupported,
        io::ErrorKind::OutOfMemory => OpenErrorCode::ResourceLimit,
        io::ErrorKind::PermissionDenied => OpenErrorCode::PolicyDenied,
        _ => OpenErrorCode::General,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn sessions() -> (
        ClientHandle,
        JoinHandle<Result<(), MuxError>>,
        JoinHandle<Result<(), MuxError>>,
    ) {
        let (local, remote) = tokio::io::duplex(128 * 1024);
        let agent = tokio::spawn(run_agent_session(remote, AgentPolicy::default()));
        let (client, driver) = start_client_session(local).await.unwrap();
        (client, driver, agent)
    }

    async fn half_close_server() -> (SocketAddr, JoinHandle<io::Result<Vec<u8>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await?;
            let mut request = Vec::new();
            socket.read_to_end(&mut request).await?;
            socket.write_all(b"remote reply").await?;
            socket.shutdown().await?;
            Ok(request)
        });
        (address, task)
    }

    async fn echo_server(connection_count: usize) -> (SocketAddr, JoinHandle<io::Result<()>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            for _ in 0..connection_count {
                let (mut socket, _) = listener.accept().await?;
                let mut value = [0u8; 1];
                socket.read_exact(&mut value).await?;
                socket.write_all(&value).await?;
                socket.shutdown().await?;
            }
            Ok(())
        });
        (address, task)
    }

    #[tokio::test]
    async fn ip_open_relays_and_preserves_tcp_half_close() {
        let (address, server) = half_close_server().await;
        let (client, driver, agent) = sessions().await;
        let mut stream = client
            .open_ip(address, Duration::from_secs(3))
            .await
            .unwrap();
        assert_eq!(stream.stream_id() % 2, 1);
        assert_ne!(stream.bound_address().port(), 0);
        stream.write_all(b"local request").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut reply = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply, b"remote reply");
        assert_eq!(server.await.unwrap().unwrap(), b"local request");
        drop(stream);
        driver.abort();
        agent.abort();
    }

    #[tokio::test]
    async fn crossed_close_keeps_generation_ready_for_the_next_stream() {
        let (address, server) = echo_server(2).await;
        let (client, driver, agent) = sessions().await;

        let mut first = client
            .open_ip(address, Duration::from_secs(3))
            .await
            .unwrap();
        first.write_all(b"a").await.unwrap();
        let mut echoed = [0u8; 1];
        first.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, *b"a");
        let mut eof = Vec::new();
        first.read_to_end(&mut eof).await.unwrap();
        drop(first);

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!driver.is_finished(), "client generation ended after CLOSE");
        assert!(!agent.is_finished(), "agent generation ended after CLOSE");

        let mut second = client
            .open_ip(address, Duration::from_secs(3))
            .await
            .unwrap();
        second.write_all(b"b").await.unwrap();
        second.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, *b"b");
        drop(second);

        server.await.unwrap().unwrap();
        driver.abort();
        agent.abort();
    }

    #[tokio::test]
    async fn remote_resolution_is_two_phase_and_rejects_unlisted_candidate() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (client, driver, agent) = sessions().await;
        let mut resolved = client
            .resolve("localhost", port, Duration::from_secs(3))
            .await
            .unwrap();
        assert!(resolved.can_retry());
        assert!(!resolved.candidates().is_empty());
        let invalid = SocketAddr::from(([192, 0, 2, 1], port));
        assert_eq!(
            resolved
                .open(invalid, Duration::from_secs(1))
                .await
                .unwrap_err(),
            MuxError::InvalidCandidate(invalid)
        );
        assert!(resolved.can_retry());
        let selected = resolved
            .candidates()
            .iter()
            .copied()
            .find(SocketAddr::is_ipv4)
            .unwrap();
        let accept = tokio::spawn(async move { listener.accept().await });
        let stream = resolved
            .open(selected, Duration::from_secs(3))
            .await
            .unwrap();
        assert!(!resolved.can_retry());
        accept.await.unwrap().unwrap();
        drop(stream);
        driver.abort();
        agent.abort();
    }

    #[tokio::test]
    async fn many_streams_progress_independently() {
        const COUNT: usize = 12;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            for _ in 0..COUNT {
                let (mut socket, _) = listener.accept().await.unwrap();
                tasks.spawn(async move {
                    let mut value = [0u8; 1];
                    socket.read_exact(&mut value).await.unwrap();
                    socket.write_all(&value).await.unwrap();
                });
            }
            while tasks.join_next().await.is_some() {}
        });
        let (client, driver, agent) = sessions().await;
        let mut tasks = JoinSet::new();
        for value in 0..COUNT as u8 {
            let client = client.clone();
            tasks.spawn(async move {
                let mut stream = client
                    .open_ip(address, Duration::from_secs(5))
                    .await
                    .unwrap();
                stream.write_all(&[value]).await.unwrap();
                let mut echoed = [0u8; 1];
                stream.read_exact(&mut echoed).await.unwrap();
                assert_eq!(echoed[0], value);
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
        server.await.unwrap();
        driver.abort();
        agent.abort();
    }

    #[tokio::test]
    async fn connection_failure_propagates_without_killing_session() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let (client, driver, agent) = sessions().await;
        let error = client
            .open_ip(address, Duration::from_secs(3))
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            MuxError::Remote {
                code: OpenErrorCode::ConnectionRefused | OpenErrorCode::General,
                ..
            }
        ));
        driver.abort();
        agent.abort();
    }

    #[tokio::test]
    async fn open_timeout_queues_a_cancelled_close() {
        let (local, mut remote) = tokio::io::duplex(128 * 1024);
        let peer = tokio::spawn(async move {
            handshake(&mut remote, Role::Agent).await.unwrap();
            let stream_id = match protocol::read_frame(&mut remote).await.unwrap() {
                Frame::Open { stream_id, .. } => stream_id,
                frame => panic!("expected OPEN, received {frame:?}"),
            };
            assert_eq!(
                protocol::read_frame(&mut remote).await.unwrap(),
                Frame::Close {
                    stream_id,
                    reason: CloseReason::Cancelled,
                }
            );
        });
        let (client, driver) = start_client_session(local).await.unwrap();
        let error = client
            .open_ip("192.0.2.1:443".parse().unwrap(), Duration::from_millis(50))
            .await
            .unwrap_err();
        assert_eq!(error, MuxError::Timeout);
        tokio::time::timeout(Duration::from_secs(1), peer)
            .await
            .unwrap()
            .unwrap();
        driver.abort();
    }

    #[tokio::test]
    async fn abrupt_generation_loss_fails_live_streams() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(10)).await;
        });
        let (client, driver, agent) = sessions().await;
        let mut stream = client
            .open_ip(address, Duration::from_secs(3))
            .await
            .unwrap();
        agent.abort();
        let mut byte = [0u8; 1];
        let result = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut byte))
            .await
            .unwrap();
        assert!(result.is_err(), "live stream should fail on DVC loss");
        driver.abort();
        server.abort();
    }

    #[tokio::test]
    async fn reconnect_starts_a_fresh_generation_without_stale_stream_state() {
        let (address, server) = echo_server(2).await;

        let (client_a, driver_a, agent_a) = sessions().await;
        let mut first = client_a
            .open_ip(address, Duration::from_secs(3))
            .await
            .unwrap();
        assert_eq!(first.stream_id(), 1);
        first.write_all(b"a").await.unwrap();
        let mut echoed = [0u8; 1];
        first.read_exact(&mut echoed).await.unwrap();
        agent_a.abort();
        let result = tokio::time::timeout(Duration::from_secs(3), driver_a)
            .await
            .expect("old client generation should stop")
            .unwrap();
        assert!(result.is_err());
        drop(first);
        drop(client_a);

        let (client_b, driver_b, agent_b) = sessions().await;
        let mut second = client_b
            .open_ip(address, Duration::from_secs(3))
            .await
            .unwrap();
        assert_eq!(second.stream_id(), 1);
        second.write_all(b"b").await.unwrap();
        second.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, *b"b");

        server.await.unwrap().unwrap();
        drop(second);
        driver_b.abort();
        agent_b.abort();
    }

    #[tokio::test]
    async fn receive_window_replenishes_during_a_large_transfer() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let expected = vec![0x5a; protocol::INITIAL_WINDOW as usize * 2 + 17];
        let payload = expected.clone();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(&payload).await.unwrap();
            socket.shutdown().await.unwrap();
        });
        let (client, driver, agent) = sessions().await;
        let mut stream = client
            .open_ip(address, Duration::from_secs(3))
            .await
            .unwrap();
        let mut received = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, expected);
        server.await.unwrap();
        drop(stream);
        driver.abort();
        agent.abort();
    }

    #[tokio::test]
    async fn receive_credit_is_not_reissued_until_window_update_is_queued() {
        let shared = StreamShared::new(4);
        shared.push_inbound(b"abcd").unwrap();
        let mut stream = RdpStream {
            shared: shared.clone(),
            stream_id: 1,
            bound_address: "127.0.0.1:1".parse().unwrap(),
            slot: None,
        };
        let mut consumed = [0u8; 2];
        stream.read_exact(&mut consumed).await.unwrap();
        assert_eq!(consumed, *b"ab");
        assert_eq!(
            shared.push_inbound(b"x").unwrap_err(),
            MuxError::Protocol("peer sent DATA without receive credit".into())
        );
    }

    #[tokio::test]
    async fn negotiated_max_data_is_enforced_by_the_mux() {
        let shared = StreamShared::new(8);
        let mut streams = BTreeMap::from([(1, ClientStreamState::Open(StreamRecord { shared }))]);
        let (control, _control_rx) = mpsc::channel(1);
        let (ordered, _ordered_rx) = mpsc::channel(1);
        let (events, _events_rx) = mpsc::channel(1);
        let mut ping = None;
        let limits = NegotiatedLimits {
            max_data: 4,
            receive_window: 8,
            max_streams: 1,
        };
        let error = handle_client_frame(
            Frame::Data {
                stream_id: 1,
                payload: vec![0; 5],
            },
            limits,
            &mut streams,
            &control,
            &ordered,
            &events,
            &mut ping,
        )
        .await
        .unwrap_err();
        assert_eq!(
            error,
            MuxError::Protocol("DATA exceeds negotiated max_data".into())
        );
    }

    #[tokio::test]
    async fn invalid_client_state_transitions_are_rejected() {
        let (reply, _response) = oneshot::channel();
        let mut streams = BTreeMap::from([(1, ClientStreamState::Resolving { port: 443, reply })]);
        let (control, _control_rx) = mpsc::channel(1);
        let (ordered, _ordered_rx) = mpsc::channel(1);
        let (events, _events_rx) = mpsc::channel(1);
        let limits = NegotiatedLimits {
            max_data: 8,
            receive_window: 8,
            max_streams: 1,
        };
        let mut ping = None;

        let data_error = handle_client_frame(
            Frame::Data {
                stream_id: 1,
                payload: b"x".to_vec(),
            },
            limits,
            &mut streams,
            &control,
            &ordered,
            &events,
            &mut ping,
        )
        .await
        .unwrap_err();
        assert_eq!(
            data_error,
            MuxError::Protocol("DATA arrived before OPEN_OK".into())
        );

        let open_error = handle_client_frame(
            Frame::OpenOk {
                stream_id: 1,
                bound_address: "127.0.0.1:1".parse().unwrap(),
            },
            limits,
            &mut streams,
            &control,
            &ordered,
            &events,
            &mut ping,
        )
        .await
        .unwrap_err();
        assert_eq!(
            open_error,
            MuxError::Protocol("OPEN_OK in the wrong stream state".into())
        );
    }

    #[tokio::test]
    async fn resolve_ok_rejects_a_peer_selected_port() {
        let (reply, response) = oneshot::channel();
        let mut streams = BTreeMap::from([(1, ClientStreamState::Resolving { port: 443, reply })]);
        let (control, _control_rx) = mpsc::channel(1);
        let (ordered, _ordered_rx) = mpsc::channel(1);
        let (events, _events_rx) = mpsc::channel(1);
        let mut ping = None;
        let error = handle_client_frame(
            Frame::ResolveOk {
                stream_id: 1,
                addresses: vec!["192.0.2.10:80".parse().unwrap()],
            },
            NegotiatedLimits {
                max_data: 8,
                receive_window: 8,
                max_streams: 1,
            },
            &mut streams,
            &control,
            &ordered,
            &events,
            &mut ping,
        )
        .await
        .unwrap_err();

        assert_eq!(
            error,
            MuxError::Protocol("RESOLVE_OK returned an address with an unexpected port".into())
        );
        assert_eq!(response.await.unwrap().unwrap_err(), error);
        assert!(streams.is_empty());
    }

    #[tokio::test]
    async fn remote_dns_failure_is_returned_as_open_error() {
        let mut streams = BTreeMap::from([(1, AgentStreamState::Resolving)]);
        let (ordered, mut ordered_rx) = mpsc::channel(1);
        let (events, _events_rx) = mpsc::channel(1);
        let mut relays = JoinSet::new();
        finish_agent_operation(
            AgentOperation::Resolved {
                stream_id: 1,
                result: Err(io::Error::new(io::ErrorKind::NotFound, "name not found")),
            },
            NegotiatedLimits {
                max_data: 4,
                receive_window: 8,
                max_streams: 1,
            },
            &mut streams,
            &ordered,
            &events,
            &mut relays,
        )
        .await
        .unwrap();
        assert!(streams.is_empty());
        assert_eq!(
            ordered_rx.recv().await,
            Some(Frame::OpenError {
                stream_id: 1,
                code: OpenErrorCode::HostUnreachable,
                diagnostic: "name not found".into(),
            })
        );
    }

    #[tokio::test]
    async fn remote_connect_host_unreachable_is_returned_as_open_error() {
        let candidates = vec!["192.0.2.10:443".parse().unwrap()];
        let mut streams = BTreeMap::from([(
            1,
            AgentStreamState::Opening {
                candidates: Some(candidates.clone()),
            },
        )]);
        let (ordered, mut ordered_rx) = mpsc::channel(1);
        let (events, _events_rx) = mpsc::channel(1);
        let mut relays = JoinSet::new();
        finish_agent_operation(
            AgentOperation::Opened {
                stream_id: 1,
                result: Err(io::Error::new(
                    io::ErrorKind::HostUnreachable,
                    "no route to host",
                )),
            },
            NegotiatedLimits {
                max_data: 4,
                receive_window: 8,
                max_streams: 1,
            },
            &mut streams,
            &ordered,
            &events,
            &mut relays,
        )
        .await
        .unwrap();

        assert_eq!(
            ordered_rx.recv().await,
            Some(Frame::OpenError {
                stream_id: 1,
                code: OpenErrorCode::HostUnreachable,
                diagnostic: "no route to host".into(),
            })
        );
        assert!(matches!(
            streams.get(&1),
            Some(AgentStreamState::Resolved(saved)) if saved == &candidates
        ));
    }

    #[tokio::test]
    async fn local_io_failure_queues_an_io_close() {
        let shared = StreamShared::new(8);
        shared.set_close_reason(CloseReason::Io);
        shared.drop_local();
        let (ordered, mut ordered_rx) = mpsc::channel(1);
        let (events, mut events_rx) = mpsc::channel(1);
        outbound_worker(1, 4, shared, ordered, events).await;
        assert_eq!(
            ordered_rx.recv().await,
            Some(Frame::Close {
                stream_id: 1,
                reason: CloseReason::Io,
            })
        );
        assert!(matches!(
            events_rx.recv().await,
            Some(WorkerEvent::LocalCloseQueued(1))
        ));
    }

    #[tokio::test]
    async fn zero_length_read_completes_immediately() {
        let mut stream = RdpStream {
            shared: StreamShared::new(8),
            stream_id: 1,
            bound_address: "127.0.0.1:1".parse().unwrap(),
            slot: None,
        };
        let mut empty = [];
        let read = tokio::time::timeout(Duration::from_millis(50), stream.read(&mut empty))
            .await
            .expect("empty read should not wait")
            .unwrap();
        assert_eq!(read, 0);
    }

    #[tokio::test]
    async fn credit_window_rejects_overflow_and_replenishes() {
        let credit = Arc::new(CreditWindow::new(8));
        assert_eq!(credit.take_up_to(6).await, Some(6));
        credit.add(4).unwrap();
        assert_eq!(credit.take_up_to(8).await, Some(6));
        assert_eq!(
            credit.add(9).unwrap_err(),
            MuxError::Protocol("WINDOW_UPDATE exceeds negotiated window".into())
        );
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_frame_writer_times_out() {
        let (_reader, writer) = tokio::io::duplex(1);
        let (control_tx, control_rx) = mpsc::channel(1);
        let (_ordered_tx, ordered_rx) = mpsc::channel(1);
        control_tx.send(Frame::Ping { nonce: 1 }).await.unwrap();
        let task = tokio::spawn(frame_writer(writer, control_rx, ordered_rx));
        tokio::task::yield_now().await;

        tokio::time::advance(FRAME_WRITE_TIMEOUT + Duration::from_secs(1)).await;
        assert_eq!(task.await.unwrap().unwrap_err(), MuxError::Timeout);
    }

    #[tokio::test]
    async fn stale_close_ack_retires_the_client_tombstone() {
        let mut agent_streams = BTreeMap::new();
        let (agent_control, _agent_control_rx) = mpsc::channel(1);
        let (agent_ordered, mut agent_ordered_rx) = mpsc::channel(1);
        let mut operations = JoinSet::new();
        let mut agent_ping = None;
        let mut highest_stream_id = 1;
        let limits = NegotiatedLimits {
            max_data: 8,
            receive_window: 8,
            max_streams: 1,
        };
        handle_agent_frame(
            Frame::Close {
                stream_id: 1,
                reason: CloseReason::Cancelled,
            },
            limits,
            &AgentPolicy::default(),
            &mut agent_streams,
            &agent_control,
            &agent_ordered,
            &mut operations,
            &mut agent_ping,
            &mut highest_stream_id,
        )
        .await
        .unwrap();
        let acknowledgement = agent_ordered_rx.recv().await.unwrap();
        assert_eq!(
            acknowledgement,
            Frame::Close {
                stream_id: 1,
                reason: CloseReason::Normal,
            }
        );

        let mut client_streams = BTreeMap::from([(1, ClientStreamState::Closing)]);
        let (client_control, _client_control_rx) = mpsc::channel(1);
        let (client_ordered, _client_ordered_rx) = mpsc::channel(1);
        let (events, _events_rx) = mpsc::channel(1);
        let mut client_ping = None;
        handle_client_frame(
            acknowledgement,
            limits,
            &mut client_streams,
            &client_control,
            &client_ordered,
            &events,
            &mut client_ping,
        )
        .await
        .unwrap();
        assert!(client_streams.is_empty());
    }

    #[tokio::test]
    async fn stale_close_still_requires_a_valid_peer_stream_id() {
        let mut streams = BTreeMap::new();
        let (control, _control_rx) = mpsc::channel(1);
        let (ordered, _ordered_rx) = mpsc::channel(1);
        let mut operations = JoinSet::new();
        let mut ping = None;
        let mut highest_stream_id = 3;
        let error = handle_agent_frame(
            Frame::Close {
                stream_id: 2,
                reason: CloseReason::Normal,
            },
            NegotiatedLimits {
                max_data: 8,
                receive_window: 8,
                max_streams: 1,
            },
            &AgentPolicy::default(),
            &mut streams,
            &control,
            &ordered,
            &mut operations,
            &mut ping,
            &mut highest_stream_id,
        )
        .await
        .unwrap_err();

        assert_eq!(
            error,
            MuxError::Protocol("local stream IDs must be nonzero and odd".into())
        );
    }

    #[test]
    fn io_error_kinds_map_to_open_error_codes() {
        let cases = [
            (
                io::ErrorKind::ConnectionRefused,
                OpenErrorCode::ConnectionRefused,
            ),
            (io::ErrorKind::TimedOut, OpenErrorCode::Timeout),
            (
                io::ErrorKind::NetworkUnreachable,
                OpenErrorCode::NetworkUnreachable,
            ),
            (
                io::ErrorKind::HostUnreachable,
                OpenErrorCode::HostUnreachable,
            ),
            (io::ErrorKind::NotFound, OpenErrorCode::HostUnreachable),
            (
                io::ErrorKind::AddrNotAvailable,
                OpenErrorCode::HostUnreachable,
            ),
            (
                io::ErrorKind::Unsupported,
                OpenErrorCode::AddressTypeUnsupported,
            ),
            (io::ErrorKind::OutOfMemory, OpenErrorCode::ResourceLimit),
            (io::ErrorKind::PermissionDenied, OpenErrorCode::PolicyDenied),
            (io::ErrorKind::Other, OpenErrorCode::General),
        ];

        for (kind, expected) in cases {
            assert_eq!(open_error_code(&io::Error::from(kind)), expected);
        }
    }

    #[test]
    fn stream_ids_and_agent_policy_are_strict() {
        assert!(validate_local_stream_id(1).is_ok());
        assert!(validate_local_stream_id(0).is_err());
        assert!(validate_local_stream_id(2).is_err());
        let mut highest = 0;
        register_peer_stream_id(1, &mut highest).unwrap();
        register_peer_stream_id(3, &mut highest).unwrap();
        assert!(register_peer_stream_id(3, &mut highest).is_err());
        assert!(register_peer_stream_id(1, &mut highest).is_err());
        let policy = AgentPolicy {
            deny_loopback: true,
            deny_private: true,
            deny_link_local: true,
            ..AgentPolicy::default()
        };
        assert!(!agent_address_allowed(
            "127.0.0.1".parse().unwrap(),
            &policy
        ));
        assert!(!agent_address_allowed("10.0.0.1".parse().unwrap(), &policy));
        assert!(!agent_address_allowed(
            "169.254.1.1".parse().unwrap(),
            &policy
        ));
        assert!(agent_address_allowed("192.0.2.1".parse().unwrap(), &policy));
        assert_eq!(
            MuxError::Remote {
                code: OpenErrorCode::HostUnreachable,
                diagnostic: "unreachable".into(),
            }
            .into_io()
            .kind(),
            io::ErrorKind::HostUnreachable
        );
    }
}
