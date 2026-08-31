//! mstsc-side out-of-process COM/DVC transport.

use std::ffi::c_void;
use std::io;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::{Arc, Mutex, Weak};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, watch};
use tracing::{debug, error, info, warn};
use windows::core::{implement, Error, IUnknown, Interface, BSTR, GUID, PCSTR};
use windows::Win32::Foundation::{
    CloseHandle, BOOL, CLASS_E_NOAGGREGATION, E_INVALIDARG, E_OUTOFMEMORY, FALSE, HANDLE, TRUE,
};
use windows::Win32::System::Com::{
    CoInitializeEx, CoRegisterClassObject, CoResumeClassObjects, CoRevokeClassObject,
    CoUninitialize, IClassFactory, IClassFactory_Impl, CLSCTX_LOCAL_SERVER, COINIT_MULTITHREADED,
    REGCLS_MULTIPLEUSE, REGCLS_SUSPENDED,
};
use windows::Win32::System::Console::{
    SetConsoleCtrlHandler, CTRL_BREAK_EVENT, CTRL_CLOSE_EVENT, CTRL_C_EVENT, CTRL_SHUTDOWN_EVENT,
};
use windows::Win32::System::RemoteDesktop::{
    IWTSListener, IWTSListenerCallback, IWTSListenerCallback_Impl, IWTSPlugin, IWTSPlugin_Impl,
    IWTSVirtualChannel, IWTSVirtualChannelCallback, IWTSVirtualChannelCallback_Impl,
    IWTSVirtualChannelManager,
};
use windows::Win32::System::Threading::{CreateEventW, SetEvent, WaitForSingleObject, INFINITE};
use windows_core::AgileReference;

use super::pipe;
use super::registration::PLUGIN_CLSID;

pub const CHANNEL_NAME: &str = "alighieri::rdp::v1";
const CHANNEL_NAME_NUL: &[u8] = b"alighieri::rdp::v1\0";
const BRIDGE_QUEUE_CAPACITY: usize = 512;
const MAX_CALLBACK_BYTES: u32 = 65_536;
/// Conservative maximum accepted by every supported mstsc DVC implementation.
const DVC_WRITE_CHUNK: usize = 1_590;

static SHUTDOWN_EVENT: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

fn shutdown_handle() -> HANDLE {
    HANDLE(SHUTDOWN_EVENT.load(Ordering::Acquire))
}

unsafe extern "system" fn console_handler(control: u32) -> BOOL {
    if matches!(
        control,
        CTRL_C_EVENT | CTRL_BREAK_EVENT | CTRL_CLOSE_EVENT | CTRL_SHUTDOWN_EVENT
    ) {
        let event = shutdown_handle();
        if !event.is_invalid() {
            // SAFETY: `run_com_server` publishes a live manual-reset event until
            // after the handler is removed.
            unsafe {
                let _ = SetEvent(event);
            }
        }
        TRUE
    } else {
        FALSE
    }
}

#[derive(Default)]
struct BridgeHub {
    active: Mutex<Option<Weak<SessionBridge>>>,
}

impl BridgeHub {
    fn open(&self, channel: &IWTSVirtualChannel) -> windows::core::Result<Arc<SessionBridge>> {
        let mut active = self
            .active
            .lock()
            .map_err(|_| Error::new(E_OUTOFMEMORY, "bridge lock poisoned"))?;
        if let Some(existing) = active.as_ref().and_then(Weak::upgrade) {
            if !existing.is_closed() {
                return Err(Error::new(
                    E_OUTOFMEMORY,
                    "an Alighieri DVC is already active",
                ));
            }
        }

        let agile = AgileReference::new(channel)?;
        let session = SessionBridge::start(agile)?;
        *active = Some(Arc::downgrade(&session));
        Ok(session)
    }

    fn close_active(&self) {
        if let Ok(active) = self.active.lock() {
            if let Some(session) = active.as_ref().and_then(Weak::upgrade) {
                session.close();
            }
        }
    }
}

struct SessionBridge {
    inbound: mpsc::Sender<Vec<u8>>,
    stop: watch::Sender<bool>,
    closed: AtomicBool,
}

impl SessionBridge {
    fn start(channel: AgileReference<IWTSVirtualChannel>) -> windows::core::Result<Arc<Self>> {
        let (inbound_tx, inbound_rx) = mpsc::channel(BRIDGE_QUEUE_CAPACITY);
        let (outbound_tx, outbound_rx) = mpsc::channel(BRIDGE_QUEUE_CAPACITY);
        let (stop, stop_rx) = watch::channel(false);
        let session = Arc::new(Self {
            inbound: inbound_tx,
            stop,
            closed: AtomicBool::new(false),
        });

        spawn_channel_writer(session.clone(), channel, outbound_rx).map_err(|error| {
            Error::new(
                E_OUTOFMEMORY,
                format!("failed to start DVC writer: {error}"),
            )
        })?;
        if let Err(error) = spawn_pipe_bridge(session.clone(), inbound_rx, outbound_tx, stop_rx) {
            session.close();
            return Err(Error::new(
                E_OUTOFMEMORY,
                format!("failed to start named-pipe bridge: {error}"),
            ));
        }
        Ok(session)
    }

    fn on_data(&self, data: &[u8]) -> windows::core::Result<()> {
        if self.is_closed() {
            return Ok(());
        }
        match self.inbound.try_send(data.to_vec()) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.close();
                Err(Error::new(
                    E_OUTOFMEMORY,
                    "Alighieri DVC receive queue is full",
                ))
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Ok(()),
        }
    }

    fn close(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.stop.send_replace(true);
        }
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

impl Drop for SessionBridge {
    fn drop(&mut self) {
        self.close();
    }
}

fn spawn_channel_writer(
    session: Arc<SessionBridge>,
    channel: AgileReference<IWTSVirtualChannel>,
    mut outbound: mpsc::Receiver<Vec<u8>>,
) -> io::Result<()> {
    std::thread::Builder::new()
        .name("alighieri-rdp-dvc-writer".into())
        .spawn(move || {
            // SAFETY: this thread owns one balanced MTA initialization.
            let initialized = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }.is_ok();
            if !initialized {
                error!("failed to initialize the DVC writer COM apartment");
                session.close();
                return;
            }

            let result = channel.resolve().and_then(|resolved| {
                let writes = (|| -> windows::core::Result<()> {
                    while let Some(data) = outbound.blocking_recv() {
                        for chunk in data.chunks(DVC_WRITE_CHUNK) {
                            // SAFETY: the resolved proxy is used only in this initialized
                            // apartment and `Write` copies the live slice before returning.
                            unsafe {
                                resolved.Write(chunk, None::<&IUnknown>)?;
                            }
                        }
                    }
                    Ok(())
                })();
                // This is outside every DVC callback. Closing here makes pipe loss
                // visible to WTS immediately instead of waiting for keepalive expiry.
                let close = unsafe { resolved.Close() };
                drop(resolved);
                writes.and(close)
            });
            drop(channel);
            if let Err(error) = result {
                warn!(%error, "RDP DVC writer stopped");
            }
            session.close();
            // SAFETY: balances the successful initialization above on this thread.
            unsafe { CoUninitialize() };
        })?;
    Ok(())
}

fn spawn_pipe_bridge(
    session: Arc<SessionBridge>,
    mut inbound: mpsc::Receiver<Vec<u8>>,
    outbound: mpsc::Sender<Vec<u8>>,
    mut stop: watch::Receiver<bool>,
) -> io::Result<()> {
    std::thread::Builder::new()
        .name("alighieri-rdp-pipe".into())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    error!(%error, "failed to create local bridge runtime");
                    session.close();
                    return;
                }
            };
            runtime.block_on(async {
                let result = run_pipe_bridge(&mut inbound, &outbound, &mut stop).await;
                if let Err(error) = result {
                    debug!(%error, "local RDP pipe bridge stopped");
                }
                session.close();
            });
        })?;
    Ok(())
}

async fn run_pipe_bridge(
    inbound: &mut mpsc::Receiver<Vec<u8>>,
    outbound: &mpsc::Sender<Vec<u8>>,
    stop: &mut watch::Receiver<bool>,
) -> io::Result<()> {
    let mut pipe = pipe::create_server()?;
    tokio::select! {
        result = pipe.connect() => result?,
        _ = stop.wait_for(|value| *value) => return Ok(()),
    }
    info!(
        pipe = pipe::PIPE_NAME,
        "Alighieri connected to the RDP channel bridge"
    );

    let mut read_buffer = [0u8; 16 * 1024];
    loop {
        tokio::select! {
            _ = stop.wait_for(|value| *value) => return Ok(()),
            data = inbound.recv() => match data {
                Some(data) => pipe.write_all(&data).await?,
                None => return Ok(()),
            },
            read = pipe.read(&mut read_buffer) => {
                let count = read?;
                if count == 0 {
                    return Ok(());
                }
                // The COM writer owns the channel and performs the final DVC-sized
                // chunking. Awaiting this bounded queue propagates backpressure to
                // the pipe without ever blocking a COM callback.
                outbound
                    .send(read_buffer[..count].to_vec())
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "DVC writer closed"))?;
            }
        }
    }
}

#[implement(IWTSPlugin, IWTSListenerCallback)]
struct RdpPlugin {
    listener: Mutex<Option<IWTSListener>>,
    manager: Mutex<Option<IWTSVirtualChannelManager>>,
    session: Mutex<Option<Weak<SessionBridge>>>,
    hub: Arc<BridgeHub>,
}

impl RdpPlugin {
    fn new(hub: Arc<BridgeHub>) -> Self {
        Self {
            listener: Mutex::new(None),
            manager: Mutex::new(None),
            session: Mutex::new(None),
            hub,
        }
    }

    fn close_owned_session(&self) {
        if let Ok(session) = self.session.lock() {
            if let Some(session) = session.as_ref().and_then(Weak::upgrade) {
                session.close();
            }
        }
    }
}

impl Drop for RdpPlugin {
    fn drop(&mut self) {
        self.close_owned_session();
    }
}

impl IWTSPlugin_Impl for RdpPlugin_Impl {
    fn Initialize(
        &self,
        channel_manager: Option<&IWTSVirtualChannelManager>,
    ) -> windows::core::Result<()> {
        let manager = channel_manager.ok_or_else(|| Error::new(E_INVALIDARG, "null manager"))?;
        // SAFETY: the windows-rs implementation object advertises
        // IWTSListenerCallback through the `implement` declaration above.
        let callback: IWTSListenerCallback = unsafe { self.cast()? };
        // SAFETY: CHANNEL_NAME_NUL is static, ASCII, and NUL-terminated; callback
        // and listener COM references are retained for the plugin lifetime.
        let listener =
            unsafe { manager.CreateListener(PCSTR(CHANNEL_NAME_NUL.as_ptr()), 0, &callback)? };
        *self
            .listener
            .lock()
            .map_err(|_| Error::new(E_OUTOFMEMORY, "listener lock poisoned"))? = Some(listener);
        *self
            .manager
            .lock()
            .map_err(|_| Error::new(E_OUTOFMEMORY, "manager lock poisoned"))? =
            Some(manager.clone());
        info!(
            channel = CHANNEL_NAME,
            "registered RDP Dynamic Virtual Channel listener"
        );
        Ok(())
    }

    fn Connected(&self) -> windows::core::Result<()> {
        info!("mstsc connected");
        Ok(())
    }

    fn Disconnected(&self, disconnect_code: u32) -> windows::core::Result<()> {
        info!(disconnect_code, "mstsc disconnected");
        self.close_owned_session();
        Ok(())
    }

    fn Terminated(&self) -> windows::core::Result<()> {
        self.close_owned_session();
        if let Ok(mut listener) = self.listener.lock() {
            *listener = None;
        }
        if let Ok(mut manager) = self.manager.lock() {
            *manager = None;
        }
        info!("RDP DVC plugin terminated");
        Ok(())
    }
}

impl IWTSListenerCallback_Impl for RdpPlugin_Impl {
    fn OnNewChannelConnection(
        &self,
        channel: Option<&IWTSVirtualChannel>,
        _data: &BSTR,
        accept: *mut BOOL,
        callback: *mut Option<IWTSVirtualChannelCallback>,
    ) -> windows::core::Result<()> {
        if accept.is_null() || callback.is_null() {
            return Err(Error::new(E_INVALIDARG, "null DVC callback output"));
        }
        // Initialize all out parameters before any fallible work.
        // SAFETY: COM supplies writable, potentially uninitialized out storage
        // when these pointers are non-null. `ptr::write` must be used for the
        // interface Option so initialization never tries to release garbage.
        unsafe {
            ptr::write(accept, FALSE);
            ptr::write(callback, None);
        }
        let channel = channel.ok_or_else(|| Error::new(E_INVALIDARG, "null DVC"))?;
        // Acquire the only fallible per-plugin state before starting bridge
        // threads. If this mutex were poisoned after `hub.open`, those threads
        // would otherwise retain an ownerless live session.
        let mut owned_session = self
            .session
            .lock()
            .map_err(|_| Error::new(E_OUTOFMEMORY, "session lock poisoned"))?;
        let session = match self.hub.open(channel) {
            Ok(session) => session,
            Err(error) => {
                warn!(%error, "rejected additional RDP DVC");
                return Ok(());
            }
        };
        *owned_session = Some(Arc::downgrade(&session));
        drop(owned_session);
        let channel_callback: IWTSVirtualChannelCallback = RdpChannelCallback { session }.into();
        // SAFETY: both outputs were initialized above. `ptr::write` transfers
        // the callback interface directly into COM-owned output storage only
        // after the bridge successfully started; the previous value is `None`.
        unsafe {
            ptr::write(accept, TRUE);
            ptr::write(callback, Some(channel_callback));
        }
        info!(
            channel = CHANNEL_NAME,
            "accepted RDP Dynamic Virtual Channel"
        );
        Ok(())
    }
}

#[implement(IWTSVirtualChannelCallback)]
struct RdpChannelCallback {
    session: Arc<SessionBridge>,
}

impl Drop for RdpChannelCallback {
    fn drop(&mut self) {
        // COM is not required to deliver OnClose when a client or proxy dies.
        // Closing from Drop wakes both bridge threads and releases the hub slot.
        self.session.close();
    }
}

impl IWTSVirtualChannelCallback_Impl for RdpChannelCallback_Impl {
    fn OnDataReceived(&self, size: u32, buffer: *const u8) -> windows::core::Result<()> {
        if size == 0 {
            return Ok(());
        }
        if buffer.is_null() || size > MAX_CALLBACK_BYTES {
            self.session.close();
            return Err(Error::new(E_INVALIDARG, "invalid DVC callback buffer"));
        }
        // SAFETY: mstsc guarantees the callback buffer is readable for `size`
        // bytes during this call; it is copied before returning.
        let data = unsafe { std::slice::from_raw_parts(buffer, size as usize) };
        self.session.on_data(data)
    }

    fn OnClose(&self) -> windows::core::Result<()> {
        // Keep teardown out of the callback: signaling lets the dedicated COM
        // writer serialize the final Close and all proxy release operations.
        self.session.close();
        info!(channel = CHANNEL_NAME, "RDP Dynamic Virtual Channel closed");
        Ok(())
    }
}

#[implement(IClassFactory)]
struct ClassFactory {
    hub: Arc<BridgeHub>,
}

impl IClassFactory_Impl for ClassFactory_Impl {
    fn CreateInstance(
        &self,
        outer: Option<&IUnknown>,
        iid: *const GUID,
        object: *mut *mut c_void,
    ) -> windows::core::Result<()> {
        if !object.is_null() {
            // SAFETY: a non-null COM out pointer is writable for this call.
            unsafe { *object = ptr::null_mut() };
        }
        if outer.is_some() {
            return Err(Error::new(
                CLASS_E_NOAGGREGATION,
                "aggregation is unsupported",
            ));
        }
        if iid.is_null() || object.is_null() {
            return Err(Error::new(E_INVALIDARG, "null COM output"));
        }
        // SAFETY: validated pointers are supplied by COM; `query` AddRefs the
        // returned interface into the caller-owned out pointer.
        unsafe {
            let plugin: IWTSPlugin = RdpPlugin::new(self.hub.clone()).into();
            plugin.query(&*iid, object).ok()
        }
    }

    fn LockServer(&self, _lock: BOOL) -> windows::core::Result<()> {
        Ok(())
    }
}

/// Runs the free-threaded COM LocalServer until a console shutdown signal or
/// process termination. mstsc launches this entry point with `-Embedding`.
pub fn run() -> io::Result<()> {
    run_com_server().map_err(io::Error::other)
}

fn run_com_server() -> windows::core::Result<()> {
    // SAFETY: all COM/event registrations are balanced on this same main thread.
    unsafe {
        CoInitializeEx(None, COINIT_MULTITHREADED).ok()?;
        let event = match CreateEventW(None, true, false, None) {
            Ok(event) => event,
            Err(error) => {
                CoUninitialize();
                return Err(error);
            }
        };
        SHUTDOWN_EVENT.store(event.0, Ordering::Release);
        if let Err(error) = SetConsoleCtrlHandler(Some(console_handler), true) {
            SHUTDOWN_EVENT.store(ptr::null_mut(), Ordering::Release);
            let _ = CloseHandle(event);
            CoUninitialize();
            return Err(error);
        }

        let hub = Arc::new(BridgeHub::default());
        let factory: IClassFactory = ClassFactory { hub: hub.clone() }.into();
        let cookie = match CoRegisterClassObject(
            &PLUGIN_CLSID,
            &factory,
            CLSCTX_LOCAL_SERVER,
            REGCLS_MULTIPLEUSE | REGCLS_SUSPENDED,
        ) {
            Ok(cookie) => cookie,
            Err(error) => {
                drop(factory);
                let _ = SetConsoleCtrlHandler(Some(console_handler), false);
                SHUTDOWN_EVENT.store(ptr::null_mut(), Ordering::Release);
                let _ = CloseHandle(event);
                CoUninitialize();
                return Err(error);
            }
        };
        if let Err(error) = CoResumeClassObjects() {
            let _ = CoRevokeClassObject(cookie);
            drop(factory);
            let _ = SetConsoleCtrlHandler(Some(console_handler), false);
            SHUTDOWN_EVENT.store(ptr::null_mut(), Ordering::Release);
            let _ = CloseHandle(event);
            CoUninitialize();
            return Err(error);
        }

        info!(clsid = %format!("{{{PLUGIN_CLSID:?}}}"), "RDP transport COM LocalServer ready");
        WaitForSingleObject(event, INFINITE);
        hub.close_active();
        let _ = CoRevokeClassObject(cookie);
        drop(factory);
        let _ = SetConsoleCtrlHandler(Some(console_handler), false);
        SHUTDOWN_EVENT.store(ptr::null_mut(), Ordering::Release);
        let _ = CloseHandle(event);
        CoUninitialize();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_session() -> (Arc<SessionBridge>, watch::Receiver<bool>) {
        let (inbound, _inbound_rx) = mpsc::channel(1);
        let (stop, stop_rx) = watch::channel(false);
        (
            Arc::new(SessionBridge {
                inbound,
                stop,
                closed: AtomicBool::new(false),
            }),
            stop_rx,
        )
    }

    #[test]
    fn callback_drop_closes_the_bridge_without_on_close() {
        let (session, stop) = test_session();
        drop(RdpChannelCallback {
            session: session.clone(),
        });

        assert!(session.is_closed());
        assert!(*stop.borrow());
    }

    #[test]
    fn plugin_drop_closes_its_owned_bridge() {
        let (session, stop) = test_session();
        let plugin = RdpPlugin::new(Arc::new(BridgeHub::default()));
        *plugin.session.lock().unwrap() = Some(Arc::downgrade(&session));
        drop(plugin);

        assert!(session.is_closed());
        assert!(*stop.borrow());
    }
}
