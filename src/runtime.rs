//! Shared runtime helpers for console and service hosts.

use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::future::Future;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tracing::{error, info};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::EnvFilter;

use crate::config::{Config, LogFormat, LogOutput};
#[cfg(windows)]
use crate::config::{DEFAULT_LOG_ROTATE_KEEP, DEFAULT_LOG_ROTATE_SIZE_BYTES};
use crate::errors::{Error, Result};
use crate::server::Server;

/// Runs the SOCKS server until it exits or the supplied shutdown future
/// resolves.
pub async fn run_server_until_shutdown<F>(config: Config, shutdown: F) -> Result<()>
where
    F: Future<Output = ()>,
{
    let server = Server::bind(config).await?;
    run_bound_server_until_shutdown(server, shutdown).await
}

/// Loads configuration from `config_path`, runs the server, and reloads the
/// runtime policy for new connections whenever a reload event is received.
pub async fn run_server_reloading_until_shutdown<F>(
    config_path: PathBuf,
    shutdown: F,
    reloads: mpsc::UnboundedReceiver<()>,
) -> Result<()>
where
    F: Future<Output = ()>,
{
    let config = Config::load(&config_path)?;
    let server = Server::bind(config).await?;
    run_bound_server_reloading_until_shutdown(server, config_path, shutdown, reloads).await
}

/// Runs an already-bound SOCKS server and reloads runtime policy from
/// `config_path` whenever a reload event is received.
pub async fn run_bound_server_reloading_until_shutdown<F>(
    server: Server,
    config_path: PathBuf,
    shutdown: F,
    mut reloads: mpsc::UnboundedReceiver<()>,
) -> Result<()>
where
    F: Future<Output = ()>,
{
    let server = Arc::new(server);
    let run_server = server.clone();
    let mut run_task = tokio::spawn(async move { run_server.run().await });
    let mut reloads_closed = false;
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            res = &mut run_task => {
                return server_join_result(res);
            }
            _ = &mut shutdown => {
                // Stop accepting and drain in-flight connections (bounded inside
                // `run`), then wait for the loop to finish rather than aborting it.
                info!("shutdown signal received; draining in-flight connections");
                server.begin_shutdown();
                return server_join_result((&mut run_task).await);
            }
            event = reloads.recv(), if !reloads_closed => {
                match event {
                    Some(()) => {
                        // Apply the reload as a future raced against shutdown, so a
                        // stop signal is never delayed behind slow config/userlist
                        // I/O or a wedged filesystem. `Config::load` is synchronous,
                        // so run it on a blocking thread rather than on this task;
                        // `server.reload` already does its own blocking reads. With
                        // `biased`, shutdown wins over an in-progress reload.
                        let reload = async {
                            let path = config_path.clone();
                            match tokio::task::spawn_blocking(move || Config::load(&path)).await {
                                Ok(Ok(config)) => {
                                    if let Err(e) = server.reload(config).await {
                                        error!(config = %config_path.display(), error = %e, "configuration reload failed; keeping active configuration");
                                    }
                                }
                                Ok(Err(e)) => {
                                    error!(config = %config_path.display(), error = %e, "configuration reload failed; keeping active configuration");
                                }
                                Err(e) => {
                                    error!(config = %config_path.display(), error = %e, "configuration reload task failed; keeping active configuration");
                                }
                            }
                        };
                        tokio::select! {
                            biased;
                            _ = &mut shutdown => {
                                info!("shutdown signal received; draining in-flight connections");
                                server.begin_shutdown();
                                return server_join_result((&mut run_task).await);
                            }
                            // Still observe a fatal server exit during a slow reload
                            // so the driver returns promptly rather than after the
                            // reload finishes.
                            res = &mut run_task => return server_join_result(res),
                            () = reload => {}
                        }
                    }
                    None => reloads_closed = true,
                }
            }
        }
    }
}

/// Maps a joined `run` task result to the driver's return value. A cancelled
/// (aborted) task counts as a clean stop.
fn server_join_result(
    joined: std::result::Result<Result<()>, tokio::task::JoinError>,
) -> Result<()> {
    match joined {
        Ok(res) => res,
        Err(e) if e.is_cancelled() => Ok(()),
        Err(e) => Err(Error::Io(io::Error::other(format!(
            "server task failed: {e}"
        )))),
    }
}

/// Runs an already-bound SOCKS server until it exits or the supplied shutdown
/// future resolves. On shutdown the accept loop stops and in-flight connections
/// are drained (bounded inside `run`) before the process returns.
pub async fn run_bound_server_until_shutdown<F>(server: Server, shutdown: F) -> Result<()>
where
    F: Future<Output = ()>,
{
    let server = Arc::new(server);
    let run_server = server.clone();
    let mut run_task = tokio::spawn(async move { run_server.run().await });
    tokio::pin!(shutdown);

    tokio::select! {
        res = &mut run_task => server_join_result(res),
        _ = &mut shutdown => {
            info!("shutdown signal received; draining in-flight connections");
            server.begin_shutdown();
            server_join_result((&mut run_task).await)
        }
    }
}

/// Returns a receiver that emits process reload requests.
///
/// Unix builds use SIGHUP. Other platforms currently return a disabled
/// receiver; Windows Service mode wires its Service Control Manager reload
/// command directly into `run_bound_server_reloading_until_shutdown`.
pub fn reload_signal_channel() -> mpsc::UnboundedReceiver<()> {
    let (tx, rx) = mpsc::unbounded_channel();
    spawn_reload_signal_task(tx);
    rx
}

#[cfg(unix)]
fn spawn_reload_signal_task(tx: mpsc::UnboundedSender<()>) {
    tokio::spawn(async move {
        use tokio::signal::unix::{signal, SignalKind};
        use tracing::warn;

        let mut sighup = match signal(SignalKind::hangup()) {
            Ok(signal) => signal,
            Err(e) => {
                warn!(error = %e, "failed to install SIGHUP handler; hot reload disabled");
                return;
            }
        };
        while sighup.recv().await.is_some() {
            if tx.send(()).is_err() {
                break;
            }
        }
    });
}

#[cfg(not(unix))]
fn spawn_reload_signal_task(_tx: mpsc::UnboundedSender<()>) {}

/// Initialises console logging using all configured sinks. The returned
/// guard must be held for the life of the process; dropping it flushes the
/// background log writer.
pub fn init_console_logging(config: &Config) -> io::Result<LogGuard> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let writer = LogWriters::from_config(config)?;
    init_logging(
        filter,
        writer,
        config.log_format,
        config.uses_file_logging(),
    )
}

fn init_logging(
    filter: EnvFilter,
    writer: LogWriters,
    format: LogFormat,
    disable_ansi: bool,
) -> io::Result<LogGuard> {
    // Log records are formatted inline but written by a dedicated thread:
    // console and file I/O are synchronous and process-global, and paying for
    // them on the data path costs measurable connection throughput.
    let (make_writer, guard) =
        AsyncLogWriters::spawn(writer.into_multi(), LOG_QUEUE_CAPACITY, format)?;
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_ansi(!disable_ansi)
        .with_writer(make_writer);

    let result = match format {
        LogFormat::Text => builder.try_init(),
        LogFormat::Json => builder.json().try_init(),
    };

    if let Err(e) = result {
        // Returning the guard would be misleading (it does not flush the
        // subscriber that is actually active), and dropping it here also
        // winds down the writer thread spawned above.
        return Err(io::Error::other(format!(
            "logging already initialised: {e}"
        )));
    }
    Ok(guard)
}

/// Initialises file logging for service mode and returns the active log file
/// together with the guard that flushes the writer on drop.
#[cfg(windows)]
pub fn init_file_logging(log_dir: &Path) -> io::Result<(PathBuf, LogGuard)> {
    std::fs::create_dir_all(log_dir)?;
    let log_path = log_dir.join("alighieri.log");
    let writer = LogWriters::file(
        log_path.clone(),
        DEFAULT_LOG_ROTATE_SIZE_BYTES,
        DEFAULT_LOG_ROTATE_KEEP,
    )?;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let guard = init_logging(filter, writer, LogFormat::Text, true)?;

    Ok((log_path, guard))
}

#[cfg(windows)]
pub fn init_service_logging(config: &Config, log_dir: &Path) -> io::Result<(PathBuf, LogGuard)> {
    std::fs::create_dir_all(log_dir)?;
    let log_path = log_dir.join("alighieri.log");
    let writer = LogWriters::file(
        log_path.clone(),
        config.log_rotate_size,
        config.log_rotate_keep,
    )?;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let guard = init_logging(filter, writer, config.log_format, true)?;

    Ok((log_path, guard))
}

/// Queue depth for the background log writer. Records beyond this are
/// dropped (and counted) rather than blocking the data plane.
const LOG_QUEUE_CAPACITY: usize = 8192;
/// How long a shutdown flush waits for the writer thread to drain.
const LOG_FLUSH_TIMEOUT: Duration = Duration::from_secs(5);

enum LogCommand {
    Record(Vec<u8>),
    Flush(std_mpsc::SyncSender<()>),
}

/// `MakeWriter` that hands formatted records to a dedicated writer thread so
/// the async runtime never blocks on console or file I/O. When the queue is
/// full the record is dropped and counted instead of applying backpressure;
/// the writer thread reports the running drop count in-band.
#[derive(Clone)]
struct AsyncLogWriters {
    tx: std_mpsc::SyncSender<LogCommand>,
    dropped: Arc<AtomicU64>,
}

impl AsyncLogWriters {
    fn spawn<W: Write + Send + 'static>(
        mut sink: W,
        capacity: usize,
        format: LogFormat,
    ) -> io::Result<(Self, LogGuard)> {
        let (tx, rx) = std_mpsc::sync_channel(capacity);
        let dropped = Arc::new(AtomicU64::new(0));
        let worker_dropped = dropped.clone();
        std::thread::Builder::new()
            .name("log-writer".into())
            .spawn(move || run_log_worker(rx, &mut sink, &worker_dropped, format))?;
        let guard = LogGuard { tx: tx.clone() };
        Ok((AsyncLogWriters { tx, dropped }, guard))
    }
}

fn run_log_worker<W: Write>(
    rx: std_mpsc::Receiver<LogCommand>,
    sink: &mut W,
    dropped: &AtomicU64,
    format: LogFormat,
) {
    let mut reported: u64 = 0;
    let mut sink_failing = false;
    while let Ok(command) = rx.recv() {
        match command {
            LogCommand::Record(record) => {
                report_dropped_records(sink, dropped, &mut reported, format);
                match sink.write_all(&record) {
                    Ok(()) => sink_failing = false,
                    Err(e) => {
                        // The record is lost like a queue overflow, so fold it
                        // into the drop count — the in-band report covers it
                        // once the sink recovers. stderr is the only channel
                        // left to note the failure itself; once per streak.
                        dropped.fetch_add(1, Ordering::Relaxed);
                        if !sink_failing {
                            eprintln!("alighieri: log sink write failed: {e}");
                            sink_failing = true;
                        }
                    }
                }
            }
            LogCommand::Flush(ack) => {
                // Reporting here too makes drops visible even when the
                // process shuts down before another record is written.
                report_dropped_records(sink, dropped, &mut reported, format);
                let _ = sink.flush();
                let _ = ack.send(());
            }
        }
    }
    report_dropped_records(sink, dropped, &mut reported, format);
    let _ = sink.flush();
}

/// Emits the in-band warning about dropped records in the sink's own format,
/// so JSON pipelines keep parsing the stream.
fn report_dropped_records<W: Write>(
    sink: &mut W,
    dropped: &AtomicU64,
    reported: &mut u64,
    format: LogFormat,
) {
    let total = dropped.load(Ordering::Relaxed);
    if total <= *reported {
        return;
    }
    let delta = total - *reported;
    let line = match format {
        LogFormat::Text => format!(
            "WARN alighieri: dropped {delta} log records under load ({total} dropped in total)\n"
        ),
        LogFormat::Json => format!(
            "{{\"level\":\"WARN\",\"fields\":{{\"message\":\"dropped {delta} log records under load ({total} dropped in total)\"}},\"target\":\"alighieri::runtime\"}}\n"
        ),
    };
    // Only mark the drops as reported once the warning actually reached the
    // sink; a failed write retries on the next opportunity.
    if sink.write_all(line.as_bytes()).is_ok() {
        *reported = total;
    }
}

/// One formatted log record in flight; queued to the writer thread on drop.
struct AsyncLogHandle {
    buf: Vec<u8>,
    tx: std_mpsc::SyncSender<LogCommand>,
    dropped: Arc<AtomicU64>,
}

impl Write for AsyncLogHandle {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for AsyncLogHandle {
    fn drop(&mut self) {
        if self.buf.is_empty() {
            return;
        }
        let record = std::mem::take(&mut self.buf);
        if self.tx.try_send(LogCommand::Record(record)).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl<'a> MakeWriter<'a> for AsyncLogWriters {
    type Writer = AsyncLogHandle;

    fn make_writer(&'a self) -> Self::Writer {
        AsyncLogHandle {
            buf: Vec::new(),
            tx: self.tx.clone(),
            dropped: self.dropped.clone(),
        }
    }
}

/// Flushes the background log writer when dropped. Hold it in `main` (or the
/// service entry point) for the lifetime of the process.
pub struct LogGuard {
    tx: std_mpsc::SyncSender<LogCommand>,
}

impl Drop for LogGuard {
    fn drop(&mut self) {
        let (ack_tx, ack_rx) = std_mpsc::sync_channel(1);
        let deadline = Instant::now() + LOG_FLUSH_TIMEOUT;
        let mut command = LogCommand::Flush(ack_tx);
        loop {
            match self.tx.try_send(command) {
                Ok(()) => {
                    let _ = ack_rx.recv_timeout(deadline.saturating_duration_since(Instant::now()));
                    break;
                }
                Err(std_mpsc::TrySendError::Full(returned)) => {
                    if Instant::now() >= deadline {
                        break;
                    }
                    command = returned;
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(std_mpsc::TrySendError::Disconnected(_)) => break,
            }
        }
    }
}

#[derive(Clone)]
struct LogWriters {
    sinks: Vec<LogSink>,
}

impl LogWriters {
    fn from_config(config: &Config) -> io::Result<Self> {
        let mut sinks = Vec::new();
        for output in &config.log_outputs {
            match output {
                LogOutput::Stdout => sinks.push(LogSink::Stdout),
                LogOutput::Stderr => sinks.push(LogSink::Stderr),
                LogOutput::File => {
                    let Some(path) = &config.log_file else {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "logoutput 'file' requires a logfile setting",
                        ));
                    };
                    sinks.push(LogSink::File(RotatingFileHandle::open(
                        path,
                        config.log_rotate_size,
                        config.log_rotate_keep,
                    )?));
                }
            }
        }
        Ok(Self { sinks })
    }

    #[cfg(windows)]
    fn file(path: PathBuf, max_bytes: u64, keep: usize) -> io::Result<Self> {
        Ok(Self {
            sinks: vec![LogSink::File(RotatingFileHandle::open(
                path, max_bytes, keep,
            )?)],
        })
    }

    fn into_multi(self) -> MultiLogWriter {
        MultiLogWriter {
            sinks: self
                .sinks
                .into_iter()
                .map(|sink| SinkState {
                    sink,
                    failing: false,
                })
                .collect(),
        }
    }
}

#[derive(Clone)]
enum LogSink {
    Stdout,
    Stderr,
    File(RotatingFileHandle),
    #[cfg(test)]
    Test(TestSink),
}

impl LogSink {
    fn name(&self) -> &'static str {
        match self {
            LogSink::Stdout => "stdout",
            LogSink::Stderr => "stderr",
            LogSink::File(_) => "file",
            #[cfg(test)]
            LogSink::Test(_) => "test",
        }
    }

    fn write_record(&self, buf: &[u8]) -> io::Result<()> {
        match self {
            LogSink::Stdout => std::io::stdout().write_all(buf),
            LogSink::Stderr => std::io::stderr().write_all(buf),
            LogSink::File(file) => file.write_all(buf),
            #[cfg(test)]
            LogSink::Test(sink) => sink.write_record(buf),
        }
    }

    fn flush_sink(&self) -> io::Result<()> {
        match self {
            LogSink::Stdout => std::io::stdout().flush(),
            LogSink::Stderr => std::io::stderr().flush(),
            LogSink::File(file) => file.flush(),
            #[cfg(test)]
            LogSink::Test(_) => Ok(()),
        }
    }
}

/// A sink with controllable failure, used to exercise multi-sink semantics.
#[cfg(test)]
#[derive(Clone)]
struct TestSink {
    failing: Arc<std::sync::atomic::AtomicBool>,
    out: Arc<Mutex<Vec<u8>>>,
}

#[cfg(test)]
impl TestSink {
    fn write_record(&self, buf: &[u8]) -> io::Result<()> {
        if self.failing.load(Ordering::SeqCst) {
            return Err(io::Error::other("sink unavailable"));
        }
        self.out.lock().unwrap().extend_from_slice(buf);
        Ok(())
    }
}

struct SinkState {
    sink: LogSink,
    failing: bool,
}

struct MultiLogWriter {
    sinks: Vec<SinkState>,
}

impl Write for MultiLogWriter {
    /// Best-effort fan-out: every sink gets a chance at every record, so one
    /// failing sink neither starves the others nor causes the drop warning
    /// to be retried against (and spam) the healthy ones. `Err` is returned
    /// only when no sink accepted the record; per-sink failures are noted on
    /// stderr once per failure streak.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut delivered = false;
        let mut last_error = None;
        for state in &mut self.sinks {
            match state.sink.write_record(buf) {
                Ok(()) => {
                    state.failing = false;
                    delivered = true;
                }
                Err(e) => {
                    if !state.failing {
                        eprintln!(
                            "alighieri: log sink ({}) write failed: {e}",
                            state.sink.name()
                        );
                        state.failing = true;
                    }
                    last_error = Some(e);
                }
            }
        }
        if delivered {
            Ok(buf.len())
        } else {
            Err(last_error.unwrap_or_else(|| io::Error::other("no log sinks configured")))
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut flushed = false;
        let mut last_error = None;
        for state in &self.sinks {
            match state.sink.flush_sink() {
                Ok(()) => flushed = true,
                Err(e) => last_error = Some(e),
            }
        }
        if flushed {
            Ok(())
        } else {
            Err(last_error.unwrap_or_else(|| io::Error::other("no log sinks configured")))
        }
    }
}

#[derive(Clone)]
struct RotatingFileHandle {
    state: Arc<Mutex<RotatingFile>>,
}

impl RotatingFileHandle {
    fn open(path: impl Into<PathBuf>, max_bytes: u64, keep: usize) -> io::Result<Self> {
        Ok(Self {
            state: Arc::new(Mutex::new(RotatingFile::open(
                path.into(),
                max_bytes,
                keep,
            )?)),
        })
    }

    fn write_all(&self, buf: &[u8]) -> io::Result<()> {
        self.state
            .lock()
            .map_err(|_| io::Error::other("log file lock poisoned"))?
            .write_all(buf)
    }

    fn flush(&self) -> io::Result<()> {
        self.state
            .lock()
            .map_err(|_| io::Error::other("log file lock poisoned"))?
            .flush()
    }
}

struct RotatingFile {
    path: PathBuf,
    max_bytes: u64,
    keep: usize,
    file: Option<File>,
    len: u64,
}

impl RotatingFile {
    fn open(path: PathBuf, max_bytes: u64, keep: usize) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let len = file.metadata()?.len();
        Ok(Self {
            path,
            max_bytes,
            keep,
            file: Some(file),
            len,
        })
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        if self.should_rotate(buf.len() as u64) {
            self.rotate()?;
        }
        self.file_mut()?.write_all(buf)?;
        self.len = self.len.saturating_add(buf.len() as u64);
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file_mut()?.flush()
    }

    fn should_rotate(&self, incoming: u64) -> bool {
        self.max_bytes > 0 && self.len > 0 && self.len.saturating_add(incoming) > self.max_bytes
    }

    fn rotate(&mut self) -> io::Result<()> {
        if let Some(mut file) = self.file.take() {
            file.flush()?;
            file.sync_all()?;
        }

        if self.keep == 0 {
            remove_if_exists(&self.path)?;
        } else {
            remove_if_exists(&rotated_path(&self.path, self.keep))?;
            for index in (1..self.keep).rev() {
                let from = rotated_path(&self.path, index);
                let to = rotated_path(&self.path, index + 1);
                rename_if_exists(&from, &to)?;
            }
            rename_if_exists(&self.path, &rotated_path(&self.path, 1))?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        self.len = file.metadata()?.len();
        self.file = Some(file);
        Ok(())
    }

    fn file_mut(&mut self) -> io::Result<&mut File> {
        self.file
            .as_mut()
            .ok_or_else(|| io::Error::other("log file handle is closed"))
    }
}

fn rotated_path(path: &Path, index: usize) -> PathBuf {
    let file_name = path
        .file_name()
        .unwrap_or_else(|| OsStr::new("alighieri.log"));
    let mut rotated = OsString::from(file_name);
    rotated.push(format!(".{index}"));
    path.with_file_name(rotated)
}

fn remove_if_exists(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn rename_if_exists(from: &Path, to: &Path) -> io::Result<()> {
    match std::fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Resolves when the process receives an interrupt (Ctrl-C) or, on Unix, a
/// SIGTERM.
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn run_server_exits_when_shutdown_future_resolves() {
        let config = Config::parse(
            "internal: 127.0.0.1:0\nclient pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }\nsocks pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }",
        )
        .unwrap();

        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            run_server_until_shutdown(config, async {}),
        )
        .await
        .unwrap()
        .unwrap();
    }

    #[tokio::test]
    async fn reload_loop_keeps_running_after_invalid_reload() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("alighieri.conf");
        std::fs::write(
            &config_path,
            "internal: 127.0.0.1 port = 0\nclient pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }\nsocks pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }\n",
        )
        .unwrap();
        let server = Server::bind(Config::load(&config_path).unwrap())
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();

        let (reload_tx, reload_rx) = mpsc::unbounded_channel();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let run = tokio::spawn({
            let config_path = config_path.clone();
            async move {
                run_bound_server_reloading_until_shutdown(
                    server,
                    config_path,
                    async {
                        let _ = shutdown_rx.await;
                    },
                    reload_rx,
                )
                .await
            }
        });

        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if tokio::net::TcpStream::connect(addr).await.is_ok() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        std::fs::write(&config_path, "not-a-real-setting: nope\n").unwrap();
        reload_tx.send(()).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        if run.is_finished() {
            panic!("reload loop exited early: {:?}", run.await);
        }

        let _ = shutdown_tx.send(());
        tokio::time::timeout(std::time::Duration::from_secs(2), run)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn reload_loop_keeps_running_after_valid_reload() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("alighieri.conf");
        std::fs::write(
            &config_path,
            "internal: 127.0.0.1 port = 0\nclient pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }\nsocks pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }\n",
        )
        .unwrap();
        let server = Server::bind(Config::load(&config_path).unwrap())
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();

        let (reload_tx, reload_rx) = mpsc::unbounded_channel();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let run = tokio::spawn({
            let config_path = config_path.clone();
            async move {
                run_bound_server_reloading_until_shutdown(
                    server,
                    config_path,
                    async {
                        let _ = shutdown_rx.await;
                    },
                    reload_rx,
                )
                .await
            }
        });

        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if tokio::net::TcpStream::connect(addr).await.is_ok() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        // A valid reload exercises the success branch of the reload arm; the loop
        // must keep running.
        std::fs::write(
            &config_path,
            "internal: 127.0.0.1 port = 0\nhandshaketimeout: 9\nclient pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }\nsocks pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }\n",
        )
        .unwrap();
        reload_tx.send(()).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!run.is_finished(), "loop exited after a valid reload");

        let _ = shutdown_tx.send(());
        tokio::time::timeout(std::time::Duration::from_secs(2), run)
            .await
            .expect("driver did not stop after shutdown")
            .expect("driver task panicked")
            .expect("driver returned an error");
    }

    // A reload reads the config (and userlist) with blocking I/O. A wedged read
    // must not delay a stop: the config read is raced against shutdown, with
    // shutdown taking priority. Uses a reader-blocking FIFO as the config path.
    #[cfg(unix)]
    #[tokio::test]
    async fn shutdown_is_not_delayed_by_a_wedged_reload() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::OpenOptionsExt;

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("alighieri.conf");
        std::fs::write(
            &config_path,
            "internal: 127.0.0.1 port = 0\nclient pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }\nsocks pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }\n",
        )
        .unwrap();
        let server = Server::bind(Config::load(&config_path).unwrap())
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();

        let (reload_tx, reload_rx) = mpsc::unbounded_channel();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let run = tokio::spawn({
            let config_path = config_path.clone();
            async move {
                run_bound_server_reloading_until_shutdown(
                    server,
                    config_path,
                    async {
                        let _ = shutdown_rx.await;
                    },
                    reload_rx,
                )
                .await
            }
        });

        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if tokio::net::TcpStream::connect(addr).await.is_ok() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        // Replace the config with a FIFO that has no writer, so the reload's
        // config read blocks at open, then trigger the reload.
        std::fs::remove_file(&config_path).unwrap();
        let c_path = std::ffi::CString::new(config_path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        reload_tx.send(()).unwrap();

        // Synchronize rather than sleep: a non-blocking writer-open of the FIFO
        // succeeds only once the reload's `Config::load` is waiting at the open,
        // which deterministically confirms the wedged path is exercised before we
        // signal shutdown. Hold the writer open without writing, so the reader now
        // blocks at read and the reload stays wedged.
        let writer = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                match std::fs::OpenOptions::new()
                    .write(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open(&config_path)
                {
                    Ok(writer) => break writer,
                    // `ENXIO`: no reader yet — the reload has not reached the open.
                    Err(_) => tokio::time::sleep(std::time::Duration::from_millis(5)).await,
                }
            }
        })
        .await
        .expect("reload never reached the wedged config read");

        // Shutdown must still return promptly despite the wedged reload.
        let _ = shutdown_tx.send(());
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), run).await;

        // Closing the writer lets the wedged read see EOF and finish, so the
        // detached blocking task does not hang runtime teardown. Done regardless
        // of the assertion below so a failure does not leave a stuck thread.
        drop(writer);

        result
            .expect("shutdown was delayed behind the wedged reload")
            .expect("driver task panicked")
            .expect("driver returned an error");
    }

    #[test]
    fn rotating_file_keeps_bounded_history() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("alighieri.log");
        let mut file = RotatingFile::open(path.clone(), 10, 2).unwrap();

        file.write_all(b"first\n").unwrap();
        file.write_all(b"second\n").unwrap();
        file.write_all(b"third\n").unwrap();
        file.flush().unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "third\n");
        assert_eq!(
            std::fs::read_to_string(rotated_path(&path, 1)).unwrap(),
            "second\n"
        );
        assert_eq!(
            std::fs::read_to_string(rotated_path(&path, 2)).unwrap(),
            "first\n"
        );
        assert!(!rotated_path(&path, 3).exists());
    }

    #[test]
    fn rotating_file_can_discard_history() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("alighieri.log");
        let mut file = RotatingFile::open(path.clone(), 4, 0).unwrap();

        file.write_all(b"one\n").unwrap();
        file.write_all(b"two\n").unwrap();
        file.flush().unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "two\n");
        assert!(!rotated_path(&path, 1).exists());
    }

    #[derive(Clone)]
    struct SharedSink(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedSink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A sink that signals when a write starts and then blocks until the
    /// shared gate is released, to deterministically fill the log queue.
    struct GatedSink {
        entered: Arc<std::sync::atomic::AtomicBool>,
        gate: Arc<Mutex<()>>,
        out: SharedSink,
    }

    impl Write for GatedSink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.entered.store(true, Ordering::SeqCst);
            let _gate = self.gate.lock().unwrap();
            self.out.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn async_log_writer_delivers_records_in_order() {
        let out = Arc::new(Mutex::new(Vec::new()));
        let (writers, guard) =
            AsyncLogWriters::spawn(SharedSink(out.clone()), LOG_QUEUE_CAPACITY, LogFormat::Text)
                .unwrap();

        for record in [b"one\n".as_slice(), b"two\n", b"three\n"] {
            let mut handle = writers.make_writer();
            handle.write_all(record).unwrap();
        }
        drop(guard); // flushes and waits for the worker to drain

        assert_eq!(out.lock().unwrap().as_slice(), b"one\ntwo\nthree\n");
    }

    #[test]
    fn async_log_writer_drops_and_reports_when_queue_is_full() {
        let out = Arc::new(Mutex::new(Vec::new()));
        let entered = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let gate = Arc::new(Mutex::new(()));
        let sink = GatedSink {
            entered: entered.clone(),
            gate: gate.clone(),
            out: SharedSink(out.clone()),
        };
        let (writers, guard) = AsyncLogWriters::spawn(sink, 1, LogFormat::Text).unwrap();

        let blocker = gate.lock().unwrap();
        writers.make_writer().write_all(b"first\n").unwrap();
        // Wait until the worker is blocked inside the sink so the queue
        // state below is deterministic.
        while !entered.load(Ordering::SeqCst) {
            std::thread::yield_now();
        }
        writers.make_writer().write_all(b"second\n").unwrap(); // fills the queue
        writers.make_writer().write_all(b"third\n").unwrap(); // dropped
        assert_eq!(writers.dropped.load(Ordering::Relaxed), 1);
        drop(blocker);
        drop(guard);

        let written = String::from_utf8(out.lock().unwrap().clone()).unwrap();
        assert!(written.contains("first\n"));
        assert!(written.contains("dropped 1 log records under load (1 dropped in total)"));
        assert!(written.contains("second\n"));
        assert!(!written.contains("third\n"));
    }

    /// A sink that fails writes while the flag is set, then recovers.
    struct FlakySink {
        failing: Arc<std::sync::atomic::AtomicBool>,
        out: SharedSink,
    }

    impl Write for FlakySink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.failing.load(Ordering::SeqCst) {
                return Err(io::Error::other("sink unavailable"));
            }
            self.out.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn async_log_writer_counts_sink_write_failures_as_drops() {
        let out = Arc::new(Mutex::new(Vec::new()));
        let failing = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let sink = FlakySink {
            failing: failing.clone(),
            out: SharedSink(out.clone()),
        };
        let (writers, guard) =
            AsyncLogWriters::spawn(sink, LOG_QUEUE_CAPACITY, LogFormat::Text).unwrap();

        writers.make_writer().write_all(b"lost\n").unwrap();
        // Wait until the worker consumed the record and recorded the failure.
        while writers.dropped.load(Ordering::Relaxed) == 0 {
            std::thread::yield_now();
        }
        failing.store(false, Ordering::SeqCst);
        writers.make_writer().write_all(b"kept\n").unwrap();
        drop(guard);

        let written = String::from_utf8(out.lock().unwrap().clone()).unwrap();
        assert!(written.contains("dropped 1 log records under load (1 dropped in total)"));
        assert!(written.contains("kept\n"));
        assert!(!written.contains("lost\n"));
    }

    #[test]
    fn multi_sink_outage_neither_spams_nor_miscounts() {
        let healthy_out = Arc::new(Mutex::new(Vec::new()));
        let failing_out = Arc::new(Mutex::new(Vec::new()));
        let failing_flag = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let multi = MultiLogWriter {
            sinks: vec![
                SinkState {
                    sink: LogSink::Test(TestSink {
                        failing: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                        out: healthy_out.clone(),
                    }),
                    failing: false,
                },
                SinkState {
                    sink: LogSink::Test(TestSink {
                        failing: failing_flag.clone(),
                        out: failing_out.clone(),
                    }),
                    failing: false,
                },
            ],
        };
        let (writers, guard) =
            AsyncLogWriters::spawn(multi, LOG_QUEUE_CAPACITY, LogFormat::Text).unwrap();

        // A genuine queue drop happened earlier; the warning must reach the
        // healthy sink exactly once even though the other sink keeps failing.
        writers.dropped.fetch_add(1, Ordering::Relaxed);
        for record in [b"rec1\n".as_slice(), b"rec2\n", b"rec3\n"] {
            writers.make_writer().write_all(record).unwrap();
        }
        // Wait for the worker to process the burst before the sink recovers,
        // so rec1..3 deterministically hit the failing sink.
        while !String::from_utf8_lossy(&healthy_out.lock().unwrap()).contains("rec3") {
            std::thread::yield_now();
        }
        failing_flag.store(false, Ordering::SeqCst);
        writers.make_writer().write_all(b"rec4\n").unwrap();
        drop(guard);

        assert_eq!(writers.dropped.load(Ordering::Relaxed), 1);
        let healthy = String::from_utf8(healthy_out.lock().unwrap().clone()).unwrap();
        assert_eq!(healthy.matches("dropped 1 log records").count(), 1);
        for record in ["rec1\n", "rec2\n", "rec3\n", "rec4\n"] {
            assert!(healthy.contains(record));
        }
        let failed = String::from_utf8(failing_out.lock().unwrap().clone()).unwrap();
        assert!(failed.contains("rec4\n"));
        assert!(!failed.contains("rec1\n"));
    }

    #[test]
    fn async_log_writer_reports_drops_on_flush_without_further_records() {
        let out = Arc::new(Mutex::new(Vec::new()));
        let (writers, guard) =
            AsyncLogWriters::spawn(SharedSink(out.clone()), LOG_QUEUE_CAPACITY, LogFormat::Text)
                .unwrap();

        // Simulate records lost to a full queue with no subsequent traffic.
        writers.dropped.fetch_add(5, Ordering::Relaxed);
        drop(guard); // shutdown flush must still surface the drops

        let written = String::from_utf8(out.lock().unwrap().clone()).unwrap();
        assert!(written.contains("dropped 5 log records under load (5 dropped in total)"));
    }

    #[test]
    fn async_log_writer_reports_drops_as_json_when_configured() {
        let out = Arc::new(Mutex::new(Vec::new()));
        let (writers, guard) =
            AsyncLogWriters::spawn(SharedSink(out.clone()), LOG_QUEUE_CAPACITY, LogFormat::Json)
                .unwrap();

        writers.dropped.fetch_add(2, Ordering::Relaxed);
        drop(guard);

        let written = String::from_utf8(out.lock().unwrap().clone()).unwrap();
        let line = written.lines().next().unwrap();
        assert!(line.starts_with("{\"level\":\"WARN\""));
        assert!(line.contains("dropped 2 log records under load (2 dropped in total)"));
        assert!(line.ends_with('}'));
    }
}
