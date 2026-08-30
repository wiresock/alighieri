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
use crate::config::{LoadedIncludePattern, TlsConfig};
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
    reloads: mpsc::UnboundedReceiver<()>,
) -> Result<()>
where
    F: Future<Output = ()>,
{
    run_bound_server_reloading_until_shutdown_validated(
        server,
        config_path,
        shutdown,
        reloads,
        |_| Ok(()),
    )
    .await
}

/// Windows Service reload driver that keeps reloadable filesystem settings
/// disjoint from both the active startup log sink and the sink configured for
/// the next service restart.
#[cfg(windows)]
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub async fn run_bound_windows_service_reloading_until_shutdown<F>(
    server: Server,
    config_path: PathBuf,
    shutdown: F,
    reloads: mpsc::UnboundedReceiver<()>,
    active_log_path: PathBuf,
    active_log_rotate_keep: usize,
    default_log_dir: PathBuf,
    service_config_marker: PathBuf,
) -> Result<()>
where
    F: Future<Output = ()>,
{
    let validation_config_path = config_path.clone();
    run_bound_server_reloading_until_shutdown_validated(
        server,
        config_path,
        shutdown,
        reloads,
        move |config| {
            // Validate the family the next restart would select even when the
            // SCM control was sent directly instead of through `service reload`.
            validate_windows_service_logging_paths(
                config,
                &validation_config_path,
                &default_log_dir,
                &service_config_marker,
            )?;
            // Logging itself is not reloadable, so also guard reloadable paths
            // against the writer that this process continues to hold.
            validate_windows_service_active_log_paths(
                config,
                &validation_config_path,
                &active_log_path,
                active_log_rotate_keep,
                &service_config_marker,
            )
        },
    )
    .await
}

async fn run_bound_server_reloading_until_shutdown_validated<F, V>(
    server: Server,
    config_path: PathBuf,
    shutdown: F,
    mut reloads: mpsc::UnboundedReceiver<()>,
    validate_reload: V,
) -> Result<()>
where
    F: Future<Output = ()>,
    V: Fn(&Config) -> io::Result<()> + Send + Sync + 'static,
{
    let server = Arc::new(server);
    let run_server = server.clone();
    let mut run_task = tokio::spawn(async move { run_server.run().await });
    let mut reloads_closed = false;
    let validate_reload = Arc::new(validate_reload);
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
                        // so read it on a detached OS thread — not `spawn_blocking`:
                        // if shutdown preempts the reload, a wedged read keeps
                        // running, and a detached thread (unlike a blocking-pool
                        // task) does not hold up the runtime's shutdown, so the
                        // process still exits promptly. `server.reload` does its own
                        // blocking reads off-task. With `biased`, shutdown wins.
                        let reload = async {
                            let path = config_path.clone();
                            let validate_reload = validate_reload.clone();
                            let (tx, rx) = tokio::sync::oneshot::channel();
                            // `Builder::spawn` so a transient thread-creation
                            // failure (e.g. resource exhaustion) fails the reload
                            // gracefully instead of panicking the service.
                            if let Err(e) = std::thread::Builder::new()
                                .name("config-reload".into())
                                .spawn(move || {
                                    let result = Config::load(&path).and_then(|config| {
                                        validate_reload(&config).map_err(Error::Io)?;
                                        Ok(config)
                                    });
                                    let _ = tx.send(result);
                                })
                            {
                                error!(config = %config_path.display(), error = %e, "configuration reload failed: could not spawn config-reader thread; keeping active configuration");
                                return;
                            }
                            match rx.await {
                                Ok(Ok(config)) => {
                                    if let Err(e) = server.reload(config).await {
                                        error!(config = %config_path.display(), error = %e, "configuration reload failed; keeping active configuration");
                                    }
                                }
                                Ok(Err(e)) => {
                                    error!(config = %config_path.display(), error = %e, "configuration reload failed; keeping active configuration");
                                }
                                Err(_) => {
                                    error!(config = %config_path.display(), "configuration reload thread panicked; keeping active configuration");
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
#[doc(hidden)]
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

#[cfg(windows)]
#[doc(hidden)]
pub fn init_service_logging(
    config: &Config,
    config_path: &Path,
    default_log_dir: &Path,
    service_config_marker: &Path,
) -> io::Result<(PathBuf, LogGuard)> {
    let log_path = validate_windows_service_logging_paths(
        config,
        config_path,
        default_log_dir,
        service_config_marker,
    )?;
    if let Some(parent) = log_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    let writer = LogWriters::file(
        log_path.clone(),
        config.log_rotate_size,
        config.log_rotate_keep,
    )?;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let guard = init_logging(filter, writer, config.log_format, true)?;

    Ok((log_path, guard))
}

/// Resolves and validates the Windows Service log path before anything opens it.
///
/// Service logging owns the active file and all configured rotation targets. It
/// must never append to, rename, or remove another service artifact merely
/// because a syntactically valid configuration reused that path as `logfile`.
/// This check lives at the service boundary (rather than only in the wizard) so
/// imported and hand-written configurations receive the same protection.
#[cfg(windows)]
#[doc(hidden)]
pub fn validate_windows_service_logging_paths(
    config: &Config,
    config_path: &Path,
    default_log_dir: &Path,
    service_config_marker: &Path,
) -> io::Result<PathBuf> {
    let selected_log_path = windows_service_log_path(config, config_path, default_log_dir)?;
    windows_service_validate_path_spelling("Windows Service logfile", &selected_log_path)?;
    windows_service_reject_unresolved_reparse_points(
        "Windows Service logfile",
        &selected_log_path,
    )?;
    // Freeze any existing parent reparse points (and a final symlink, if
    // present) before opening the writer. Pinning the final file handle alone
    // cannot stop a junction earlier in the configured spelling from being
    // replaced while the service is running. Using this resolved path for both
    // validation and rotation keeps the family being checked identical to the
    // family the writer will actually own.
    let log_path = windows_service_normalized_path(&selected_log_path);
    validate_windows_service_active_log_paths(
        config,
        config_path,
        &log_path,
        config.log_rotate_keep,
        service_config_marker,
    )?;
    Ok(log_path)
}

/// Rejects reloadable service paths that overlap the log family already held
/// open by the running Windows Service process.
#[cfg(windows)]
#[doc(hidden)]
pub fn validate_windows_service_active_log_paths(
    config: &Config,
    config_path: &Path,
    active_log_path: &Path,
    active_log_rotate_keep: usize,
    service_config_marker: &Path,
) -> io::Result<()> {
    // `active_log_path` is the canonical path returned by service startup.
    // Canonical Windows paths may use an internal volume-GUID spelling even
    // when the operator supplied a normal drive path, so do not apply the
    // user-input spelling policy to it a second time.
    windows_service_validate_path_spelling("active configuration", config_path)?;
    windows_service_validate_path_spelling("service configuration marker", service_config_marker)?;
    let config_backup =
        windows_service_suffixed_sibling_path(config_path, "alighieri.conf", "", ".bak");
    windows_service_validate_path_spelling("active configuration backup", &config_backup)?;
    let mut protected_files = vec![
        (
            "active configuration",
            WindowsServiceComparablePath::new(config_path.to_path_buf()),
        ),
        (
            "active configuration backup",
            WindowsServiceComparablePath::new(config_backup),
        ),
        (
            "service configuration marker",
            WindowsServiceComparablePath::new(service_config_marker.to_path_buf()),
        ),
    ];
    // `Config::load` canonicalizes the entrypoint and every include. Keep those
    // resolved source identities in the protected set: an included fragment is
    // just as destructive to overwrite or rotate as the top-level file. The
    // top-level backup remains a separate, predictable artifact; includes are
    // never written by the service and therefore do not imply `.bak` files.
    for source_path in config.loaded_source_paths() {
        protected_files.push((
            "loaded configuration source",
            WindowsServiceComparablePath::new(source_path.clone()),
        ));
    }
    if let Some(userlist) = &config.userlist {
        windows_service_validate_path_spelling("configured userlist", userlist)?;
        let userlist_backup = windows_service_suffixed_sibling_path(userlist, "users", "", ".bak");
        let userlist_lock = windows_service_suffixed_sibling_path(userlist, "users", ".", ".lock");
        windows_service_validate_path_spelling("configured userlist backup", &userlist_backup)?;
        windows_service_validate_path_spelling("configured userlist lock", &userlist_lock)?;
        protected_files.push((
            "configured userlist",
            WindowsServiceComparablePath::new(userlist.clone()),
        ));
        protected_files.push((
            "configured userlist backup",
            WindowsServiceComparablePath::new(userlist_backup),
        ));
        protected_files.push((
            "configured userlist lock",
            WindowsServiceComparablePath::new(userlist_lock),
        ));
    }
    if let Some(program) = config
        .auth_command
        .as_ref()
        .and_then(|command| command.first())
    {
        let program_path = Path::new(program);
        let has_explicit_path = program_path.is_absolute()
            || program_path.components().count() > 1
            || program.contains('\\')
            || program.contains('/');
        if !has_explicit_path {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Windows Service auth.command program {program:?} must use an explicit filesystem path; bare program names resolved through Windows process search cannot be checked safely against logfile rotation targets"
                ),
            ));
        }
        for candidate in windows_service_auth_program_candidates(program_path) {
            windows_service_validate_path_spelling("external authentication command", &candidate)?;
            protected_files.push((
                "external authentication command",
                WindowsServiceComparablePath::new(candidate),
            ));
        }
    }
    if let Some(TlsConfig::Files {
        cert_file,
        key_file,
    }) = &config.tls
    {
        windows_service_validate_path_spelling("TLS certificate", cert_file)?;
        windows_service_validate_path_spelling("TLS private key", key_file)?;
        protected_files.push((
            "TLS certificate",
            WindowsServiceComparablePath::new(cert_file.clone()),
        ));
        protected_files.push((
            "TLS private key",
            WindowsServiceComparablePath::new(key_file.clone()),
        ));
    }

    let acme_cache = match &config.tls {
        Some(TlsConfig::Acme(acme)) => {
            windows_service_validate_path_spelling("ACME cache directory", &acme.cache_dir)?;
            Some(WindowsServiceComparablePath::new(acme.cache_dir.clone()))
        }
        _ => None,
    };
    let log_family = WindowsServiceLogFamily::new(active_log_path, active_log_rotate_keep);

    // A wildcard include is re-expanded on every reload. A logfile that does
    // not exist during the first load can therefore create a new matching
    // configuration source and make all later reloads parse log records as
    // config. Reserve every current and rotated family member that the pattern
    // would match, not only the files that happened to exist at startup.
    validate_windows_service_log_family_against_include_patterns(
        &log_family,
        config.loaded_include_patterns(),
        windows_service_log_candidate_label,
    )?;

    let existing_members = validate_windows_service_log_family_against_files(
        &log_family,
        &protected_files,
        windows_service_log_candidate_label,
    )?;

    // Loaded configuration sources are regular files, not directory trees. A
    // would-be logfile at or above one of them is necessarily a directory and
    // cannot be opened as the configured file; the inverse nesting is equally
    // impossible because the source file occupies an ancestor component. Run
    // this broader check after exact/hardlink comparisons so collisions with
    // the active entrypoint retain their more specific diagnostic.
    for source_path in config.loaded_source_paths() {
        let source = WindowsServiceComparablePath::new(source_path.clone());
        if let Some(index) = log_family.conflicting_tree_member(&source.normalized) {
            return Err(service_log_collision_error(
                windows_service_log_candidate_label(index),
                &log_family.candidate_path(index),
                "loaded configuration source",
                &source.path,
            ));
        }
    }

    if let Some(cache) = &acme_cache {
        // The ACME cache owns a directory tree. A log anywhere inside it can
        // collide with rustls-acme's current or future cache entries; making the
        // cache a child of a would-be log file is invalid for the same filesystem
        // reason.
        for candidate in &existing_members {
            if windows_service_normalized_path_is_same_or_descendant(
                &candidate.normalized,
                &cache.normalized,
            ) || windows_service_normalized_path_is_same_or_descendant(
                &cache.normalized,
                &candidate.normalized,
            ) {
                return Err(service_log_collision_error(
                    windows_service_log_candidate_label(candidate.index),
                    &candidate.path,
                    "ACME cache directory",
                    &cache.path,
                ));
            }
        }
        if let Some(index) = log_family.conflicting_tree_member(&cache.normalized) {
            return Err(service_log_collision_error(
                windows_service_log_candidate_label(index),
                &log_family.candidate_path(index),
                "ACME cache directory",
                &cache.path,
            ));
        }
    }

    Ok(())
}

#[cfg(windows)]
fn validate_windows_service_log_family_against_include_patterns(
    log_family: &WindowsServiceLogFamily,
    patterns: &[LoadedIncludePattern],
    candidate_label: fn(usize) -> &'static str,
) -> io::Result<()> {
    for pattern in patterns {
        let normalized_parent = windows_service_normalized_path(pattern.parent());
        // The include directory must remain a directory. A base/rotation path
        // at or above it would be opened as a file and make startup (or a later
        // rotation) deterministically fail. A logfile merely *inside* the same
        // directory remains valid and is handled by the filename match below.
        if let Some(index) = log_family.member_containing_path(&normalized_parent) {
            return Err(service_log_collision_error(
                candidate_label(index),
                &log_family.candidate_path(index),
                "configuration include directory",
                pattern.parent(),
            ));
        }
        if !windows_service_normalized_paths_equal(
            &log_family.normalized_rotation_parent,
            &normalized_parent,
        ) {
            continue;
        }
        for index in 0..=log_family.keep {
            let candidate = log_family.candidate_path(index);
            if candidate
                .file_name()
                .is_some_and(|file_name| pattern.matches_file_name(file_name))
            {
                return Err(service_log_collision_error(
                    candidate_label(index),
                    &candidate,
                    "configuration include pattern",
                    pattern.path(),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn validate_windows_service_log_family_against_files(
    log_family: &WindowsServiceLogFamily,
    protected_files: &[(&str, WindowsServiceComparablePath)],
    candidate_label: fn(usize) -> &'static str,
) -> io::Result<Vec<WindowsServiceExistingLogMember>> {
    // Lexical and canonical aliases can be classified directly from each
    // protected path's parent and file name; do not probe every possible `.N`.
    for (protected_label, protected_path) in protected_files {
        if let Some(index) = log_family.member_index(&protected_path.normalized) {
            return Err(service_log_collision_error(
                candidate_label(index),
                &log_family.candidate_path(index),
                protected_label,
                &protected_path.path,
            ));
        }
    }

    // A differently named existing hardlink cannot be found lexically. Enumerate
    // the one log directory and inspect only entries whose names belong to this
    // family, so `logrotate.keep: 10000` does not cause 10,001 failed opens.
    let existing_members = log_family.existing_members()?;
    for candidate in &existing_members {
        for (protected_label, protected_path) in protected_files {
            if protected_path.identity.zip(candidate.identity).is_some_and(
                |(protected_identity, candidate_identity)| protected_identity == candidate_identity,
            ) {
                return Err(service_log_collision_error(
                    candidate_label(candidate.index),
                    &candidate.path,
                    protected_label,
                    &protected_path.path,
                ));
            }
        }
    }
    Ok(existing_members)
}

#[cfg(windows)]
fn windows_service_suffixed_sibling_path(
    path: &Path,
    fallback_name: &str,
    prefix: &str,
    suffix: &str,
) -> PathBuf {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .unwrap_or_else(|| OsStr::new(fallback_name));
    let mut sibling = OsString::from(prefix);
    sibling.push(file_name);
    sibling.push(suffix);
    parent.join(sibling)
}

#[cfg(windows)]
fn windows_service_auth_program_candidates(program: &Path) -> Vec<PathBuf> {
    use std::os::windows::ffi::OsStrExt;

    let mut candidates = vec![program.to_path_buf()];
    let file_name = program
        .file_name()
        .unwrap_or(program.as_os_str())
        .encode_wide()
        .collect::<Vec<_>>();
    let exe_suffix = [b'.' as u16, b'e' as u16, b'x' as u16, b'e' as u16];
    let has_exe_suffix = file_name.len() >= exe_suffix.len()
        && windows_service_wide_strings_equal_case_insensitive(
            &file_name[file_name.len() - exe_suffix.len()..],
            &exe_suffix,
        );
    if !has_exe_suffix {
        // Rust's Windows process resolver tries this appended candidate first
        // for both bare extensions and names such as `verify.cmd`; if it does
        // not exist, it falls back to the literal spelling above. Protect both
        // so later file creation cannot turn a previously safe config unsafe.
        let mut appended = program.as_os_str().to_os_string();
        appended.push(".exe");
        candidates.push(PathBuf::from(appended));
    }
    candidates
}

#[cfg(windows)]
fn windows_service_validate_path_spelling(label: &str, path: &Path) -> io::Result<()> {
    use std::path::{Component, Prefix};

    let invalid = |detail: String| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} '{}' {detail}", path.display()),
        )
    };

    if path.has_root() && !path.is_absolute() {
        return Err(invalid(
            "must not use a root-relative Windows path; use a normal drive-letter or UNC path"
                .into(),
        ));
    }

    let mut verbatim = false;
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => match prefix.kind() {
                Prefix::Disk(_) if path.has_root() => {}
                Prefix::Disk(_) => {
                    return Err(invalid(
                        "must not use drive-relative syntax; use an ordinary relative path or a fully absolute path"
                            .into(),
                    ));
                }
                Prefix::UNC(server, share) => {
                    windows_service_validate_path_component(server, false, &invalid)?;
                    windows_service_validate_path_component(share, false, &invalid)?;
                }
                Prefix::VerbatimDisk(_) if path.has_root() => verbatim = true,
                Prefix::VerbatimDisk(_) => {
                    return Err(invalid(
                        "must not use drive-relative syntax; use a fully absolute path".into(),
                    ));
                }
                Prefix::VerbatimUNC(server, share) => {
                    windows_service_validate_path_component(server, false, &invalid)?;
                    windows_service_validate_path_component(share, false, &invalid)?;
                    verbatim = true;
                }
                Prefix::DeviceNS(_) | Prefix::Verbatim(_) => {
                    return Err(invalid(
                        "must use a drive-letter or UNC filesystem path".into(),
                    ));
                }
            },
            Component::Normal(value) => {
                windows_service_validate_path_component(value, true, &invalid)?
            }
            Component::CurDir | Component::ParentDir if verbatim => {
                return Err(invalid(
                    "must not contain '.' or '..' components in a verbatim Windows path".into(),
                ));
            }
            Component::RootDir | Component::CurDir | Component::ParentDir => {}
        }
    }
    Ok(())
}

/// Rejects a reparse component that cannot be resolved to a stable target.
///
/// A missing ordinary suffix is expected for a new logfile, but a dangling
/// symlink/junction must not be mistaken for one: path normalization would then
/// validate the link spelling while the eventual open either follows a newly
/// available target or fails at a surprising location.
#[cfg(windows)]
fn windows_service_reject_unresolved_reparse_points(label: &str, path: &Path) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt;
    use std::path::Component;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    let absolute = std::path::absolute(path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "cannot resolve {label} '{}' before checking Windows reparse points: {e}",
                path.display()
            ),
        )
    })?;
    let mut prefix = PathBuf::new();
    for component in absolute.components() {
        prefix.push(component.as_os_str());
        if !matches!(component, Component::Normal(_)) {
            continue;
        }
        let metadata = match std::fs::symlink_metadata(&prefix) {
            Ok(metadata) => metadata,
            // Once an ordinary component is absent, no later component can
            // exist (Win32 parent segments were already collapsed by
            // `absolute`), so the remaining suffix is safe to create normally.
            Err(e) if e.kind() == io::ErrorKind::NotFound => break,
            Err(e) => {
                return Err(io::Error::new(
                    e.kind(),
                    format!(
                        "cannot inspect {label} component '{}' for Windows reparse points: {e}",
                        prefix.display()
                    ),
                ))
            }
        };
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            if let Err(e) = std::fs::canonicalize(&prefix) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "{label} '{}' contains an unresolved Windows reparse point at '{}': {e}",
                        path.display(),
                        prefix.display()
                    ),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn windows_service_validate_path_component(
    value: &OsStr,
    reject_reserved_name: bool,
    invalid: &impl Fn(String) -> io::Error,
) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    let encoded = value.encode_wide().collect::<Vec<_>>();
    if encoded.is_empty() {
        return Err(invalid(
            "must not contain an empty UNC server or share name".into(),
        ));
    }
    const INVALID: [u16; 9] = [
        b'<' as u16,
        b'>' as u16,
        b':' as u16,
        b'"' as u16,
        b'|' as u16,
        b'?' as u16,
        b'*' as u16,
        b'/' as u16,
        b'\\' as u16,
    ];
    if encoded
        .iter()
        .any(|unit| *unit <= 31 || INVALID.contains(unit))
    {
        return Err(invalid(
            "contains a character that is not valid in a Windows file name".into(),
        ));
    }
    if encoded == [u16::from(b'.')] || encoded == [u16::from(b'.'), u16::from(b'.')] {
        return Err(invalid(
            "must not contain '.' or '..' components in a verbatim Windows path".into(),
        ));
    }
    if matches!(encoded.last(), Some(unit) if *unit == u16::from(b'.') || *unit == u16::from(b' '))
    {
        return Err(invalid(
            "must not contain a Windows path component ending in a dot or space".into(),
        ));
    }

    let name = String::from_utf16_lossy(&encoded);
    let base = name.split('.').next().unwrap_or("").to_uppercase();
    let reserved = matches!(
        base.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || ["COM", "LPT"].iter().any(|prefix| {
        base.strip_prefix(prefix).is_some_and(|suffix| {
            matches!(
                suffix,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
    });
    if reject_reserved_name && reserved {
        return Err(invalid(format!(
            "must not use the reserved Windows device name '{base}'"
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn service_log_collision_error(
    log_label: &str,
    log_path: &Path,
    protected_label: &str,
    protected_path: &Path,
) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "{log_label} '{}' conflicts with the {protected_label} '{}'; choose a separate logfile whose rotation files do not overlap service-owned paths",
            log_path.display(),
            protected_path.display()
        ),
    )
}

#[cfg(windows)]
fn windows_service_log_path(
    config: &Config,
    config_path: &Path,
    default_log_dir: &Path,
) -> io::Result<PathBuf> {
    let default_log_path = || default_log_dir.join("alighieri.log");

    if !config.uses_file_logging() {
        return Ok(default_log_path());
    }

    let Some(configured_path) = config.log_file.as_deref() else {
        return Ok(default_log_path());
    };
    if configured_path.is_absolute() {
        return Ok(configured_path.to_path_buf());
    }
    let has_prefix = configured_path
        .components()
        .next()
        .is_some_and(|component| matches!(component, std::path::Component::Prefix(_)));
    if configured_path.has_root() || has_prefix {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "service logfile path '{}' is anchored but not fully absolute; use a fully absolute path or an ordinary relative path (resolved against the configuration file directory)",
                configured_path.display()
            ),
        ));
    }

    // Services do not have a stable working directory (SCM normally starts
    // them in System32), so resolve explicit relative paths beside the config.
    Ok(config_path
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .join(configured_path))
}

#[cfg(windows)]
struct WindowsServiceComparablePath {
    path: PathBuf,
    normalized: PathBuf,
    identity: Option<(u64, [u8; 16])>,
}

#[cfg(windows)]
impl WindowsServiceComparablePath {
    fn new(path: PathBuf) -> Self {
        let normalized = windows_service_normalized_path(&path);
        let identity = windows_service_file_identity(&path);
        Self {
            path,
            normalized,
            identity,
        }
    }
}

#[cfg(windows)]
struct WindowsServiceLogFamily {
    base_path: PathBuf,
    normalized_base: PathBuf,
    normalized_rotation_parent: PathBuf,
    base_file_name: OsString,
    keep: usize,
}

#[cfg(windows)]
struct WindowsServiceExistingLogMember {
    index: usize,
    path: PathBuf,
    normalized: PathBuf,
    identity: Option<(u64, [u8; 16])>,
}

#[cfg(windows)]
impl WindowsServiceLogFamily {
    fn new(base_path: &Path, keep: usize) -> Self {
        let normalized_base = windows_service_normalized_path(base_path);
        let normalized_rotation_parent = windows_service_normalized_path(
            rotated_path(base_path, 1)
                .parent()
                .unwrap_or_else(|| Path::new(".")),
        );
        let base_file_name = base_path
            .file_name()
            .unwrap_or_else(|| OsStr::new("alighieri.log"))
            .to_os_string();
        Self {
            base_path: base_path.to_path_buf(),
            normalized_base,
            normalized_rotation_parent,
            base_file_name,
            keep,
        }
    }

    fn candidate_path(&self, index: usize) -> PathBuf {
        if index == 0 {
            self.base_path.clone()
        } else {
            rotated_path(&self.base_path, index)
        }
    }

    fn member_index(&self, normalized_path: &Path) -> Option<usize> {
        if windows_service_normalized_paths_equal(normalized_path, &self.normalized_base) {
            return Some(0);
        }
        let parent = normalized_path.parent()?;
        if !windows_service_normalized_paths_equal(parent, &self.normalized_rotation_parent) {
            return None;
        }
        let index = windows_service_log_file_name_index(
            &self.base_file_name,
            normalized_path.file_name()?,
            self.keep,
        )?;
        // Index zero is the base itself; a different normalized path that merely
        // has the same leaf is not that base (notably the root-path fallback).
        (index != 0).then_some(index)
    }

    /// Returns the family member that equals or is an ancestor of `path`.
    /// Unlike `conflicting_tree_member`, this is intentionally one-way so an
    /// ordinary logfile inside an include/cache directory is not classified as
    /// containing that directory.
    fn member_containing_path(&self, normalized_path: &Path) -> Option<usize> {
        if windows_service_normalized_path_is_same_or_descendant(
            normalized_path,
            &self.normalized_base,
        ) {
            return Some(0);
        }
        if self.keep == 0
            || !windows_service_normalized_path_is_same_or_descendant(
                normalized_path,
                &self.normalized_rotation_parent,
            )
        {
            return None;
        }

        let parent_components = self.normalized_rotation_parent.components().count();
        let first_relative = normalized_path.components().nth(parent_components)?;
        windows_service_log_file_name_index(
            &self.base_file_name,
            first_relative.as_os_str(),
            self.keep,
        )
        .filter(|index| *index != 0)
    }

    fn existing_members(&self) -> io::Result<Vec<WindowsServiceExistingLogMember>> {
        let entries = match std::fs::read_dir(&self.normalized_rotation_parent) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut members = Vec::new();
        for entry in entries {
            let entry = entry?;
            let Some(index) = windows_service_log_file_name_index(
                &self.base_file_name,
                &entry.file_name(),
                self.keep,
            ) else {
                continue;
            };
            let path = entry.path();
            if index == 0
                && !windows_service_normalized_paths_equal(
                    &windows_service_normalized_path(&path),
                    &self.normalized_base,
                )
            {
                continue;
            }
            members.push(WindowsServiceExistingLogMember {
                index,
                normalized: windows_service_normalized_path(&path),
                identity: windows_service_file_identity(&path),
                path,
            });
        }
        Ok(members)
    }

    fn conflicting_tree_member(&self, normalized_tree: &Path) -> Option<usize> {
        if windows_service_normalized_path_is_same_or_descendant(
            &self.normalized_base,
            normalized_tree,
        ) || windows_service_normalized_path_is_same_or_descendant(
            normalized_tree,
            &self.normalized_base,
        ) {
            return Some(0);
        }
        if self.keep == 0 {
            return None;
        }

        // Every rotation is an immediate child of this one parent. If that parent
        // is within the cache, the first rotation is already a conflict.
        if windows_service_normalized_path_is_same_or_descendant(
            &self.normalized_rotation_parent,
            normalized_tree,
        ) {
            return Some(1);
        }
        if !windows_service_normalized_path_is_same_or_descendant(
            normalized_tree,
            &self.normalized_rotation_parent,
        ) {
            return None;
        }

        // The cache is below the rotation parent. Its first relative component
        // names the only possible rotation that can equal or contain it.
        let parent_components = self.normalized_rotation_parent.components().count();
        let first_relative = normalized_tree.components().nth(parent_components)?;
        windows_service_log_file_name_index(
            &self.base_file_name,
            first_relative.as_os_str(),
            self.keep,
        )
        .filter(|index| *index != 0)
    }
}

#[cfg(windows)]
fn windows_service_log_candidate_label(index: usize) -> &'static str {
    if index == 0 {
        "Windows Service logfile"
    } else {
        "Windows Service rotated logfile"
    }
}

#[cfg(windows)]
fn windows_service_log_file_name_index(
    base: &OsStr,
    candidate: &OsStr,
    keep: usize,
) -> Option<usize> {
    use std::os::windows::ffi::OsStrExt;

    let base: Vec<u16> = base.encode_wide().collect();
    let candidate: Vec<u16> = candidate.encode_wide().collect();
    if candidate.len() == base.len()
        && windows_service_wide_strings_equal_case_insensitive(&base, &candidate)
    {
        return Some(0);
    }
    if candidate.len() <= base.len() + 1
        || candidate[base.len()] != u16::from(b'.')
        || !windows_service_wide_strings_equal_case_insensitive(&base, &candidate[..base.len()])
    {
        return None;
    }

    let digits = &candidate[base.len() + 1..];
    if digits.first() == Some(&u16::from(b'0')) {
        return None;
    }
    let mut index = 0usize;
    for digit in digits {
        let digit = u8::try_from(*digit).ok()?;
        if !digit.is_ascii_digit() {
            return None;
        }
        index = index
            .checked_mul(10)?
            .checked_add(usize::from(digit - b'0'))?;
    }
    (index >= 1 && index <= keep).then_some(index)
}

#[cfg(windows)]
fn windows_service_normalized_paths_equal(left: &Path, right: &Path) -> bool {
    windows_service_os_strings_equal_case_insensitive(left.as_os_str(), right.as_os_str())
}

#[cfg(windows)]
fn windows_service_file_identity(path: &Path) -> Option<(u64, [u8; 16])> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FileIdInfo, GetFileInformationByHandleEx, FILE_FLAG_BACKUP_SEMANTICS, FILE_ID_INFO,
        FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let file = std::fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .ok()?;
    let mut information = FILE_ID_INFO::default();
    let information_size = u32::try_from(std::mem::size_of::<FILE_ID_INFO>()).ok()?;
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            (&mut information as *mut FILE_ID_INFO).cast(),
            information_size,
        )
    } == 0
    {
        return None;
    }
    Some((
        information.VolumeSerialNumber,
        information.FileId.Identifier,
    ))
}

#[cfg(windows)]
fn windows_service_os_strings_equal_case_insensitive(left: &OsStr, right: &OsStr) -> bool {
    use std::os::windows::ffi::OsStrExt;

    let left: Vec<u16> = left.encode_wide().collect();
    let right: Vec<u16> = right.encode_wide().collect();
    windows_service_wide_strings_equal_case_insensitive(&left, &right)
}

#[cfg(windows)]
fn windows_service_wide_strings_equal_case_insensitive(left: &[u16], right: &[u16]) -> bool {
    use windows_sys::Win32::Globalization::{CompareStringOrdinal, CSTR_EQUAL};

    let (Ok(left_len), Ok(right_len)) = (i32::try_from(left.len()), i32::try_from(right.len()))
    else {
        return false;
    };
    unsafe {
        CompareStringOrdinal(left.as_ptr(), left_len, right.as_ptr(), right_len, 1) == CSTR_EQUAL
    }
}

#[cfg(windows)]
fn windows_service_normalized_path(path: &Path) -> PathBuf {
    // `std::path::absolute` uses Win32 full-path normalization on Windows. Do
    // this before following any reparse point: ordinary Win32 I/O collapses
    // `junction\..` lexically, whereas resolving the junction first and then
    // popping a target component describes a different file.
    let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    if let Ok(canonical) = std::fs::canonicalize(&absolute) {
        return canonical;
    }

    // The final target is commonly absent during installation. Canonicalize the
    // longest existing prefix (so real parent junctions are still resolved),
    // then append the missing suffix after Win32 lexical normalization.
    let mut prefix = absolute.as_path();
    let mut suffix = Vec::<OsString>::new();
    while let Some(file_name) = prefix.file_name() {
        suffix.push(file_name.to_os_string());
        let Some(parent) = prefix.parent() else {
            break;
        };
        prefix = parent;
        if let Ok(mut canonical) = std::fs::canonicalize(prefix) {
            for component in suffix.iter().rev() {
                canonical.push(component);
            }
            return canonical;
        }
    }
    absolute
}

#[cfg(windows)]
fn windows_service_normalized_path_is_same_or_descendant(path: &Path, ancestor: &Path) -> bool {
    let mut path_components = path.components();
    ancestor.components().all(|ancestor_component| {
        path_components.next().is_some_and(|path_component| {
            windows_service_os_strings_equal_case_insensitive(
                path_component.as_os_str(),
                ancestor_component.as_os_str(),
            )
        })
    })
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
#[doc(hidden)]
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
            sinks: vec![LogSink::File(RotatingFileHandle::open_pinned(
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

    #[cfg(windows)]
    fn open_pinned(path: impl Into<PathBuf>, max_bytes: u64, keep: usize) -> io::Result<Self> {
        Ok(Self {
            state: Arc::new(Mutex::new(RotatingFile::open_pinned(
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
    pin_path: bool,
}

impl RotatingFile {
    fn open(path: PathBuf, max_bytes: u64, keep: usize) -> io::Result<Self> {
        Self::open_with_path_pinning(path, max_bytes, keep, false)
    }

    #[cfg(windows)]
    fn open_pinned(path: PathBuf, max_bytes: u64, keep: usize) -> io::Result<Self> {
        Self::open_with_path_pinning(path, max_bytes, keep, true)
    }

    fn open_with_path_pinning(
        path: PathBuf,
        max_bytes: u64,
        keep: usize,
        pin_path: bool,
    ) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let file = open_rotating_log_file(&path, pin_path)?;
        let len = file.metadata()?.len();
        Ok(Self {
            path,
            max_bytes,
            keep,
            file: Some(file),
            len,
            pin_path,
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

        let file = open_rotating_log_file(&self.path, self.pin_path)?;
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

fn open_rotating_log_file(path: &Path, _pin_path: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};

        if _pin_path {
            // The service reload validator guards the path family held by this
            // writer. Pin the active name to that handle: Windows otherwise
            // permits an open log to be renamed away and replaced, making a
            // pathname-based reload check inspect a different file while this
            // handle keeps writing the renamed one. Our own rotation closes the
            // handle before renaming. Console logging keeps the standard delete
            // sharing behavior so external rotation remains supported there.
            options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
        }
    }
    options.open(path)
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

    #[cfg(windows)]
    fn windows_file_logging_config(log_file: PathBuf, rotate_keep: usize) -> Config {
        let mut config = Config::parse("internal: 127.0.0.1:1080").unwrap();
        config.log_outputs = vec![LogOutput::File];
        config.log_file = Some(log_file);
        config.log_rotate_keep = rotate_keep;
        config
    }

    #[cfg(windows)]
    fn create_windows_junction(link: &Path, target: &Path) {
        let output = std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "mklink", "/j"])
            .arg(link)
            .arg(target)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "failed to create junction: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_service_resolves_configured_logfiles_from_a_stable_base() {
        let default_dir = PathBuf::from(r"C:\ProgramData\Alighieri\logs");
        let config_path = PathBuf::from(r"C:\ProgramData\Alighieri\alighieri.conf");
        let custom_log = PathBuf::from(r"D:\Alighieri Data\proxy.log");
        let mut config = Config::parse("internal: 127.0.0.1:1080").unwrap();
        let default_log = default_dir.join("alighieri.log");

        assert_eq!(
            windows_service_log_path(&config, &config_path, &default_dir).unwrap(),
            default_log
        );

        config.log_outputs = vec![LogOutput::File];
        config.log_file = Some(custom_log.clone());
        assert_eq!(
            windows_service_log_path(&config, &config_path, &default_dir).unwrap(),
            custom_log
        );

        config.log_file = Some(PathBuf::from(r"logs\custom.log"));
        assert_eq!(
            windows_service_log_path(&config, &config_path, &default_dir).unwrap(),
            PathBuf::from(r"C:\ProgramData\Alighieri\logs\custom.log")
        );

        config.log_file = Some(PathBuf::from(r"..\shared-logs\custom.log"));
        assert_eq!(
            windows_service_log_path(&config, &config_path, &default_dir).unwrap(),
            PathBuf::from(r"C:\ProgramData\Alighieri\..\shared-logs\custom.log")
        );

        for ambiguous_path in [r"D:logs\custom.log", r"\logs\custom.log"] {
            config.log_file = Some(PathBuf::from(ambiguous_path));
            let error = windows_service_log_path(&config, &config_path, &default_dir).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(error
                .to_string()
                .contains("anchored but not fully absolute"));
            assert!(error.to_string().contains("ordinary relative path"));
            assert!(error.to_string().contains("configuration file directory"));
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_service_rejects_primary_and_rotated_log_collisions() {
        let dir = tempfile::tempdir().unwrap();
        let default_log_dir = dir.path().join("default-logs");

        for (role_index, protected_label) in [
            "active configuration",
            "configured userlist",
            "service configuration marker",
        ]
        .into_iter()
        .enumerate()
        {
            for rotated in [false, true] {
                let stem = format!("role-{role_index}-rotated-{rotated}");
                let log_path = dir.path().join(format!("{stem}.log"));
                let protected_path = if rotated {
                    rotated_path(&log_path, 1)
                } else {
                    log_path.clone()
                };
                let mut config_path = dir.path().join(format!("{stem}.conf"));
                let mut marker_path = dir.path().join(format!("{stem}.marker"));
                let mut config = windows_file_logging_config(log_path, usize::from(rotated));

                match protected_label {
                    "active configuration" => config_path = protected_path,
                    "configured userlist" => config.userlist = Some(protected_path),
                    "service configuration marker" => marker_path = protected_path,
                    _ => unreachable!(),
                }

                let error = validate_windows_service_logging_paths(
                    &config,
                    &config_path,
                    &default_log_dir,
                    &marker_path,
                )
                .unwrap_err();
                let message = error.to_string();
                assert!(message.contains(protected_label), "{message}");
                if rotated {
                    assert!(message.contains("rotated logfile"), "{message}");
                } else {
                    assert!(message.contains("Service logfile"), "{message}");
                }
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_service_rejects_predictable_config_and_userlist_sidecars() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("alighieri.conf");
        let marker_path = dir.path().join("service-config-path.txt");
        let userlist = dir.path().join("users");
        let protected_sidecars = [
            (
                "active configuration backup",
                windows_service_suffixed_sibling_path(&config_path, "alighieri.conf", "", ".bak"),
            ),
            (
                "configured userlist backup",
                windows_service_suffixed_sibling_path(&userlist, "users", "", ".bak"),
            ),
            (
                "configured userlist lock",
                windows_service_suffixed_sibling_path(&userlist, "users", ".", ".lock"),
            ),
        ];

        for (label, sidecar) in protected_sidecars {
            let mut config = windows_file_logging_config(sidecar, 1);
            config.userlist = Some(userlist.clone());

            let error = validate_windows_service_logging_paths(
                &config,
                &config_path,
                &dir.path().join("logs"),
                &marker_path,
            )
            .unwrap_err();

            assert!(error.to_string().contains(label), "{label}: {error}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_service_protects_every_loaded_configuration_source() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("alighieri.conf");
        let included_path = dir.path().join("policy.conf");
        let marker_path = dir.path().join("service-config-path.txt");
        std::fs::write(
            &config_path,
            "internal: 127.0.0.1:1080\ninclude: policy.conf\n",
        )
        .unwrap();
        std::fs::write(
            &included_path,
            format!("logoutput: file\nlogfile: {}\n", included_path.display()),
        )
        .unwrap();
        let config = Config::load(&config_path).unwrap();

        let error = validate_windows_service_logging_paths(
            &config,
            &config_path,
            &dir.path().join("logs"),
            &marker_path,
        )
        .unwrap_err();

        assert!(
            error.to_string().contains("loaded configuration source"),
            "{error}"
        );

        // Includes are read-only inputs. Only the active top-level config has
        // a predictable wizard `.bak` sibling that logging must reserve.
        let included_backup =
            windows_service_suffixed_sibling_path(&included_path, "policy.conf", "", ".bak");
        std::fs::write(
            &included_path,
            format!("logoutput: file\nlogfile: {}\n", included_backup.display()),
        )
        .unwrap();
        let config = Config::load(&config_path).unwrap();
        validate_windows_service_logging_paths(
            &config,
            &config_path,
            &dir.path().join("logs"),
            &marker_path,
        )
        .unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_service_rejects_log_members_that_contain_configuration_sources() {
        for rotation_index in [0, 1] {
            let dir = tempfile::tempdir().unwrap();
            let config_path = dir.path().join("alighieri.conf");
            let marker_path = dir.path().join("service-config-path.txt");
            let log_path = dir.path().join("service.log");
            let containing_member = if rotation_index == 0 {
                log_path.clone()
            } else {
                rotated_path(&log_path, rotation_index)
            };
            std::fs::create_dir(&containing_member).unwrap();
            let included_path = containing_member.join("policy.conf");
            std::fs::write(&included_path, "socks pass { command: connect }\n").unwrap();
            std::fs::write(
                &config_path,
                format!(
                    "internal: 127.0.0.1:1080\ninclude: {}\nlogoutput: file\nlogfile: {}\nlogrotate.keep: 1\n",
                    included_path.display(),
                    log_path.display()
                ),
            )
            .unwrap();
            let config = Config::load(&config_path).unwrap();

            let error = validate_windows_service_logging_paths(
                &config,
                &config_path,
                &dir.path().join("default-logs"),
                &marker_path,
            )
            .unwrap_err();

            assert!(
                error.to_string().contains("loaded configuration source"),
                "rotation {rotation_index}: {error}"
            );
            if rotation_index == 1 {
                assert!(
                    error.to_string().contains("rotated logfile"),
                    "rotation {rotation_index}: {error}"
                );
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_service_reserves_future_wildcard_include_matches() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("alighieri.conf");
        let marker_path = dir.path().join("service-config-path.txt");
        let fragments = dir.path().join("conf.d");
        std::fs::create_dir(&fragments).unwrap();

        let future_source = fragments.join("runtime.conf");
        std::fs::write(
            &config_path,
            format!(
                "internal: 127.0.0.1:1080\ninclude: conf.d/*.conf\nlogoutput: file\nlogfile: {}\n",
                future_source.display()
            ),
        )
        .unwrap();
        std::fs::write(fragments.join("policy.conf"), "socks pass { }\n").unwrap();
        let config = Config::load(&config_path).unwrap();
        let error = validate_windows_service_logging_paths(
            &config,
            &config_path,
            &dir.path().join("default-logs"),
            &marker_path,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("configuration include pattern"),
            "{error}"
        );

        let rotated_base = fragments.join("runtime.conf");
        std::fs::write(
            &config_path,
            format!(
                "internal: 127.0.0.1:1080\ninclude: conf.d/*.conf.1\nlogoutput: file\nlogfile: {}\nlogrotate.keep: 1\n",
                rotated_base.display()
            ),
        )
        .unwrap();
        std::fs::write(fragments.join("policy.conf.1"), "socks pass { }\n").unwrap();
        let config = Config::load(&config_path).unwrap();
        let error = validate_windows_service_logging_paths(
            &config,
            &config_path,
            &dir.path().join("default-logs"),
            &marker_path,
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("configuration include pattern"),
            "{message}"
        );
        assert!(message.contains("rotated logfile"), "{message}");
    }

    #[cfg(windows)]
    #[test]
    fn windows_service_requires_and_protects_explicit_auth_command_paths() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("alighieri.conf");
        let marker_path = dir.path().join("service-config-path.txt");
        let default_log_dir = dir.path().join("logs");

        for rotation_index in [0, 1] {
            let log_path = dir.path().join(format!("auth-{rotation_index}.log"));
            let program_path = if rotation_index == 0 {
                log_path.clone()
            } else {
                rotated_path(&log_path, rotation_index)
            };
            let mut config = windows_file_logging_config(log_path, 1);
            config.auth_command = Some(vec![program_path.display().to_string()]);

            let error = validate_windows_service_logging_paths(
                &config,
                &config_path,
                &default_log_dir,
                &marker_path,
            )
            .unwrap_err();

            assert!(
                error
                    .to_string()
                    .contains("external authentication command"),
                "rotation {rotation_index}: {error}"
            );
        }

        for program_name in ["verify-credentials", "verify-credentials.cmd"] {
            let program_path = dir.path().join(program_name);
            let mut effective_executable = program_path.as_os_str().to_os_string();
            effective_executable.push(".exe");
            let effective_executable = PathBuf::from(effective_executable);
            let mut config = windows_file_logging_config(effective_executable, 1);
            config.auth_command = Some(vec![program_path.display().to_string()]);

            let error = validate_windows_service_logging_paths(
                &config,
                &config_path,
                &default_log_dir,
                &marker_path,
            )
            .unwrap_err();

            assert!(
                error
                    .to_string()
                    .contains("external authentication command"),
                "{program_name}: {error}"
            );
        }

        let mut bare = windows_file_logging_config(dir.path().join("service.log"), 1);
        bare.auth_command = Some(vec!["verify-credentials.exe".into()]);
        let error = validate_windows_service_logging_paths(
            &bare,
            &config_path,
            &default_log_dir,
            &marker_path,
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("must use an explicit filesystem path"),
            "{message}"
        );
        assert!(message.contains("Windows process search"), "{message}");
    }

    #[cfg(windows)]
    #[test]
    fn windows_service_collision_matching_handles_case_and_missing_tail_parent_segments() {
        let dir = tempfile::tempdir().unwrap();
        let marker_path = dir.path().join("service-config-path.txt");
        let default_log_dir = dir.path().join("default-logs");

        let case_log = dir.path().join("ALIGHIERI.CONF");
        let case_config = dir.path().join("alighieri.conf");
        let config = windows_file_logging_config(case_log, 1);
        let error = validate_windows_service_logging_paths(
            &config,
            &case_config,
            &default_log_dir,
            &marker_path,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("active configuration"),
            "{error}"
        );

        // The nonexistent component prevents whole-path canonicalization, so
        // collision matching must still fold the following `..` lexically.
        let parent_log = dir
            .path()
            .join("missing-tail")
            .join("..")
            .join("alighieri.conf");
        let config = windows_file_logging_config(parent_log, 1);
        let error = validate_windows_service_logging_paths(
            &config,
            &case_config,
            &default_log_dir,
            &marker_path,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("active configuration"),
            "{error}"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_service_normalizes_parent_segments_before_following_junctions() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("other").join("nested");
        std::fs::create_dir_all(&target).unwrap();
        let junction = dir.path().join("alias");
        create_windows_junction(&junction, &target);
        let config_path = dir.path().join("alighieri.conf");
        std::fs::write(&config_path, "configuration").unwrap();
        let aliased_log = junction.join("..").join("alighieri.conf");

        // This assertion documents the Win32 behavior under test: ordinary
        // paths collapse `alias\..` before traversing the junction.
        assert_eq!(
            std::fs::canonicalize(&aliased_log).unwrap(),
            std::fs::canonicalize(&config_path).unwrap()
        );
        let config = windows_file_logging_config(aliased_log, 1);
        let error = validate_windows_service_logging_paths(
            &config,
            &config_path,
            &dir.path().join("logs"),
            &dir.path().join("service-config-path.txt"),
        )
        .unwrap_err();

        assert!(
            error.to_string().contains("active configuration"),
            "{error}"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_service_freezes_log_parent_junction_before_open_and_reload() {
        let dir = tempfile::tempdir().unwrap();
        let first_target = dir.path().join("first-target");
        let second_target = dir.path().join("second-target");
        std::fs::create_dir_all(&first_target).unwrap();
        std::fs::create_dir_all(&second_target).unwrap();
        let junction = dir.path().join("logs");
        create_windows_junction(&junction, &first_target);
        let selected_log = junction.join("active.log");
        let config_path = dir.path().join("alighieri.conf");
        let marker_path = dir.path().join("service-config-path.txt");
        let config = windows_file_logging_config(selected_log, 1);

        let active_log = validate_windows_service_logging_paths(
            &config,
            &config_path,
            &dir.path().join("default-logs"),
            &marker_path,
        )
        .unwrap();
        assert_eq!(
            active_log.parent().unwrap(),
            std::fs::canonicalize(&first_target).unwrap()
        );
        let mut writer = RotatingFile::open_pinned(active_log.clone(), 4, 1).unwrap();

        // Repointing the original configured junction must not redirect writes
        // or make reload validation forget the family held by this process.
        std::fs::remove_dir(&junction).unwrap();
        create_windows_junction(&junction, &second_target);
        writer.write_all(b"one\n").unwrap();
        writer.write_all(b"two\n").unwrap();
        writer.flush().unwrap();

        assert_eq!(
            std::fs::read_to_string(first_target.join("active.log")).unwrap(),
            "two\n"
        );
        assert_eq!(
            std::fs::read_to_string(first_target.join("active.log.1")).unwrap(),
            "one\n"
        );
        assert!(!second_target.join("active.log").exists());

        let mut reloaded = windows_file_logging_config(second_target.join("after-restart.log"), 1);
        reloaded.userlist = Some(first_target.join("active.log"));
        let error = validate_windows_service_active_log_paths(
            &reloaded,
            &config_path,
            &active_log,
            1,
            &marker_path,
        )
        .unwrap_err();
        assert!(error.to_string().contains("configured userlist"), "{error}");
    }

    #[cfg(windows)]
    #[test]
    fn windows_service_rejects_unresolved_log_reparse_points() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("alighieri.conf");
        let marker_path = dir.path().join("service-config-path.txt");
        let default_log_dir = dir.path().join("default-logs");

        let dangling_target = dir.path().join("missing-target.log");
        let file_link = dir.path().join("file-link.log");
        if std::os::windows::fs::symlink_file(&dangling_target, &file_link).is_ok() {
            let config = windows_file_logging_config(file_link.clone(), 1);
            let error = validate_windows_service_logging_paths(
                &config,
                &config_path,
                &default_log_dir,
                &marker_path,
            )
            .unwrap_err();
            let message = error.to_string();
            assert!(
                message.contains("unresolved Windows reparse point"),
                "{message}"
            );
            assert!(
                message.contains(&file_link.display().to_string()),
                "{message}"
            );
            std::fs::remove_file(&file_link).unwrap();
        } else {
            eprintln!("skipping dangling file-symlink assertion: symlinks are unavailable");
        }

        let target_dir = dir.path().join("junction-target");
        std::fs::create_dir(&target_dir).unwrap();
        let junction = dir.path().join("junction");
        create_windows_junction(&junction, &target_dir);
        std::fs::remove_dir(&target_dir).unwrap();
        let configured_log = junction.join("service.log");
        let config = windows_file_logging_config(configured_log.clone(), 1);
        let error = validate_windows_service_logging_paths(
            &config,
            &config_path,
            &default_log_dir,
            &marker_path,
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("unresolved Windows reparse point"),
            "{message}"
        );
        assert!(
            message.contains(&junction.display().to_string()),
            "{message}"
        );
        std::fs::remove_dir(&junction).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_service_rejects_ambiguous_or_device_path_components() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("alighieri.conf");
        let marker_path = dir.path().join("service-config-path.txt");
        let default_log_dir = dir.path().join("logs");

        for bad_log in [
            dir.path().join("cache.").join("service.log"),
            dir.path().join("cache ").join("service.log"),
            dir.path().join("NUL").join("service.log"),
            dir.path().join("service.log:stream"),
        ] {
            let config = windows_file_logging_config(bad_log, 1);
            let error = validate_windows_service_logging_paths(
                &config,
                &config_path,
                &default_log_dir,
                &marker_path,
            )
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }

        let mut config = windows_file_logging_config(dir.path().join("service.log"), 1);
        config.userlist = Some(dir.path().join("users."));
        let error = validate_windows_service_logging_paths(
            &config,
            &config_path,
            &default_log_dir,
            &marker_path,
        )
        .unwrap_err();
        assert!(error.to_string().contains("configured userlist"), "{error}");

        for valid in [
            Path::new(r"\\?\C:\ProgramData\Alighieri\service.log"),
            Path::new(r"\\?\UNC\server\share\service.log"),
        ] {
            windows_service_validate_path_spelling("test path", valid)
                .unwrap_or_else(|error| panic!("{}: {error}", valid.display()));
        }
        for invalid in [
            Path::new(r"\\?\C:\safe\.\service.log"),
            Path::new(r"\\?\C:\safe\..\service.log"),
            Path::new(r"\\?\UNC\server\share\safe.\service.log"),
            Path::new(r"\\.\C:\service.log"),
        ] {
            assert!(
                windows_service_validate_path_spelling("test path", invalid).is_err(),
                "{}",
                invalid.display()
            );
        }

        // `canonicalize` produces the accepted verbatim-drive form on Windows;
        // exercise it through the complete collision validator as well.
        let verbatim_log = std::fs::canonicalize(dir.path())
            .unwrap()
            .join("verbatim.log");
        let config = windows_file_logging_config(verbatim_log, 1);
        validate_windows_service_logging_paths(
            &config,
            &config_path,
            &default_log_dir,
            &marker_path,
        )
        .unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_service_rejects_an_existing_hardlink_to_a_protected_file() {
        let dir = tempfile::tempdir().unwrap();
        let marker_path = dir.path().join("service-config-path.txt");

        for rotation_index in [0, 1] {
            let config_path = dir.path().join(format!("alighieri-{rotation_index}.conf"));
            let log_path = dir
                .path()
                .join(format!("apparently-separate-{rotation_index}.log"));
            let candidate = if rotation_index == 0 {
                log_path.clone()
            } else {
                rotated_path(&log_path, rotation_index)
            };
            std::fs::write(&config_path, "configuration").unwrap();
            std::fs::hard_link(&config_path, candidate).unwrap();
            let config = windows_file_logging_config(log_path, 1);

            let error = validate_windows_service_logging_paths(
                &config,
                &config_path,
                &dir.path().join("logs"),
                &marker_path,
            )
            .unwrap_err();

            assert!(
                error.to_string().contains("active configuration"),
                "rotation {rotation_index}: {error}"
            );
            if rotation_index == 1 {
                assert!(
                    error.to_string().contains("rotated logfile"),
                    "rotation {rotation_index}: {error}"
                );
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_service_reload_checks_the_log_family_held_from_startup() {
        let dir = tempfile::tempdir().unwrap();
        let active_log = dir.path().join("active.log");
        let new_log = dir.path().join("after-restart.log");
        let config_path = dir.path().join("alighieri.conf");
        let marker_path = dir.path().join("service-config-path.txt");
        let mut reloaded = windows_file_logging_config(new_log, 2);
        reloaded.userlist = Some(rotated_path(&active_log, 1));

        // The next-restart family is disjoint; only the still-open startup
        // writer makes this reload unsafe.
        validate_windows_service_logging_paths(
            &reloaded,
            &config_path,
            &dir.path().join("default-logs"),
            &marker_path,
        )
        .unwrap();
        let error = validate_windows_service_active_log_paths(
            &reloaded,
            &config_path,
            &active_log,
            1,
            &marker_path,
        )
        .unwrap_err();

        let message = error.to_string();
        assert!(message.contains("rotated logfile"), "{message}");
        assert!(message.contains("configured userlist"), "{message}");
    }

    #[cfg(windows)]
    #[test]
    fn windows_service_validation_scales_to_the_maximum_rotation_count() {
        let dir = tempfile::tempdir().unwrap();
        let config = windows_file_logging_config(dir.path().join("active.log"), 10_000);

        validate_windows_service_logging_paths(
            &config,
            &dir.path().join("alighieri.conf"),
            &dir.path().join("default-logs"),
            &dir.path().join("service-config-path.txt"),
        )
        .unwrap();
    }

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
                    // `ENXIO` means no reader yet — the reload has not reached the
                    // open. Any other error is unexpected (missing path, perms),
                    // so fail fast rather than spinning to the timeout.
                    Err(e) if e.raw_os_error() == Some(libc::ENXIO) => {
                        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                    }
                    Err(e) => panic!("unexpected error opening FIFO writer: {e}"),
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

    #[cfg(windows)]
    #[test]
    fn service_rotating_file_pins_its_active_windows_path_but_can_rotate_it_itself() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("active.log");
        let detached = dir.path().join("detached.log");
        let mut file = RotatingFile::open_pinned(path.clone(), 4, 1).unwrap();

        let _error = std::fs::rename(&path, &detached).unwrap_err();

        file.write_all(b"one\n").unwrap();
        file.write_all(b"two\n").unwrap();
        file.flush().unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "two\n");
        assert_eq!(
            std::fs::read_to_string(rotated_path(&path, 1)).unwrap(),
            "one\n"
        );

        drop(file);
        std::fs::rename(&path, &detached).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn console_rotating_file_keeps_windows_delete_sharing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("active.log");
        let detached = dir.path().join("detached.log");
        let mut file = RotatingFile::open(path.clone(), 1024, 1).unwrap();

        std::fs::rename(&path, &detached).unwrap();
        file.write_all(b"still-open\n").unwrap();
        file.flush().unwrap();

        assert_eq!(std::fs::read_to_string(&detached).unwrap(), "still-open\n");
        assert!(!path.exists());
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
