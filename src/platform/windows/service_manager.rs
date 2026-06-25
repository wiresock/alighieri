//! Windows Service management commands.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::{Duration, Instant};

use thiserror::Error;
use windows_service::service::{
    Service, ServiceAccess, ServiceAction, ServiceActionType, ServiceControlAccept,
    ServiceErrorControl, ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo,
    ServiceStartType, ServiceState, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use crate::config::Config;
use crate::platform::windows::event_log;
use crate::platform::windows::service::{
    run_service_dispatcher, SERVICE_DISPLAY_NAME, SERVICE_NAME, SERVICE_RELOAD_CONTROL,
};
use crate::tls;

const DEFAULT_CONFIG: &str = r"C:\ProgramData\Alighieri\alighieri.conf";
const SERVICE_CONFIG_MARKER: &str = "service-config-path.txt";
const LOCAL_SERVICE_ACCOUNT: &str = r"NT AUTHORITY\LocalService";
const SERVICE_STOP_TIMEOUT: Duration = Duration::from_secs(30);
const SERVICE_STOP_POLL_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceCommand {
    Install { config_path: PathBuf },
    Uninstall,
    Start,
    Stop,
    Reload,
    Status,
    Run { config_path: Option<PathBuf> },
    Help,
}

#[derive(Debug, Error)]
pub enum ServiceCliError {
    #[error("{0}")]
    Usage(String),
    #[error("configuration error: {0}")]
    Config(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Service(String),
}

pub type ServiceCliResult<T> = std::result::Result<T, ServiceCliError>;

pub trait ServiceController {
    fn install(&self, options: &InstallOptions) -> ServiceCliResult<()>;
    fn uninstall(&self) -> ServiceCliResult<()>;
    fn start(&self) -> ServiceCliResult<()>;
    fn stop(&self) -> ServiceCliResult<()>;
    fn reload(&self) -> ServiceCliResult<()>;
    fn status(&self) -> ServiceCliResult<String>;
    /// Records which config the service was installed with, so the CLI's
    /// `start`/`reload` validate the same file the service runs. Kept on the
    /// controller (rather than inlined) so install can roll back when it fails.
    fn persist_config_marker(&self, config_path: &Path) -> ServiceCliResult<()>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallOptions {
    pub executable_path: PathBuf,
    pub config_path: PathBuf,
    pub account_name: OsString,
}

pub fn handle_service_cli(args: Vec<String>) -> ServiceCliResult<String> {
    let command = parse_service_command(args)?;
    if let ServiceCommand::Run { config_path } = command {
        return run_service_dispatcher(config_path).map_err(|e| {
            ServiceCliError::Service(format!("failed to run as Windows Service: {e}"))
        });
    }

    let controller = WindowsServiceController;
    execute_service_command(&controller, command)
}

pub fn parse_service_command(args: Vec<String>) -> ServiceCliResult<ServiceCommand> {
    if args.iter().any(|arg| arg == "-h" || arg == "--help") {
        return Ok(ServiceCommand::Help);
    }
    let Some(command) = args.first().map(String::as_str) else {
        return Err(ServiceCliError::Usage(service_usage()));
    };

    match command {
        "install" => {
            let config_path = parse_config_arg(&args[1..])?.unwrap_or_else(default_config_path);
            Ok(ServiceCommand::Install { config_path })
        }
        "uninstall" => Ok(ServiceCommand::Uninstall),
        "start" => Ok(ServiceCommand::Start),
        "stop" => Ok(ServiceCommand::Stop),
        "reload" => Ok(ServiceCommand::Reload),
        "status" => Ok(ServiceCommand::Status),
        "run" => {
            let config_path = parse_config_arg(&args[1..])?;
            Ok(ServiceCommand::Run { config_path })
        }
        _ => Err(ServiceCliError::Usage(service_usage())),
    }
}

pub fn execute_service_command<C: ServiceController>(
    controller: &C,
    command: ServiceCommand,
) -> ServiceCliResult<String> {
    match command {
        ServiceCommand::Install { config_path } => {
            prepare_service_directories(&config_path)?;
            validate_config(&config_path)?;
            let options = InstallOptions {
                executable_path: std::env::current_exe()?,
                config_path: config_path.clone(),
                account_name: OsString::from(LOCAL_SERVICE_ACCOUNT),
            };
            controller.install(&options)?;
            finalize_install(controller, &config_path)?;
            Ok(format!(
                "installed {SERVICE_NAME} using config '{}'",
                config_path.display()
            ))
        }
        ServiceCommand::Uninstall => {
            controller.uninstall()?;
            Ok(format!("uninstalled {SERVICE_NAME}"))
        }
        ServiceCommand::Start => {
            let config_path = installed_config_path();
            validate_config(&config_path)?;
            controller.start()?;
            Ok(format!("started {SERVICE_NAME}"))
        }
        ServiceCommand::Stop => {
            controller.stop()?;
            Ok(format!("stopped {SERVICE_NAME}"))
        }
        ServiceCommand::Reload => {
            let config_path = installed_config_path();
            validate_config(&config_path)?;
            controller.reload()?;
            Ok(format!("requested reload of {SERVICE_NAME}"))
        }
        ServiceCommand::Status => controller.status(),
        ServiceCommand::Run { .. } => Err(ServiceCliError::Usage(
            "'service run' is reserved for the Windows Service Control Manager".into(),
        )),
        ServiceCommand::Help => Ok(service_usage()),
    }
}

fn parse_config_arg(args: &[String]) -> ServiceCliResult<Option<PathBuf>> {
    let mut config_path = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--config" => {
                let Some(path) = iter.next() else {
                    return Err(ServiceCliError::Usage("--config requires a path".into()));
                };
                config_path = Some(PathBuf::from(path));
            }
            _ => return Err(ServiceCliError::Usage(service_usage())),
        }
    }
    Ok(config_path)
}

pub fn default_base_dir() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("Alighieri")
}

pub fn default_config_path() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .map(|base| base.join("Alighieri").join("alighieri.conf"))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG))
}

pub fn default_log_dir() -> PathBuf {
    default_base_dir().join("logs")
}

fn config_marker_path() -> PathBuf {
    default_base_dir().join(SERVICE_CONFIG_MARKER)
}

fn installed_config_path() -> PathBuf {
    std::fs::read_to_string(config_marker_path())
        .ok()
        .map(|s| PathBuf::from(s.trim()))
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(default_config_path)
}

fn prepare_service_directories(config_path: &Path) -> ServiceCliResult<()> {
    std::fs::create_dir_all(default_base_dir())?;
    std::fs::create_dir_all(default_log_dir())?;
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn write_config_marker(config_path: &Path) -> ServiceCliResult<()> {
    write_marker_atomically(&config_marker_path(), &config_path.display().to_string())?;
    Ok(())
}

/// Writes the marker crash-safely: a fresh sibling temp file is written and
/// flushed, then renamed over `marker`. A direct `std::fs::write` truncates in
/// place, so a crash mid-write could leave a truncated/partial path that later
/// makes the CLI validate the wrong (or default) config; with the rename, readers
/// always see a complete old-or-new file (the rename also replaces a destination
/// link rather than writing through it). Mirrors the atomic persistence used for
/// the userlist/config writes; separated from `config_marker_path` for testing.
fn write_marker_atomically(marker: &Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write;

    let (temp, mut file) = create_marker_temp(marker)?;
    let result = file
        .write_all(contents.as_bytes())
        .and_then(|()| file.sync_all());
    drop(file);
    // Clean the temp up on any failure after it was created (write, fsync, or
    // rename) so a partial temp never lingers.
    if let Err(e) = result.and_then(|()| std::fs::rename(&temp, marker)) {
        let _ = std::fs::remove_file(&temp);
        return Err(e);
    }
    Ok(())
}

/// Creates a fresh, uniquely-named sibling temp file with `create_new`
/// (`CREATE_NEW`). Because it refuses to open an existing name, it cannot follow
/// a symlink/reparse point pre-planted in the directory — a real concern under
/// `ProgramData`, whose subfolders a standard user may be able to write — and a
/// unique `pid`-`nonce` name avoids collisions and stale-temp wedging. Mirrors
/// `create_userlist_temp`.
fn create_marker_temp(marker: &Path) -> std::io::Result<(PathBuf, std::fs::File)> {
    use std::ffi::{OsStr, OsString};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    let parent = marker
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = marker
        .file_name()
        .unwrap_or_else(|| OsStr::new(SERVICE_CONFIG_MARKER));

    for _ in 0..100 {
        let nonce = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut temp_name = OsString::from(".");
        temp_name.push(file_name);
        temp_name.push(format!(".tmp-{}-{nonce}", std::process::id()));
        let temp = parent.join(temp_name);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
        {
            Ok(file) => return Ok((temp, file)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "failed to create unique temporary marker path",
    ))
}

/// Records the installed config marker after the service is created, rolling the
/// install back if it cannot be written.
///
/// The service's config path is baked into its SCM launch arguments, and the
/// marker mirrors it for the CLI's `start`/`reload`. If the two disagreed the CLI
/// would validate a different config than the service actually runs (a missing
/// marker falls back to the default path), so a failed marker write must not
/// leave an installed service behind. A successful rollback returns the original
/// marker error (net state: not installed); if the rollback *also* fails the
/// service is still installed, so both failures are surfaced and the operator is
/// pointed at a manual uninstall rather than the leftover service being hidden
/// behind the marker error alone.
fn finalize_install<C: ServiceController>(
    controller: &C,
    config_path: &Path,
) -> ServiceCliResult<()> {
    let Err(persist_err) = controller.persist_config_marker(config_path) else {
        return Ok(());
    };
    match controller.uninstall() {
        Ok(()) => Err(persist_err),
        Err(uninstall_err) => Err(ServiceCliError::Service(format!(
            "failed to record the installed config ({persist_err}); rolling the install back \
             also failed ({uninstall_err}), so the {SERVICE_NAME} service may still be installed \
             - run 'alighieri service uninstall' to remove it"
        ))),
    }
}

fn validate_config(config_path: &Path) -> ServiceCliResult<()> {
    Config::load(config_path)
        .and_then(|config| {
            // Mirror the checks `Server::bind` runs at startup (same order as the
            // `check` command) so `service install`/`start`/`reload` reject a
            // config that would otherwise fail the moment the service binds —
            // e.g. an unauthenticated public metrics endpoint.
            config.validate_startup()?;
            tls::validate_config(&config)?;
            Ok(())
        })
        .map_err(|e| ServiceCliError::Config(format!("{} ({})", config_path.display(), e)))
}

fn service_usage() -> String {
    "usage: alighieri service install --config CONFIG | uninstall | start | stop | reload | status"
        .into()
}

pub fn explain_service_error(err: &windows_service::Error) -> String {
    let base = err.to_string();
    if matches!(err, windows_service::Error::Winapi(io) if io.raw_os_error() == Some(5)) {
        return format!("{base}; run this command from an elevated Administrator shell");
    }
    let lower = base.to_ascii_lowercase();
    if lower.contains("access is denied") || lower.contains("os error 5") {
        format!("{base}; run this command from an elevated Administrator shell")
    } else {
        base
    }
}

fn explain_io_error(err: &std::io::Error) -> String {
    let base = err.to_string();
    if err.raw_os_error() == Some(5) || base.to_ascii_lowercase().contains("access is denied") {
        format!("I/O error: {base}; run this command from an elevated Administrator shell")
    } else {
        format!("I/O error: {base}")
    }
}

fn ensure_service_stopped(service: &Service) -> ServiceCliResult<()> {
    let status = service
        .query_status()
        .map_err(|e| ServiceCliError::Service(explain_service_error(&e)))?;
    if status.current_state == ServiceState::Stopped {
        return Ok(());
    }

    if should_request_stop(status.current_state, status.controls_accepted) {
        if let Err(err) = service.stop() {
            if wait_for_service_stopped(service, SERVICE_STOP_TIMEOUT).is_ok() {
                return Ok(());
            }
            return Err(ServiceCliError::Service(explain_service_error(&err)));
        }
    }
    wait_for_service_stopped(service, SERVICE_STOP_TIMEOUT)
}

fn should_request_stop(
    current_state: ServiceState,
    controls_accepted: ServiceControlAccept,
) -> bool {
    current_state != ServiceState::Stopped
        && current_state != ServiceState::StopPending
        && controls_accepted.contains(ServiceControlAccept::STOP)
}

fn wait_for_service_stopped(service: &Service, timeout: Duration) -> ServiceCliResult<()> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        let status = service
            .query_status()
            .map_err(|e| ServiceCliError::Service(explain_service_error(&e)))?;
        if status.current_state == ServiceState::Stopped {
            return Ok(());
        }
        sleep(SERVICE_STOP_POLL_INTERVAL);
    }

    Err(ServiceCliError::Service(format!(
        "timed out waiting for {SERVICE_NAME} to stop before uninstalling"
    )))
}

pub struct WindowsServiceController;

/// A failed `WindowsServiceController::install` attempt: the error to report, and
/// whether an SCM service was left behind because cleanup could not remove it (so
/// the caller knows not to unregister the event source out from under it).
struct InstallFailure {
    error: ServiceCliError,
    service_remains: bool,
}

impl From<ServiceCliError> for InstallFailure {
    /// Failures before or while creating the service leave nothing behind.
    fn from(error: ServiceCliError) -> Self {
        InstallFailure {
            error,
            service_remains: false,
        }
    }
}

/// Builds the error for a post-create configuration failure, given the result of
/// rolling the just-created service back. A successful rollback reports only the
/// configuration error (net state: not installed); if the rollback `delete` also
/// failed the service may still be installed, so both failures are surfaced and
/// the operator is pointed at a manual uninstall. Mirrors `finalize_install`.
fn configure_rollback_error(configure_err: &str, delete: ServiceCliResult<()>) -> InstallFailure {
    match delete {
        Ok(()) => InstallFailure {
            error: ServiceCliError::Service(configure_err.to_string()),
            service_remains: false,
        },
        Err(delete_err) => InstallFailure {
            error: ServiceCliError::Service(format!(
                "{configure_err}; rolling back the partially configured service also failed \
                 ({delete_err}), so the {SERVICE_NAME} service may still be installed - run \
                 'alighieri service uninstall' to remove it"
            )),
            service_remains: true,
        },
    }
}

impl ServiceController for WindowsServiceController {
    fn install(&self, options: &InstallOptions) -> ServiceCliResult<()> {
        event_log::register_source().map_err(|e| ServiceCliError::Service(explain_io_error(&e)))?;

        let install_result = || -> Result<(), InstallFailure> {
            let manager_access =
                ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE;
            let manager = ServiceManager::local_computer(None::<&str>, manager_access)
                .map_err(|e| ServiceCliError::Service(explain_service_error(&e)))?;

            let service_info = ServiceInfo {
                name: OsString::from(SERVICE_NAME),
                display_name: OsString::from(SERVICE_DISPLAY_NAME),
                service_type: ServiceType::OWN_PROCESS,
                start_type: ServiceStartType::AutoStart,
                error_control: ServiceErrorControl::Normal,
                executable_path: options.executable_path.clone(),
                launch_arguments: vec![
                    OsString::from("service"),
                    OsString::from("run"),
                    OsString::from("--config"),
                    options.config_path.clone().into_os_string(),
                ],
                dependencies: vec![],
                account_name: Some(options.account_name.clone()),
                account_password: None,
            };

            let service_access = ServiceAccess::QUERY_STATUS
                | ServiceAccess::QUERY_CONFIG
                | ServiceAccess::CHANGE_CONFIG
                | ServiceAccess::START
                | ServiceAccess::STOP
                | ServiceAccess::DELETE;

            let service = manager
                .create_service(&service_info, service_access)
                .map_err(|e| ServiceCliError::Service(explain_service_error(&e)))?;
            // Configure the freshly created service. On any failure, best-effort
            // delete it so a half-configured service is not left behind for the
            // operator to clean up by hand.
            //
            // Auto-restart on crash mirrors the systemd unit's
            // `Restart=on-failure`: escalating delays avoid a tight restart loop,
            // and the reset period clears the failure count after a stable hour.
            // (Left at the default of recovering only from real crashes — a clean
            // exit with a config-error code is not restarted, since a restart
            // would not fix a broken config.)
            let configure = service
                .set_description(SERVICE_DISPLAY_NAME)
                .and_then(|()| {
                    service.update_failure_actions(ServiceFailureActions {
                        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(
                            60 * 60,
                        )),
                        reboot_msg: None,
                        command: None,
                        actions: Some(vec![
                            ServiceAction {
                                action_type: ServiceActionType::Restart,
                                delay: Duration::from_secs(5),
                            },
                            ServiceAction {
                                action_type: ServiceActionType::Restart,
                                delay: Duration::from_secs(30),
                            },
                            ServiceAction {
                                action_type: ServiceActionType::Restart,
                                delay: Duration::from_secs(60),
                            },
                        ]),
                    })
                });
            if let Err(e) = configure {
                let configure_err = explain_service_error(&e);
                let delete = service
                    .delete()
                    .map_err(|de| ServiceCliError::Service(explain_service_error(&de)));
                return Err(configure_rollback_error(&configure_err, delete));
            }
            Ok(())
        };

        match install_result() {
            Ok(()) => {}
            Err(InstallFailure {
                error,
                service_remains,
            }) => {
                // Keep the event source registered if a service survived a failed
                // cleanup (it still needs it for its own logging; the eventual
                // manual uninstall unregisters it). Otherwise drop it.
                if !service_remains {
                    let _ = event_log::unregister_source();
                }
                return Err(error);
            }
        }
        // The "was installed" Event Log entry is reported from
        // `persist_config_marker` (the final install step), not here: a failed
        // marker write rolls the install back, so reporting here would leave a
        // misleading "was installed" record with no service behind it.
        Ok(())
    }

    fn uninstall(&self) -> ServiceCliResult<()> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|e| ServiceCliError::Service(explain_service_error(&e)))?;
        let service = manager
            .open_service(
                SERVICE_NAME,
                ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
            )
            .map_err(|e| ServiceCliError::Service(explain_service_error(&e)))?;
        ensure_service_stopped(&service)?;
        service
            .delete()
            .map_err(|e| ServiceCliError::Service(explain_service_error(&e)))?;
        event_log::unregister_source()
            .map_err(|e| ServiceCliError::Service(explain_io_error(&e)))?;
        Ok(())
    }

    fn start(&self) -> ServiceCliResult<()> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|e| ServiceCliError::Service(explain_service_error(&e)))?;
        let service = manager
            .open_service(SERVICE_NAME, ServiceAccess::START)
            .map_err(|e| ServiceCliError::Service(explain_service_error(&e)))?;
        service
            .start::<&str>(&[])
            .map_err(|e| ServiceCliError::Service(explain_service_error(&e)))
    }

    fn stop(&self) -> ServiceCliResult<()> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|e| ServiceCliError::Service(explain_service_error(&e)))?;
        let service = manager
            .open_service(SERVICE_NAME, ServiceAccess::STOP)
            .map_err(|e| ServiceCliError::Service(explain_service_error(&e)))?;
        service
            .stop()
            .map(|_| ())
            .map_err(|e| ServiceCliError::Service(explain_service_error(&e)))
    }

    fn reload(&self) -> ServiceCliResult<()> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|e| ServiceCliError::Service(explain_service_error(&e)))?;
        let service = manager
            .open_service(SERVICE_NAME, ServiceAccess::USER_DEFINED_CONTROL)
            .map_err(|e| ServiceCliError::Service(explain_service_error(&e)))?;
        service
            .notify(SERVICE_RELOAD_CONTROL)
            .map(|_| ())
            .map_err(|e| ServiceCliError::Service(explain_service_error(&e)))
    }

    fn status(&self) -> ServiceCliResult<String> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|e| ServiceCliError::Service(explain_service_error(&e)))?;
        let service = manager
            .open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS)
            .map_err(|e| ServiceCliError::Service(explain_service_error(&e)))?;
        let status = service
            .query_status()
            .map_err(|e| ServiceCliError::Service(explain_service_error(&e)))?;
        Ok(format!("{SERVICE_NAME}: {:?}", status.current_state))
    }

    fn persist_config_marker(&self, config_path: &Path) -> ServiceCliResult<()> {
        write_config_marker(config_path)?;
        // Reported here rather than in `install` so the "was installed" entry is
        // logged only once the whole install has succeeded (service created and
        // marker persisted). A marker-write failure rolls the install back, so
        // emitting this from `install` would misreport an install the command
        // ultimately failed and removed.
        event_log::report(
            event_log::EventLevel::Info,
            event_log::EVENT_SERVICE_INSTALLED,
            format!("{SERVICE_DISPLAY_NAME} was installed"),
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_install_with_config() {
        let command = parse_service_command(vec![
            "install".into(),
            "--config".into(),
            r"C:\ProgramData\Alighieri\alighieri.conf".into(),
        ])
        .unwrap();
        assert_eq!(
            command,
            ServiceCommand::Install {
                config_path: PathBuf::from(r"C:\ProgramData\Alighieri\alighieri.conf")
            }
        );
    }

    #[test]
    fn parses_lifecycle_commands() {
        assert_eq!(
            parse_service_command(vec!["uninstall".into()]).unwrap(),
            ServiceCommand::Uninstall
        );
        assert_eq!(
            parse_service_command(vec!["start".into()]).unwrap(),
            ServiceCommand::Start
        );
        assert_eq!(
            parse_service_command(vec!["stop".into()]).unwrap(),
            ServiceCommand::Stop
        );
        assert_eq!(
            parse_service_command(vec!["reload".into()]).unwrap(),
            ServiceCommand::Reload
        );
        assert_eq!(
            parse_service_command(vec!["status".into()]).unwrap(),
            ServiceCommand::Status
        );
    }

    #[test]
    fn validate_config_rejects_public_metrics_without_allowpublic() {
        // The service validation path must enforce the same startup checks as
        // `Server::bind`, so installing/starting a config that binds public
        // metrics without `metrics.allowpublic` fails up front rather than only
        // when the service later tries to bind.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("alighieri.conf");
        std::fs::write(
            &path,
            "internal: 127.0.0.1 port = 1080\nmetrics.listen: 0.0.0.0:9090\nsocks pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }",
        )
        .unwrap();

        let Err(err) = validate_config(&path) else {
            panic!("service validation should refuse public metrics without metrics.allowpublic");
        };
        assert!(err.to_string().contains("metrics.allowpublic"), "{err}");
    }

    #[test]
    fn parses_service_help() {
        assert_eq!(
            parse_service_command(vec!["install".into(), "--help".into()]).unwrap(),
            ServiceCommand::Help
        );
    }

    #[test]
    fn default_paths_use_program_data() {
        let config = default_config_path();
        assert!(config.ends_with(Path::new("Alighieri").join("alighieri.conf")));
        let logs = default_log_dir();
        assert!(logs.ends_with(Path::new("Alighieri").join("logs")));
    }

    #[test]
    fn permission_error_mentions_elevation() {
        let err = windows_service::Error::Winapi(std::io::Error::from_raw_os_error(5));
        let message = explain_service_error(&err);
        assert!(message.contains("Administrator"));
    }

    #[test]
    fn event_log_permission_error_mentions_elevation() {
        let err = std::io::Error::from_raw_os_error(5);
        let message = explain_io_error(&err);
        assert!(message.contains("I/O error"));
        assert!(message.contains("Administrator"));
    }

    #[test]
    fn stop_pending_service_is_waited_without_second_stop_request() {
        assert!(!should_request_stop(
            ServiceState::StopPending,
            ServiceControlAccept::STOP
        ));
    }

    #[test]
    fn running_service_requests_stop_only_when_control_is_accepted() {
        assert!(should_request_stop(
            ServiceState::Running,
            ServiceControlAccept::STOP
        ));
        assert!(!should_request_stop(
            ServiceState::Running,
            ServiceControlAccept::empty()
        ));
    }

    #[derive(Default)]
    struct FakeController {
        persist_should_fail: bool,
        uninstall_should_fail: bool,
        uninstalled: std::cell::Cell<bool>,
    }

    impl ServiceController for FakeController {
        fn install(&self, _options: &InstallOptions) -> ServiceCliResult<()> {
            Ok(())
        }

        fn uninstall(&self) -> ServiceCliResult<()> {
            self.uninstalled.set(true);
            if self.uninstall_should_fail {
                Err(ServiceCliError::Service(
                    "simulated uninstall failure".into(),
                ))
            } else {
                Ok(())
            }
        }

        fn start(&self) -> ServiceCliResult<()> {
            Ok(())
        }

        fn stop(&self) -> ServiceCliResult<()> {
            Ok(())
        }

        fn reload(&self) -> ServiceCliResult<()> {
            Ok(())
        }

        fn status(&self) -> ServiceCliResult<String> {
            Ok("Alighieri: Running".into())
        }

        fn persist_config_marker(&self, _config_path: &Path) -> ServiceCliResult<()> {
            if self.persist_should_fail {
                Err(ServiceCliError::Io(std::io::Error::other(
                    "simulated marker write failure",
                )))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn command_layer_dispatches_status() {
        let message =
            execute_service_command(&FakeController::default(), ServiceCommand::Status).unwrap();
        assert_eq!(message, "Alighieri: Running");
    }

    #[test]
    fn finalize_install_rolls_back_when_config_marker_write_fails() {
        // If the marker cannot be written after the service is created, the
        // freshly installed service must be rolled back so the SCM launch
        // arguments and the CLI's marker can never point at different configs.
        let controller = FakeController {
            persist_should_fail: true,
            ..FakeController::default()
        };
        let err = finalize_install(
            &controller,
            Path::new(r"C:\ProgramData\Alighieri\alighieri.conf"),
        )
        .unwrap_err();
        assert!(matches!(err, ServiceCliError::Io(_)), "{err}");
        assert!(
            controller.uninstalled.get(),
            "a failed marker write must roll back (uninstall) the service"
        );
    }

    #[test]
    fn finalize_install_surfaces_a_failed_rollback() {
        // Marker write fails AND the rollback uninstall fails: the service may
        // still be installed, so the error must say so (and name both failures)
        // instead of returning only the marker error.
        let controller = FakeController {
            persist_should_fail: true,
            uninstall_should_fail: true,
            ..FakeController::default()
        };
        let err = finalize_install(
            &controller,
            Path::new(r"C:\ProgramData\Alighieri\alighieri.conf"),
        )
        .unwrap_err();
        assert!(
            controller.uninstalled.get(),
            "rollback uninstall must be attempted"
        );
        let msg = err.to_string();
        assert!(msg.contains("may still be installed"), "{msg}");
        assert!(msg.contains("simulated marker write failure"), "{msg}");
        assert!(msg.contains("simulated uninstall failure"), "{msg}");
    }

    #[test]
    fn finalize_install_succeeds_and_keeps_the_service_when_marker_writes() {
        let controller = FakeController::default();
        finalize_install(
            &controller,
            Path::new(r"C:\ProgramData\Alighieri\alighieri.conf"),
        )
        .unwrap();
        assert!(
            !controller.uninstalled.get(),
            "a successful install must not be rolled back"
        );
    }

    #[test]
    fn configure_rollback_error_reports_only_config_error_when_rollback_succeeds() {
        let failure = configure_rollback_error("set_description failed", Ok(()));
        assert!(!failure.service_remains);
        let msg = failure.error.to_string();
        assert!(msg.contains("set_description failed"), "{msg}");
        assert!(!msg.contains("may still be installed"), "{msg}");
    }

    #[test]
    fn configure_rollback_error_surfaces_both_failures_when_rollback_fails() {
        // Configuration failed AND the rollback delete failed: the service may
        // still be installed, so both failures and a manual-uninstall hint must
        // appear, and the caller must learn the service survived.
        let failure = configure_rollback_error(
            "set_description failed",
            Err(ServiceCliError::Service("delete access denied".into())),
        );
        assert!(failure.service_remains);
        let msg = failure.error.to_string();
        assert!(msg.contains("set_description failed"), "{msg}");
        assert!(msg.contains("delete access denied"), "{msg}");
        assert!(msg.contains("may still be installed"), "{msg}");
    }

    #[test]
    fn write_marker_atomically_replaces_existing_without_leaving_temp() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("service-config-path.txt");
        std::fs::write(&marker, "old-path").unwrap();

        write_marker_atomically(&marker, r"C:\new\alighieri.conf").unwrap();

        assert_eq!(
            std::fs::read_to_string(&marker).unwrap(),
            r"C:\new\alighieri.conf"
        );
        // No temp sibling lingers after a successful write: the directory holds
        // only the marker file itself.
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(
            names,
            vec![std::ffi::OsString::from("service-config-path.txt")]
        );
    }
}
