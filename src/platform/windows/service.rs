//! Windows Service host for the SOCKS proxy runtime.

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::{mpsc as std_mpsc, OnceLock};
use std::time::Duration;

use tokio::sync::mpsc as tokio_mpsc;
use tracing::{error, info};
use windows_service::define_windows_service;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
    ServiceType, UserEventCode,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;

use crate::config::Config;
use crate::platform::windows::event_log::{self, EventLevel};
use crate::platform::windows::service_manager::{default_config_path, default_log_dir};
use crate::runtime::{
    init_file_logging, init_service_logging, run_bound_server_reloading_until_shutdown,
};
use crate::server::Server;

pub const SERVICE_NAME: &str = "Alighieri";
pub const SERVICE_DISPLAY_NAME: &str = "Alighieri SOCKS5 Proxy Server";
// SAFETY: 128 is in the Windows user-defined service control range 128..=255.
pub const SERVICE_RELOAD_CONTROL: UserEventCode = unsafe { UserEventCode::from_unchecked(128) };

const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

static SERVICE_CONFIG_OVERRIDE: OnceLock<Option<PathBuf>> = OnceLock::new();

define_windows_service!(ffi_service_main, service_main);

pub fn run_service_dispatcher(config_path: Option<PathBuf>) -> windows_service::Result<String> {
    let _ = SERVICE_CONFIG_OVERRIDE.set(config_path);
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(String::new())
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        eprintln!("Alighieri Windows Service exited with error: {e}");
    }
}

fn run_service() -> windows_service::Result<()> {
    let (shutdown_tx, shutdown_rx) = std_mpsc::channel::<()>();
    let (reload_tx, reload_rx) = tokio_mpsc::unbounded_channel::<()>();
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        handle_service_control(control_event, &shutdown_tx, &reload_tx)
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;
    status_handle.set_service_status(service_status(
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        1,
        Duration::from_secs(10),
        SERVICE_EXIT_OK,
    ))?;

    let config_path = SERVICE_CONFIG_OVERRIDE
        .get()
        .cloned()
        .flatten()
        .unwrap_or_else(default_config_path);

    let config = match Config::load(&config_path) {
        Ok(config) => config,
        Err(e) => {
            // The guard flushes queued records when this error path returns.
            let _log_guard = match init_file_logging(&default_log_dir()) {
                Ok((_, guard)) => Some(guard),
                Err(log_error) => {
                    eprintln!("failed to initialise service file logging: {log_error}");
                    None
                }
            };
            event_log::report(
                EventLevel::Error,
                event_log::EVENT_SERVICE_CONFIG_ERROR,
                format!(
                    "Failed to load service configuration '{}': {e}",
                    config_path.display()
                ),
            );
            error!(config = %config_path.display(), error = %e, "failed to load service config");
            set_stopped(&status_handle, SERVICE_EXIT_CONFIG)?;
            return Ok(());
        }
    };

    // Held for the life of the service; dropping it flushes queued records.
    let _log_guard = match init_service_logging(&config, &default_log_dir()) {
        Ok((_, guard)) => guard,
        Err(e) => {
            eprintln!("failed to initialise service file logging: {e}");
            event_log::report(
                EventLevel::Error,
                event_log::EVENT_SERVICE_LOGGING_ERROR,
                format!("Failed to initialise service file logging: {e}"),
            );
            set_stopped(&status_handle, SERVICE_EXIT_LOGGING)?;
            return Ok(());
        }
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            event_log::report(
                EventLevel::Error,
                event_log::EVENT_SERVICE_RUNTIME_ERROR,
                format!("Failed to build service Tokio runtime: {e}"),
            );
            error!(error = %e, "failed to build service Tokio runtime");
            set_stopped(&status_handle, SERVICE_EXIT_RUNTIME)?;
            return Ok(());
        }
    };

    let server = match runtime.block_on(Server::bind(config)) {
        Ok(server) => server,
        Err(e) => {
            event_log::report(
                EventLevel::Error,
                event_log::EVENT_SERVICE_BIND_ERROR,
                format!("Failed to bind service server: {e}"),
            );
            error!(error = %e, "failed to bind service server");
            set_stopped(&status_handle, SERVICE_EXIT_BIND)?;
            return Ok(());
        }
    };

    status_handle.set_service_status(service_status(
        ServiceState::Running,
        // Accept SHUTDOWN as well as STOP so an OS shutdown/restart runs the
        // graceful stop path (final log flush, clean Stopped status) instead of
        // terminating the process abruptly.
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        0,
        Duration::default(),
        SERVICE_EXIT_OK,
    ))?;

    info!(config = %config_path.display(), "Windows Service started");
    event_log::report(
        EventLevel::Info,
        event_log::EVENT_SERVICE_STARTED,
        format!(
            "Windows Service started using config '{}'",
            config_path.display()
        ),
    );
    let run_result = runtime.block_on(async move {
        let shutdown = async move {
            let _ = tokio::task::spawn_blocking(move || shutdown_rx.recv()).await;
        };
        run_bound_server_reloading_until_shutdown(server, config_path, shutdown, reload_rx).await
    });

    status_handle.set_service_status(service_status(
        ServiceState::StopPending,
        ServiceControlAccept::empty(),
        1,
        Duration::from_secs(10),
        SERVICE_EXIT_OK,
    ))?;

    let exit_code = match run_result {
        Ok(()) => SERVICE_EXIT_OK,
        Err(e) => {
            event_log::report(
                EventLevel::Error,
                event_log::EVENT_SERVICE_SERVER_ERROR,
                format!("Service server runtime failed: {e}"),
            );
            error!(error = %e, "service server runtime failed");
            SERVICE_EXIT_SERVER
        }
    };

    set_stopped(&status_handle, exit_code)?;
    event_log::report(
        EventLevel::Info,
        event_log::EVENT_SERVICE_STOPPED,
        format!("Windows Service stopped with service exit code {exit_code}"),
    );

    Ok(())
}

fn handle_service_control(
    control_event: ServiceControl,
    shutdown_tx: &std_mpsc::Sender<()>,
    reload_tx: &tokio_mpsc::UnboundedSender<()>,
) -> ServiceControlHandlerResult {
    match control_event {
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        // STOP (explicit) and SHUTDOWN (OS shutting down) both drive the same
        // graceful stop.
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = shutdown_tx.send(());
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::UserEvent(code) if code == SERVICE_RELOAD_CONTROL => {
            let _ = reload_tx.send(());
            event_log::report(
                EventLevel::Info,
                event_log::EVENT_SERVICE_RELOAD_REQUESTED,
                "Windows Service reload requested",
            );
            ServiceControlHandlerResult::NoError
        }
        _ => ServiceControlHandlerResult::NotImplemented,
    }
}

const SERVICE_EXIT_OK: u32 = 0;
const SERVICE_EXIT_LOGGING: u32 = 1;
const SERVICE_EXIT_CONFIG: u32 = 2;
const SERVICE_EXIT_RUNTIME: u32 = 3;
const SERVICE_EXIT_BIND: u32 = 4;
const SERVICE_EXIT_SERVER: u32 = 5;

fn set_stopped(
    status_handle: &windows_service::service_control_handler::ServiceStatusHandle,
    service_exit_code: u32,
) -> windows_service::Result<()> {
    status_handle.set_service_status(service_status(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        0,
        Duration::default(),
        service_exit_code,
    ))?;
    Ok(())
}

fn service_status(
    current_state: ServiceState,
    controls_accepted: ServiceControlAccept,
    checkpoint: u32,
    wait_hint: Duration,
    service_exit_code: u32,
) -> ServiceStatus {
    let exit_code = if service_exit_code == SERVICE_EXIT_OK {
        ServiceExitCode::Win32(0)
    } else {
        ServiceExitCode::ServiceSpecific(service_exit_code)
    };

    ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state,
        controls_accepted,
        exit_code,
        checkpoint,
        wait_hint,
        process_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stop_pending_status_accepts_no_controls() {
        let status = service_status(
            ServiceState::StopPending,
            ServiceControlAccept::empty(),
            1,
            Duration::from_secs(10),
            SERVICE_EXIT_OK,
        );
        assert_eq!(status.current_state, ServiceState::StopPending);
        assert!(status.controls_accepted.is_empty());
    }

    #[test]
    fn running_status_accepts_stop_and_shutdown() {
        let status = service_status(
            ServiceState::Running,
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            0,
            Duration::default(),
            SERVICE_EXIT_OK,
        );
        assert!(status
            .controls_accepted
            .contains(ServiceControlAccept::STOP));
        assert!(status
            .controls_accepted
            .contains(ServiceControlAccept::SHUTDOWN));
    }

    #[test]
    fn reload_control_signals_reload_channel() {
        let (shutdown_tx, shutdown_rx) = std_mpsc::channel::<()>();
        let (reload_tx, mut reload_rx) = tokio_mpsc::unbounded_channel::<()>();

        let result = handle_service_control(
            ServiceControl::UserEvent(SERVICE_RELOAD_CONTROL),
            &shutdown_tx,
            &reload_tx,
        );

        assert!(matches!(result, ServiceControlHandlerResult::NoError));
        assert!(shutdown_rx.try_recv().is_err());
        assert_eq!(reload_rx.try_recv(), Ok(()));
    }

    #[test]
    fn stop_control_signals_shutdown_channel() {
        let (shutdown_tx, shutdown_rx) = std_mpsc::channel::<()>();
        let (reload_tx, mut reload_rx) = tokio_mpsc::unbounded_channel::<()>();

        let result = handle_service_control(ServiceControl::Stop, &shutdown_tx, &reload_tx);

        assert!(matches!(result, ServiceControlHandlerResult::NoError));
        assert_eq!(shutdown_rx.try_recv(), Ok(()));
        assert!(reload_rx.try_recv().is_err());
    }

    #[test]
    fn shutdown_control_signals_shutdown_channel() {
        let (shutdown_tx, shutdown_rx) = std_mpsc::channel::<()>();
        let (reload_tx, mut reload_rx) = tokio_mpsc::unbounded_channel::<()>();

        let result = handle_service_control(ServiceControl::Shutdown, &shutdown_tx, &reload_tx);

        assert!(matches!(result, ServiceControlHandlerResult::NoError));
        assert_eq!(shutdown_rx.try_recv(), Ok(()));
        assert!(reload_rx.try_recv().is_err());
    }

    #[test]
    fn failure_status_reports_service_specific_exit_code() {
        let status = service_status(
            ServiceState::Stopped,
            ServiceControlAccept::empty(),
            0,
            Duration::default(),
            SERVICE_EXIT_BIND,
        );
        assert_eq!(
            status.exit_code,
            ServiceExitCode::ServiceSpecific(SERVICE_EXIT_BIND)
        );
    }
}
