//! Windows Event Log source registration and reporting.

use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::ptr;

use windows_sys::Win32::Foundation::{GetLastError, ERROR_SUCCESS};
use windows_sys::Win32::System::EventLog::{
    DeregisterEventSource, RegisterEventSourceW, ReportEventW, EVENTLOG_ERROR_TYPE,
    EVENTLOG_INFORMATION_TYPE, EVENTLOG_WARNING_TYPE, REPORT_EVENT_TYPE,
};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE,
    KEY_WRITE, REG_DWORD, REG_EXPAND_SZ, REG_OPTION_NON_VOLATILE,
};

use crate::platform::windows::service::SERVICE_NAME;

const EVENT_LOG_APPLICATION_PATH: &str = r"SYSTEM\CurrentControlSet\Services\EventLog\Application";
// EventCreate.exe provides a generic message table for custom IDs 1-1000, so Event
// Viewer can render our insertion string without a project-specific resource DLL.
const EVENT_MESSAGE_FILE: &str = r"%SystemRoot%\System32\EventCreate.exe";

pub const EVENT_SERVICE_INSTALLED: u32 = 100;
pub const EVENT_SERVICE_STARTED: u32 = 101;
pub const EVENT_SERVICE_STOPPED: u32 = 102;
pub const EVENT_SERVICE_RELOAD_REQUESTED: u32 = 103;
pub const EVENT_SERVICE_CONFIG_ERROR: u32 = 200;
pub const EVENT_SERVICE_LOGGING_ERROR: u32 = 201;
pub const EVENT_SERVICE_RUNTIME_ERROR: u32 = 202;
pub const EVENT_SERVICE_BIND_ERROR: u32 = 203;
pub const EVENT_SERVICE_SERVER_ERROR: u32 = 204;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventLevel {
    Info,
    Warning,
    Error,
}

impl EventLevel {
    fn report_type(self) -> REPORT_EVENT_TYPE {
        match self {
            EventLevel::Info => EVENTLOG_INFORMATION_TYPE,
            EventLevel::Warning => EVENTLOG_WARNING_TYPE,
            EventLevel::Error => EVENTLOG_ERROR_TYPE,
        }
    }
}

pub fn register_source() -> io::Result<()> {
    let key_path = event_source_registry_path(SERVICE_NAME);
    let key_path = wide_null(OsStr::new(&key_path));
    let mut key: HKEY = std::ptr::null_mut();
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            key_path.as_ptr(),
            0,
            ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            ptr::null(),
            &mut key,
            ptr::null_mut(),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(win32_error(status));
    }
    let key = RegistryKey(key);

    let event_message_file = wide_null(OsStr::new(EVENT_MESSAGE_FILE));
    set_registry_expand_string(key.0, "EventMessageFile", &event_message_file)?;
    set_registry_dword(key.0, "TypesSupported", supported_event_types())?;
    Ok(())
}

pub fn unregister_source() -> io::Result<()> {
    let key_path = event_source_registry_path(SERVICE_NAME);
    let key_path = wide_null(OsStr::new(&key_path));
    let status = unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, key_path.as_ptr()) };
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        let err = win32_error(status);
        if err.kind() == io::ErrorKind::NotFound {
            Ok(())
        } else {
            Err(err)
        }
    }
}

pub fn report(level: EventLevel, event_id: u32, message: impl AsRef<str>) {
    let _ = try_report(level, event_id, message.as_ref());
}

fn try_report(level: EventLevel, event_id: u32, message: &str) -> io::Result<()> {
    let source = wide_null(OsStr::new(SERVICE_NAME));
    let handle = unsafe { RegisterEventSourceW(ptr::null(), source.as_ptr()) };
    if handle.is_null() {
        return Err(last_error());
    }
    let event_source = EventSource(handle);

    let message = wide_null(OsStr::new(message));
    let strings = [message.as_ptr()];
    let ok = unsafe {
        ReportEventW(
            event_source.0,
            level.report_type(),
            0,
            event_id,
            ptr::null_mut(),
            strings.len() as u16,
            0,
            strings.as_ptr(),
            ptr::null(),
        )
    };
    if ok == 0 {
        Err(last_error())
    } else {
        Ok(())
    }
}

fn set_registry_expand_string(key: HKEY, name: &str, value: &[u16]) -> io::Result<()> {
    let name = wide_null(OsStr::new(name));
    let bytes = wide_bytes(value);
    let status = unsafe {
        RegSetValueExW(
            key,
            name.as_ptr(),
            0,
            REG_EXPAND_SZ,
            bytes.as_ptr(),
            bytes.len() as u32,
        )
    };
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(win32_error(status))
    }
}

fn set_registry_dword(key: HKEY, name: &str, value: u32) -> io::Result<()> {
    let name = wide_null(OsStr::new(name));
    let bytes = value.to_le_bytes();
    let status = unsafe {
        RegSetValueExW(
            key,
            name.as_ptr(),
            0,
            REG_DWORD,
            bytes.as_ptr(),
            bytes.len() as u32,
        )
    };
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(win32_error(status))
    }
}

fn supported_event_types() -> u32 {
    (EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE) as u32
}

fn event_source_registry_path(source: &str) -> String {
    format!("{EVENT_LOG_APPLICATION_PATH}\\{source}")
}

fn wide_null(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

fn wide_bytes(value: &[u16]) -> &[u8] {
    unsafe { std::slice::from_raw_parts(value.as_ptr().cast::<u8>(), std::mem::size_of_val(value)) }
}

fn win32_error(code: u32) -> io::Error {
    io::Error::from_raw_os_error(code as i32)
}

fn last_error() -> io::Error {
    win32_error(unsafe { GetLastError() })
}

struct RegistryKey(HKEY);

impl Drop for RegistryKey {
    fn drop(&mut self) {
        let _ = unsafe { RegCloseKey(self.0) };
    }
}

struct EventSource(windows_sys::Win32::Foundation::HANDLE);

impl Drop for EventSource {
    fn drop(&mut self) {
        let _ = unsafe { DeregisterEventSource(self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_path_uses_application_log_source() {
        assert_eq!(
            event_source_registry_path("Alighieri"),
            r"SYSTEM\CurrentControlSet\Services\EventLog\Application\Alighieri"
        );
    }

    #[test]
    fn supported_types_include_info_warning_and_error() {
        assert_eq!(
            supported_event_types(),
            (EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE) as u32
        );
    }

    #[test]
    fn event_ids_fit_system_message_resource_range() {
        let event_ids = [
            EVENT_SERVICE_INSTALLED,
            EVENT_SERVICE_STARTED,
            EVENT_SERVICE_STOPPED,
            EVENT_SERVICE_RELOAD_REQUESTED,
            EVENT_SERVICE_CONFIG_ERROR,
            EVENT_SERVICE_LOGGING_ERROR,
            EVENT_SERVICE_RUNTIME_ERROR,
            EVENT_SERVICE_BIND_ERROR,
            EVENT_SERVICE_SERVER_ERROR,
        ];

        assert!(event_ids
            .iter()
            .all(|event_id| (1..=1000).contains(event_id)));
    }

    #[test]
    fn wide_null_terminates_strings() {
        let wide = wide_null(OsStr::new("Alighieri"));
        assert_eq!(wide.last(), Some(&0));
        assert_eq!(wide.iter().filter(|ch| **ch == 0).count(), 1);
    }
}
