//! COM LocalServer and mstsc DVC AddIn registration.

use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, WIN32_ERROR};
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegSetValueExW, HKEY, HKEY_CURRENT_USER,
    HKEY_LOCAL_MACHINE, KEY_WRITE, REG_OPTION_NON_VOLATILE, REG_SZ,
};

/// Stable COM identity for the Alighieri out-of-process DVC plugin.
pub const PLUGIN_CLSID_TEXT: &str = "{508D8D20-12D7-4C2E-AB9C-79A38C5B6701}";
pub const PLUGIN_CLSID: windows::core::GUID =
    windows::core::GUID::from_u128(0x508d8d20_12d7_4c2e_ab9c_79a38c5b6701);
pub const ADDIN_NAME: &str = "AlighieriRdpTransport";

const CLSID_KEY: &str = "Software\\Classes\\CLSID\\{508D8D20-12D7-4C2E-AB9C-79A38C5B6701}";
const LOCAL_SERVER_KEY: &str =
    "Software\\Classes\\CLSID\\{508D8D20-12D7-4C2E-AB9C-79A38C5B6701}\\LocalServer32";
const ADDIN_KEY: &str =
    "Software\\Microsoft\\Terminal Server Client\\Default\\AddIns\\AlighieriRdpTransport";

struct RegistryKey(HKEY);

impl Drop for RegistryKey {
    fn drop(&mut self) {
        // SAFETY: this object exclusively owns the successful registry handle.
        unsafe {
            let _ = RegCloseKey(self.0);
        }
    }
}

pub fn register(machine_wide: bool) -> io::Result<()> {
    let executable = std::env::current_exe()?;
    register_path(machine_wide, &executable)
}

fn register_path(machine_wide: bool, executable: &Path) -> io::Result<()> {
    if !executable.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "COM LocalServer registration requires an absolute executable path",
        ));
    }
    let root = root(machine_wide);
    let local_server = create_key(root, LOCAL_SERVER_KEY)?;
    // Quote paths containing spaces and additionally set ServerExecutable so
    // COM activation cannot ambiguously parse the image path.
    let command = format!("\"{}\"", executable.display());
    set_string(&local_server, None, OsStr::new(&command))?;
    set_string(
        &local_server,
        Some("ServerExecutable"),
        executable.as_os_str(),
    )?;

    let addin = create_key(root, ADDIN_KEY)?;
    set_string(&addin, Some("Name"), OsStr::new(PLUGIN_CLSID_TEXT))?;
    Ok(())
}

pub fn unregister(machine_wide: bool) -> io::Result<()> {
    let root = root(machine_wide);
    delete_tree_if_present(root, ADDIN_KEY)?;
    delete_tree_if_present(root, CLSID_KEY)?;
    Ok(())
}

fn root(machine_wide: bool) -> HKEY {
    if machine_wide {
        HKEY_LOCAL_MACHINE
    } else {
        HKEY_CURRENT_USER
    }
}

fn create_key(root: HKEY, path: &str) -> io::Result<RegistryKey> {
    let path = wide(path);
    let mut key = HKEY::default();
    // SAFETY: all pointers refer to live, NUL-terminated buffers for the call;
    // `key` is initialized by Windows only on success and then RAII-owned.
    let status = unsafe {
        RegCreateKeyExW(
            root,
            PCWSTR(path.as_ptr()),
            0,
            PWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut key,
            None,
        )
    };
    win32_result(status)?;
    Ok(RegistryKey(key))
}

fn set_string(key: &RegistryKey, name: Option<&str>, value: &OsStr) -> io::Result<()> {
    let name = name.map(wide);
    let value: Vec<u16> = value.encode_wide().chain(std::iter::once(0)).collect();
    // SAFETY: u16 data is deliberately viewed as bytes for REG_SZ and remains
    // alive for the call. The optional name is NUL terminated when present.
    let bytes = unsafe {
        std::slice::from_raw_parts(value.as_ptr().cast::<u8>(), value.len() * size_of::<u16>())
    };
    let status = unsafe {
        RegSetValueExW(
            key.0,
            name.as_ref()
                .map_or(PCWSTR::null(), |name| PCWSTR(name.as_ptr())),
            0,
            REG_SZ,
            Some(bytes),
        )
    };
    win32_result(status)
}

fn delete_tree_if_present(root: HKEY, path: &str) -> io::Result<()> {
    let path = wide(path);
    // SAFETY: path is a live, NUL-terminated UTF-16 buffer for the call.
    let status = unsafe { RegDeleteTreeW(root, PCWSTR(path.as_ptr())) };
    if status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND {
        Ok(())
    } else {
        win32_result(status)
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn win32_result(status: WIN32_ERROR) -> io::Result<()> {
    if status.is_ok() {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status.0 as i32))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_identity_and_paths_are_stable() {
        assert_eq!(PLUGIN_CLSID_TEXT, "{508D8D20-12D7-4C2E-AB9C-79A38C5B6701}");
        assert_eq!(ADDIN_NAME, "AlighieriRdpTransport");
        assert!(CLSID_KEY.starts_with("Software\\Classes\\CLSID\\"));
        assert!(LOCAL_SERVER_KEY.ends_with("\\LocalServer32"));
        assert!(ADDIN_KEY.contains("Terminal Server Client\\Default\\AddIns"));
        assert_eq!(
            register_path(false, Path::new("alighieri-rdp-transport.exe"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
