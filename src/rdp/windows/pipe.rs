//! Local named-pipe bridge between Alighieri and the out-of-process COM server.

use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::time::Duration;

use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{LocalFree, BOOL, ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

/// Local-only pipe used by the single-session MVP.
pub const PIPE_NAME: &str = r"\\.\pipe\alighieri-rdp-v1";

/// The object owner (the interactive user running the COM server) and Local
/// System have full access. The protected DACL prevents inherited broad grants.
const PIPE_SDDL: &str = "D:P(A;;GA;;;OW)(A;;GA;;;SY)";

struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl SecurityDescriptor {
    fn owner_only() -> io::Result<Self> {
        let sddl: Vec<u16> = PIPE_SDDL.encode_utf16().chain(std::iter::once(0)).collect();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `sddl` is NUL-terminated and `descriptor` is an out pointer.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
            .map_err(windows_error)?;
        }
        Ok(Self(descriptor))
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: the conversion API allocated this descriptor with LocalAlloc
            // and this RAII object owns it exactly once.
            unsafe {
                let _ = LocalFree(HLOCAL(self.0 .0));
            }
        }
    }
}

/// Creates the single local bridge endpoint with a protected DACL. Using the
/// first-instance flag detects a pre-existing name and fails closed rather than
/// connecting the bridge to an untrusted server.
pub fn create_server() -> io::Result<NamedPipeServer> {
    create_server_at(PIPE_NAME)
}

fn create_server_at(pipe_name: &str) -> io::Result<NamedPipeServer> {
    let descriptor = SecurityDescriptor::owner_only()?;
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0 .0,
        bInheritHandle: BOOL(0),
    };
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .access_inbound(true)
        .access_outbound(true);
    // SAFETY: `attributes` and its descriptor remain alive through CreateNamedPipeW;
    // Windows copies the security descriptor into the new kernel object.
    unsafe {
        options.create_with_security_attributes_raw(
            pipe_name,
            (&mut attributes as *mut SECURITY_ATTRIBUTES).cast::<c_void>(),
        )
    }
}

/// Connects Alighieri to an active COM bridge. Absence is reported immediately;
/// a busy single instance is retried briefly so reconnect races do not fail a
/// SOCKS request spuriously.
pub async fn connect_client() -> io::Result<NamedPipeClient> {
    let mut busy_retries = 0u8;
    loop {
        match ClientOptions::new().open(PIPE_NAME) {
            Ok(client) => return Ok(client),
            Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY.0 as i32) => {
                if busy_retries == 10 {
                    return Err(error);
                }
                busy_retries += 1;
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(error) if error.raw_os_error() == Some(ERROR_FILE_NOT_FOUND.0 as i32) => {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "no active Alighieri RDP Dynamic Virtual Channel",
                ));
            }
            Err(error) => return Err(error),
        }
    }
}

fn windows_error(error: windows::core::Error) -> io::Error {
    let hresult = error.code().0 as u32;
    if hresult & 0xffff_0000 == 0x8007_0000 {
        io::Error::from_raw_os_error((hresult & 0x0000_ffff) as i32)
    } else {
        io::Error::other(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reads a live pipe's DACL back as SDDL through its kernel handle. Keeping
    /// this independent of [`PIPE_SDDL`] makes the test verify what Windows
    /// actually installed, rather than merely re-checking the input string.
    ///
    /// Returns `None` when the current account cannot read the descriptor. CI
    /// sets `ALIGHIERI_REQUIRE_DACL_TESTS`, so that path is enforced there while
    /// still allowing an unusually restricted developer account to skip it.
    fn read_dacl_sddl(server: &NamedPipeServer) -> Option<String> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::{LocalFree, ERROR_ACCESS_DENIED, HANDLE};
        use windows_sys::Win32::Security::Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
            SE_KERNEL_OBJECT,
        };
        use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};

        // SAFETY: the server owns a valid live kernel handle. `GetSecurityInfo`
        // allocates `psd` with LocalAlloc, and pointers returned inside it stay
        // valid until that descriptor is freed below.
        unsafe {
            let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            let rc = GetSecurityInfo(
                server.as_raw_handle() as HANDLE,
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut psd,
            );
            if rc == ERROR_ACCESS_DENIED {
                LocalFree(psd);
                return None;
            }
            assert_eq!(rc, 0, "GetSecurityInfo failed (code {rc})");

            let mut sddl_ptr: *mut u16 = std::ptr::null_mut();
            let mut len = 0u32;
            let ok = ConvertSecurityDescriptorToStringSecurityDescriptorW(
                psd,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut sddl_ptr,
                &mut len,
            );
            assert_ne!(ok, 0, "converting the pipe descriptor to SDDL failed");
            let chars = (len as usize).saturating_sub(1);
            let sddl = String::from_utf16_lossy(std::slice::from_raw_parts(sddl_ptr, chars));
            LocalFree(sddl_ptr.cast());
            LocalFree(psd);
            Some(sddl)
        }
    }

    fn skip_dacl_test_or_panic(reason: &str) {
        if std::env::var_os("ALIGHIERI_REQUIRE_DACL_TESTS").is_some_and(|v| !v.is_empty()) {
            panic!("a DACL test would skip but ALIGHIERI_REQUIRE_DACL_TESTS is set: {reason}");
        }
        eprintln!("skipping DACL test: {reason}");
    }

    #[test]
    fn pipe_name_is_local_and_sddl_is_protected() {
        assert!(PIPE_NAME.starts_with(r"\\.\pipe\"));
        assert!(PIPE_SDDL.starts_with("D:P"));
        assert!(PIPE_SDDL.contains(";;;OW"));
        assert!(!PIPE_SDDL.contains(";;;WD"));
    }

    #[tokio::test]
    async fn created_pipe_is_owner_system_only_and_single_instance() {
        let pipe_name = format!(r"\\.\pipe\alighieri-rdp-v1-test-{}", std::process::id());
        let server = create_server_at(&pipe_name).expect("the secured test pipe must be created");

        let error = match create_server_at(&pipe_name) {
            Ok(_) => panic!("a second first-instance pipe creation must be rejected"),
            Err(error) => error,
        };
        assert_eq!(
            error.raw_os_error(),
            Some(windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED as i32),
            "the duplicate first-instance creation must fail closed"
        );

        let Some(sddl) = read_dacl_sddl(&server) else {
            skip_dacl_test_or_panic("the secured pipe DACL is not readable by this account");
            return;
        };
        assert!(
            sddl.starts_with("D:P"),
            "the pipe DACL must be protected: {sddl}"
        );
        let aces: Vec<&str> = sddl
            .split(['(', ')'])
            .filter(|chunk| chunk.contains(';'))
            .collect();
        assert_eq!(
            aces.len(),
            2,
            "the pipe DACL must have exactly two ACEs: {sddl}"
        );
        assert!(
            aces.iter().all(|ace| ace.starts_with("A;")),
            "every pipe ACE must be an allow ACE: {sddl}"
        );
        let trustees: std::collections::BTreeSet<&str> = aces
            .iter()
            .filter_map(|ace| ace.rsplit(';').next())
            .collect();
        assert_eq!(
            trustees,
            std::collections::BTreeSet::from(["OW", "SY"]),
            "pipe DACL trustees must be exactly Owner Rights and SYSTEM: {sddl}"
        );
    }
}
