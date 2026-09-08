//! Local named-pipe bridge between Alighieri and the out-of-process COM server.

use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::time::Duration;

use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    LocalFree, BOOL, ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, ERROR_PIPE_BUSY, HANDLE,
    HLOCAL,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_KERNEL_OBJECT,
};
use windows::Win32::Security::{
    GetTokenInformation, TokenUser, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Local-only pipe used by the single-session MVP.
pub const PIPE_NAME: &str = r"\\.\pipe\alighieri-rdp-v1";

/// The explicitly assigned creating user and Local System have full access.
/// The protected DACL prevents inherited broad grants.
const PIPE_SDDL: &str = "D:P(A;;GA;;;OW)(A;;GA;;;SY)";

struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl SecurityDescriptor {
    fn owner_only() -> io::Result<Self> {
        // Elevated tokens can otherwise default the object owner to the
        // Administrators group. Pin OW to the creating user, regardless of UAC.
        let sddl = format!("O:{}{PIPE_SDDL}", current_user_sid()?);
        let sddl: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
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
/// first-instance flag detects a pre-existing name and fails closed. The client
/// separately authenticates the owner of its connected handle.
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
    connect_client_at(PIPE_NAME).await
}

async fn connect_client_at(pipe_name: &str) -> io::Result<NamedPipeClient> {
    let expected_owner = current_user_sid()?;
    let mut busy_retries = 0u8;
    loop {
        // Tokio uses SECURITY_IDENTIFICATION by default: opening a squatted
        // pipe must not let its server impersonate this process.
        match ClientOptions::new().open(pipe_name) {
            Ok(client) => {
                validate_server_owner(&client, &expected_owner)?;
                return Ok(client);
            }
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

fn validate_server_owner(client: &NamedPipeClient, expected_owner: &str) -> io::Result<()> {
    let mut owner = PSID::default();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: query the connected kernel object, not its replaceable name.
    // Windows allocates the descriptor; `owner` points inside that allocation.
    let result = unsafe {
        GetSecurityInfo(
            HANDLE(client.as_raw_handle()),
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            Some(&mut descriptor),
        )
    };
    let _descriptor = SecurityDescriptor(descriptor);
    if result.is_err() {
        return Err(io::Error::from_raw_os_error(result.0 as i32));
    }
    let owner = sid_string(owner)?;
    if owner == expected_owner || owner == "S-1-5-18" {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "RDP bridge pipe is not owned by the current user or Local System",
        ))
    }
}

fn current_user_sid() -> io::Result<String> {
    let mut token = HANDLE::default();
    // SAFETY: the process pseudo-handle is valid and token is writable.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
        .map_err(windows_error)?;
    // SAFETY: OpenProcessToken returned a new owned handle on success.
    let token = unsafe { OwnedHandle::from_raw_handle(token.0) };
    let mut length = 0;
    // SAFETY: the live token is queried only for the required buffer size.
    let query = unsafe {
        GetTokenInformation(
            HANDLE(token.as_raw_handle()),
            TokenUser,
            None,
            0,
            &mut length,
        )
    };
    let error = query.err().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned an empty TOKEN_USER",
        )
    })?;
    if error.code() != windows::core::HRESULT::from_win32(ERROR_INSUFFICIENT_BUFFER.0) {
        return Err(windows_error(error));
    }
    // usize storage supplies the alignment TOKEN_USER requires. The returned
    // SID remains valid while this buffer lives.
    let mut buffer = vec![0usize; (length as usize).div_ceil(size_of::<usize>())];
    // SAFETY: buffer has the required size/alignment and token remains live.
    unsafe {
        GetTokenInformation(
            HANDLE(token.as_raw_handle()),
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            length,
            &mut length,
        )
    }
    .map_err(windows_error)?;
    // SAFETY: GetTokenInformation initialized a correctly aligned TOKEN_USER.
    sid_string(unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid })
}

fn sid_string(sid: PSID) -> io::Result<String> {
    let mut text = PWSTR::null();
    // SAFETY: callers provide a SID in a live Windows-owned descriptor/token.
    unsafe { ConvertSidToStringSidW(sid, &mut text) }.map_err(windows_error)?;
    // SAFETY: successful conversion yields a NUL-terminated LocalAlloc string.
    let result = unsafe { text.to_string() }.map_err(io::Error::other);
    unsafe { LocalFree(HLOCAL(text.0.cast())) };
    result
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

    #[tokio::test]
    async fn client_authenticates_the_connected_pipe_owner_before_sending_data() {
        use tokio::io::AsyncReadExt;

        let pipe_name = format!(r"\\.\pipe\alighieri-rdp-owner-test-{}", std::process::id());
        let mut server = create_server_at(&pipe_name).unwrap();
        let client = connect_client_at(&pipe_name).await.unwrap();
        server.connect().await.unwrap();

        let owner = current_user_sid().unwrap();
        validate_server_owner(&client, &owner).unwrap();
        if owner != "S-1-5-18" {
            // The actual kernel object belongs to this user, not the unrelated
            // Guests SID. A permissive DACL alone cannot establish peer identity.
            assert_eq!(
                validate_server_owner(&client, "S-1-5-32-546")
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
        }
        let mut byte = [0];
        assert!(
            tokio::time::timeout(Duration::from_millis(25), server.read(&mut byte))
                .await
                .is_err(),
            "authentication must not send any application bytes"
        );
    }

    #[tokio::test]
    async fn live_pipe_dacl_grants_owner_system_and_denies_an_unrelated_sid() {
        use windows::Win32::Foundation::LUID;
        use windows::Win32::Security::Authorization::{
            AuthzAccessCheck, AuthzFreeContext, AuthzFreeResourceManager,
            AuthzInitializeContextFromSid, AuthzInitializeResourceManager, ConvertStringSidToSidW,
            AUTHZ_ACCESS_CHECK_FLAGS, AUTHZ_ACCESS_REPLY, AUTHZ_ACCESS_REQUEST,
            AUTHZ_AUDIT_EVENT_HANDLE, AUTHZ_CLIENT_CONTEXT_HANDLE, AUTHZ_RESOURCE_MANAGER_HANDLE,
            AUTHZ_RM_FLAG_NO_AUDIT, AUTHZ_SKIP_TOKEN_GROUPS,
        };
        use windows::Win32::Security::{DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION};
        use windows::Win32::Storage::FileSystem::{FILE_GENERIC_READ, FILE_GENERIC_WRITE};

        let pipe_name = format!(r"\\.\pipe\alighieri-rdp-access-test-{}", std::process::id());
        let server = create_server_at(&pipe_name).unwrap();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: query the live kernel object's installed security descriptor.
        let status = unsafe {
            GetSecurityInfo(
                HANDLE(server.as_raw_handle()),
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                None,
                None,
                None,
                None,
                Some(&mut descriptor),
            )
        };
        let descriptor = SecurityDescriptor(descriptor);
        assert!(status.is_ok(), "read live pipe security: {status:?}");
        let desired = (FILE_GENERIC_READ | FILE_GENERIC_WRITE).0;

        // Evaluate the installed descriptor with Windows' authorization engine.
        // Supplying explicit SIDs without account/group lookup avoids creating
        // users, depending on domain connectivity, or requiring elevation.
        for (sid, expected_access) in [
            (current_user_sid().unwrap(), true),
            ("S-1-5-18".to_owned(), true),
            ("S-1-5-21-1-2-3-1001".to_owned(), false),
        ] {
            let wide: Vec<u16> = sid.encode_utf16().chain(std::iter::once(0)).collect();
            let mut principal = PSID::default();
            let mut manager = AUTHZ_RESOURCE_MANAGER_HANDLE::default();
            let mut context = AUTHZ_CLIENT_CONTEXT_HANDLE::default();
            let mut granted = 0;
            let mut access_error = 0;
            let request = AUTHZ_ACCESS_REQUEST {
                DesiredAccess: desired,
                ..Default::default()
            };
            let mut reply = AUTHZ_ACCESS_REPLY {
                ResultListLength: 1,
                GrantedAccessMask: &mut granted,
                Error: &mut access_error,
                ..Default::default()
            };
            // SAFETY: all input/output storage lives through these calls;
            // handles and the converted SID are released before assertions.
            let result = unsafe {
                (|| -> windows::core::Result<()> {
                    ConvertStringSidToSidW(PCWSTR(wide.as_ptr()), &mut principal)?;
                    AuthzInitializeResourceManager(
                        AUTHZ_RM_FLAG_NO_AUDIT.0,
                        None,
                        None,
                        None,
                        PCWSTR::null(),
                        &mut manager,
                    )?;
                    AuthzInitializeContextFromSid(
                        AUTHZ_SKIP_TOKEN_GROUPS,
                        principal,
                        manager,
                        None,
                        LUID::default(),
                        None,
                        &mut context,
                    )?;
                    AuthzAccessCheck(
                        AUTHZ_ACCESS_CHECK_FLAGS(0),
                        context,
                        &request,
                        AUTHZ_AUDIT_EVENT_HANDLE::default(),
                        descriptor.0,
                        None,
                        &mut reply,
                        None,
                    )
                })()
            };
            unsafe {
                let _ = AuthzFreeContext(context);
                let _ = AuthzFreeResourceManager(manager);
                let _ = LocalFree(HLOCAL(principal.0));
            }
            result.expect("evaluate pipe DACL using AuthzAccessCheck");
            assert_eq!(
                access_error == 0 && granted & desired == desired,
                expected_access,
                "unexpected pipe access for {sid}: error={access_error}, granted={granted:#x}"
            );
        }
    }
}
