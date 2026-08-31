//! Versioned machine-output support for the local administration CLI.

use std::io::{Read, Write};
use std::process::ExitCode;

use serde::Serialize;
use zeroize::{Zeroize, Zeroizing};

pub(crate) const SCHEMA_VERSION: u32 = 1;
pub(crate) const MANAGEMENT_PROTOCOL_VERSION: u32 = 1;
pub(crate) const MAX_PASSWORD_BYTES: usize = alighieri::auth::RFC1929_FIELD_MAX_BYTES;
// Inspect a 256-byte password plus CRLF so it can be classified as an invalid
// RFC 1929 password; one additional byte distinguishes genuinely excessive
// input without ever growing the buffer beyond this small fixed ceiling.
const MAX_PASSWORD_FRAME_BYTES: usize = MAX_PASSWORD_BYTES + 3;

pub(crate) const FEATURES: &[&str] = &[
    "config.check-json",
    "user.add-json",
    "user.delete-json",
    "user.list-json",
    "user.verify-json",
    "user.password-stdin",
    "user.target-userlist",
    "user.target-config",
];

#[derive(Serialize)]
struct SuccessEnvelope<T> {
    schema_version: u32,
    ok: bool,
    operation: &'static str,
    result: T,
}

#[derive(Serialize)]
struct ErrorEnvelope {
    schema_version: u32,
    ok: bool,
    operation: &'static str,
    error: ManagementError,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ManagementErrorCode {
    InvalidArguments,
    InvalidUsername,
    InvalidPassword,
    PasswordStdinReadFailed,
    PasswordInputTooLarge,
    ConfigLoadFailed,
    UserlistNotConfigured,
    UserlistNotActive,
    ExternalAuthBackend,
    RelativeUserlistNotSupported,
    UserlistReadFailed,
    UserlistParseFailed,
    UserlistUpdateFailed,
    UserNotFound,
    CredentialsRejected,
    SerializationFailed,
    InternalError,
}

#[derive(Debug, Serialize)]
pub(crate) struct ManagementError {
    pub(crate) code: ManagementErrorCode,
    pub(crate) message: String,
}

impl ManagementError {
    pub(crate) fn new(code: ManagementErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct CapabilitiesResult {
    product: &'static str,
    version: &'static str,
    target_os: &'static str,
    target_arch: &'static str,
    management_protocol_version: u32,
    features: &'static [&'static str],
}

impl CapabilitiesResult {
    pub(crate) fn current() -> Self {
        Self {
            product: "alighieri",
            version: env!("CARGO_PKG_VERSION"),
            target_os: std::env::consts::OS,
            target_arch: std::env::consts::ARCH,
            management_protocol_version: MANAGEMENT_PROTOCOL_VERSION,
            features: FEATURES,
        }
    }
}

#[derive(Serialize)]
pub(crate) struct AddResult {
    pub(crate) username: String,
    pub(crate) userlist: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) config: Option<String>,
    pub(crate) action: &'static str,
    pub(crate) changed: bool,
}

#[derive(Serialize)]
pub(crate) struct DeleteResult {
    pub(crate) username: String,
    pub(crate) userlist: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) config: Option<String>,
    pub(crate) deleted: bool,
    pub(crate) changed: bool,
}

#[derive(Serialize)]
pub(crate) struct ListResult {
    pub(crate) userlist: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) config: Option<String>,
    pub(crate) count: usize,
    pub(crate) users: Vec<String>,
}

#[derive(Serialize)]
pub(crate) struct VerifyResult {
    pub(crate) username: String,
    pub(crate) userlist: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) config: Option<String>,
    pub(crate) verified: bool,
}

pub(crate) fn emit_success<T: Serialize>(operation: &'static str, result: T) -> ExitCode {
    let envelope = SuccessEnvelope {
        schema_version: SCHEMA_VERSION,
        ok: true,
        operation,
        result,
    };
    emit_serializable(operation, &envelope)
}

pub(crate) fn emit_error(operation: &'static str, error: ManagementError) -> ExitCode {
    let envelope = ErrorEnvelope {
        schema_version: SCHEMA_VERSION,
        ok: false,
        operation,
        error,
    };
    emit_serializable(operation, &envelope);
    ExitCode::FAILURE
}

fn emit_serializable<T: Serialize>(operation: &'static str, value: &T) -> ExitCode {
    let (mut document, serialization_succeeded) = match serde_json::to_vec(value) {
        Ok(document) => (document, true),
        Err(_) => {
            let fallback = ErrorEnvelope {
                schema_version: SCHEMA_VERSION,
                ok: false,
                operation,
                error: ManagementError::new(
                    ManagementErrorCode::SerializationFailed,
                    "failed to serialize management response",
                ),
            };
            match serde_json::to_vec(&fallback) {
                Ok(document) => (document, false),
                Err(_) => return ExitCode::FAILURE,
            }
        }
    };
    document.push(b'\n');
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    if stdout.write_all(&document).is_ok() && serialization_succeeded {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// A password buffer that is cleared on drop and deliberately implements none
/// of `Debug`, `Display`, or `Serialize`.
pub(crate) struct SecretString(Zeroizing<String>);

impl SecretString {
    pub(crate) fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    pub(crate) fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(any(unix, windows))]
pub(crate) fn read_password_stdin() -> Result<SecretString, ManagementError> {
    let mut stdin = unbuffered_stdin().map_err(|_| password_stdin_read_error())?;
    read_password_record(&mut stdin)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn read_password_stdin() -> Result<SecretString, ManagementError> {
    // Do not fall back to Stdin::lock(): its process-global buffer is not
    // zeroized. Unix and Windows are the supported management CLI targets.
    Err(password_stdin_read_error())
}

#[cfg(unix)]
fn unbuffered_stdin() -> std::io::Result<std::fs::File> {
    use std::os::fd::AsFd;

    // Stdin::lock() reads through a process-global BufReader whose consumed
    // bytes are not zeroized. Duplicate the descriptor and read through File
    // so the bounded Zeroizing buffer below is the only userspace read buffer
    // owned by this process.
    std::io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .map(Into::into)
}

#[cfg(windows)]
fn unbuffered_stdin() -> std::io::Result<std::fs::File> {
    use std::os::windows::io::AsHandle;

    // As on Unix, File reads the duplicated standard handle directly instead
    // of routing the password through std's process-global stdin buffer.
    std::io::stdin()
        .as_handle()
        .try_clone_to_owned()
        .map(Into::into)
}

fn password_stdin_read_error() -> ManagementError {
    ManagementError::new(
        ManagementErrorCode::PasswordStdinReadFailed,
        "failed to read password from stdin",
    )
}

fn read_password_record(reader: &mut impl Read) -> Result<SecretString, ManagementError> {
    // Read at most one byte beyond the largest valid frame. This both detects
    // excess input and keeps allocation bounded before the password is parsed.
    // Every read targets zeroizing storage directly; no temporary userspace
    // buffer ever owns the password bytes.
    let mut bytes = Zeroizing::new(vec![0_u8; MAX_PASSWORD_FRAME_BYTES + 1]);
    let mut filled = 0;
    while filled < bytes.len() {
        match reader.read(&mut bytes[filled..]) {
            Ok(0) => break,
            Ok(count) => filled += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(password_stdin_read_error()),
        }
    }
    bytes.truncate(filled);

    if bytes.len() > MAX_PASSWORD_FRAME_BYTES {
        return Err(ManagementError::new(
            ManagementErrorCode::PasswordInputTooLarge,
            "password input exceeds the maximum framed size",
        ));
    }

    if bytes.ends_with(b"\r\n") {
        let new_len = bytes.len() - 2;
        bytes.truncate(new_len);
    } else if bytes.ends_with(b"\n") {
        let new_len = bytes.len() - 1;
        bytes.truncate(new_len);
    }

    if bytes.contains(&b'\n') || bytes.contains(&b'\r') {
        return Err(ManagementError::new(
            ManagementErrorCode::InvalidPassword,
            "stdin must contain exactly one password record",
        ));
    }
    if bytes.len() > MAX_PASSWORD_BYTES {
        return Err(ManagementError::new(
            ManagementErrorCode::InvalidPassword,
            "password must not exceed 255 bytes",
        ));
    }

    let owned = std::mem::take(&mut *bytes);
    match String::from_utf8(owned) {
        Ok(password) => Ok(SecretString::new(password)),
        Err(error) => {
            let mut invalid = error.into_bytes();
            invalid.zeroize();
            Err(ManagementError::new(
                ManagementErrorCode::InvalidPassword,
                "password input must be valid UTF-8",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(mut input: &[u8]) -> Result<SecretString, ManagementError> {
        read_password_record(&mut input)
    }

    #[test]
    fn password_record_accepts_lf_and_crlf() {
        assert_eq!(read(b"secret\n").unwrap().as_str(), "secret");
        assert_eq!(read(b"secret\r\n").unwrap().as_str(), "secret");
    }

    #[test]
    fn password_record_preserves_spaces() {
        assert_eq!(read(b"  secret  \n").unwrap().as_str(), "  secret  ");
    }

    #[test]
    fn password_record_rejects_additional_lines() {
        let error = match read(b"secret\nsecond\n") {
            Ok(_) => panic!("additional password record was accepted"),
            Err(error) => error,
        };
        assert_eq!(error.code, ManagementErrorCode::InvalidPassword);
    }

    #[test]
    fn password_record_is_bounded() {
        let input = vec![b'p'; MAX_PASSWORD_FRAME_BYTES + 1];
        let error = match read(&input) {
            Ok(_) => panic!("oversized password input was accepted"),
            Err(error) => error,
        };
        assert_eq!(error.code, ManagementErrorCode::PasswordInputTooLarge);
    }

    #[test]
    fn password_record_accepts_255_and_rejects_256_bytes() {
        assert_eq!(read(&vec![b'p'; 255]).unwrap().as_str().len(), 255);
        let error = match read(&vec![b'p'; 256]) {
            Ok(_) => panic!("256-byte password was accepted"),
            Err(error) => error,
        };
        assert_eq!(error.code, ManagementErrorCode::InvalidPassword);
    }

    #[test]
    fn password_record_maps_read_failures_without_exposing_input() {
        struct FailingReader;

        impl Read for FailingReader {
            fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("synthetic failure"))
            }
        }

        let error = match read_password_record(&mut FailingReader) {
            Ok(_) => panic!("failing reader unexpectedly produced a password"),
            Err(error) => error,
        };
        assert_eq!(error.code, ManagementErrorCode::PasswordStdinReadFailed);
        assert_eq!(error.message, "failed to read password from stdin");
    }

    #[test]
    fn password_record_retries_interrupted_chunked_reads() {
        struct InterruptedChunkedReader<'a> {
            remaining: &'a [u8],
            interrupted_once: bool,
            read_calls: usize,
            requested: Vec<usize>,
        }

        impl Read for InterruptedChunkedReader<'_> {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                self.read_calls += 1;
                self.requested.push(buffer.len());
                if !self.interrupted_once {
                    self.interrupted_once = true;
                    return Err(std::io::ErrorKind::Interrupted.into());
                }
                if self.remaining.is_empty() {
                    return Ok(0);
                }

                let count = self.remaining.len().min(buffer.len()).min(2);
                let (chunk, remaining) = self.remaining.split_at(count);
                buffer[..count].copy_from_slice(chunk);
                self.remaining = remaining;
                Ok(count)
            }
        }

        let mut reader = InterruptedChunkedReader {
            remaining: b"chunked secret\r\n",
            interrupted_once: false,
            read_calls: 0,
            requested: Vec::new(),
        };
        let password = read_password_record(&mut reader).unwrap();

        assert_eq!(password.as_str(), "chunked secret");
        assert!(reader.interrupted_once);
        assert!(reader.read_calls > 2);
        assert_eq!(
            reader.requested.first(),
            Some(&(MAX_PASSWORD_FRAME_BYTES + 1))
        );
        assert!(reader
            .requested
            .windows(2)
            .all(|requests| requests[1] <= requests[0]));
    }

    #[test]
    fn password_record_rejects_invalid_utf8() {
        let error = match read(&[0xff, b'\n']) {
            Ok(_) => panic!("invalid UTF-8 password was accepted"),
            Err(error) => error,
        };
        assert_eq!(error.code, ManagementErrorCode::InvalidPassword);
    }
}
