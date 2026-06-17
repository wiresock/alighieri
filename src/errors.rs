use thiserror::Error;

use crate::socks5::Reply;

/// Top-level error type for the Alighieri proxy.
#[derive(Debug, Error)]
pub enum Error {
    /// A configuration file could not be parsed or failed validation. The
    /// inner string carries a human-readable explanation (often with a line
    /// number) suitable for printing to the operator.
    #[error("configuration error: {0}")]
    Config(String),

    /// An underlying I/O failure (socket bind, accept, read, write, ...).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The client spoke something that is not valid SOCKS5.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Authentication failed (bad credentials or unsupported method).
    #[error("authentication failed")]
    AuthFailed,

    /// The request was denied by the access-control rules.
    #[error("access denied by rule")]
    AccessDenied,

    /// A SOCKS5 command was understood but is not supported by this server.
    #[error("command not supported")]
    CommandNotSupported,

    /// An operation exceeded its configured time budget.
    #[error("operation timed out")]
    Timeout,
}

impl Error {
    /// Maps an error encountered while servicing a request onto the SOCKS5
    /// reply code that should be returned to the client (RFC 1928 §6).
    ///
    /// Errors that occur before a request reply is meaningful (for example a
    /// handshake protocol error) still map to a sane default of
    /// [`Reply::GeneralFailure`].
    pub fn to_reply(&self) -> Reply {
        match self {
            Error::AccessDenied | Error::AuthFailed => Reply::ConnectionNotAllowed,
            Error::CommandNotSupported => Reply::CommandNotSupported,
            Error::Timeout => Reply::TtlExpired,
            Error::Io(e) => match e.kind() {
                std::io::ErrorKind::ConnectionRefused => Reply::ConnectionRefused,
                std::io::ErrorKind::TimedOut => Reply::TtlExpired,
                std::io::ErrorKind::AddrNotAvailable => Reply::HostUnreachable,
                std::io::ErrorKind::PermissionDenied => Reply::ConnectionNotAllowed,
                _ => Reply::NetworkUnreachable,
            },
            _ => Reply::GeneralFailure,
        }
    }
}

/// Convenient crate-wide result alias.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_error_display() {
        let e = Error::Config("line 3: bad keyword".into());
        assert_eq!(e.to_string(), "configuration error: line 3: bad keyword");
    }

    #[test]
    fn io_error_is_convertible() {
        let io = std::io::Error::new(std::io::ErrorKind::AddrInUse, "in use");
        let e: Error = io.into();
        assert!(e.to_string().contains("in use"));
    }

    #[test]
    fn access_denied_maps_to_not_allowed() {
        assert_eq!(Error::AccessDenied.to_reply(), Reply::ConnectionNotAllowed);
        assert_eq!(Error::AuthFailed.to_reply(), Reply::ConnectionNotAllowed);
    }

    #[test]
    fn command_unsupported_maps_through() {
        assert_eq!(
            Error::CommandNotSupported.to_reply(),
            Reply::CommandNotSupported
        );
    }

    #[test]
    fn io_refused_maps_to_refused() {
        let io = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "nope");
        assert_eq!(Error::Io(io).to_reply(), Reply::ConnectionRefused);
    }

    #[test]
    fn timeout_maps_to_ttl_expired() {
        assert_eq!(Error::Timeout.to_reply(), Reply::TtlExpired);
    }

    #[test]
    fn protocol_error_maps_to_general_failure() {
        assert_eq!(
            Error::Protocol("bad version".into()).to_reply(),
            Reply::GeneralFailure
        );
    }
}
