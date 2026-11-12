//! Windows integration for the RDP Dynamic Virtual Channel transport.

// Generated Win32/COM bindings: see scripts/generate-rdp-bindings.sh.
mod bindings;
pub(crate) mod client;
pub mod pdu;
pub mod pipe;
pub mod registration;
pub mod transport;
pub mod wts;
