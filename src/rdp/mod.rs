//! RDP Dynamic Virtual Channel transport support.
//!
//! The wire protocol is platform-neutral. Windows-specific COM, WTS, and named
//! pipe integration lives in sibling modules and is compiled only where those
//! facilities are available.

#[cfg(any(windows, test))]
pub(crate) mod mux;
pub mod protocol;

#[cfg(windows)]
pub mod windows;
