//! Platform-specific integration points.

#[cfg(all(target_os = "linux", feature = "installer-fs"))]
#[doc(hidden)]
pub mod linux;

#[cfg(windows)]
pub mod windows;
