//! Alighieri — a lightweight, secure, asynchronous SOCKS5 proxy server.
//!
//! The supported library surface is intentionally small:
//!
//! - [`errors`]: the crate-wide error type.
//! - [`config`]: the Dante-inspired configuration model and parser.
//! - [`server`]: the listener/accept loop.
//! - [`runtime`]: shared process/service runtime helpers.
//! - `plugin` (feature `plugins`, off by default): the plugin SDK interface.
//!
//! Other public-but-hidden modules are implementation or binary-support shims,
//! not part of the compatibility contract.

mod abuse;
mod acl;
#[doc(hidden)]
pub mod auth;
mod client_stream;
pub mod config;
mod connection;
mod dns;
pub mod errors;
mod metrics;
mod net;
#[doc(hidden)]
pub mod platform;
#[cfg(feature = "plugins")]
pub mod plugin;
mod proxy_protocol;
mod relay;
pub mod runtime;
pub mod server;
#[doc(hidden)]
pub mod socks5;
mod throttle;
#[doc(hidden)]
pub mod tls;
#[doc(hidden)]
pub mod util;
