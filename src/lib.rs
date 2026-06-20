//! Alighieri — a lightweight, secure, asynchronous SOCKS5 proxy server.
//!
//! The crate is organised into focused modules:
//!
//! - [`errors`]: the crate-wide error type.
//! - [`abuse`]: optional per-client rate limits and abuse controls.
//! - [`client_stream`]: accepted plaintext/TLS client stream wrapper.
//! - [`net`]: CIDR / address-spec primitives used by the access-control engine.
//! - [`config`]: the Dante-inspired configuration model and parser.
//! - [`dns`]: DNS result ordering and post-resolution safety policy.
//! - [`metrics`]: optional Prometheus-style runtime counters.
//! - [`acl`]: rule evaluation (the access-control engine).
//! - [`auth`]: username/password credential storage and verification.
//! - [`socks5`]: SOCKS5 (RFC 1928) and username/password auth (RFC 1929) wire
//!   primitives.
//! - [`server`]: the listener/accept loop.
//! - [`connection`]: the per-client SOCKS5 state machine.
//! - [`relay`]: TCP bidirectional relay and the UDP associate relay.
//! - [`runtime`]: shared process/service runtime helpers.
//! - [`tls`]: optional TLS listener setup.

pub mod abuse;
pub mod acl;
pub mod auth;
pub mod client_stream;
pub mod config;
pub mod connection;
pub mod dns;
pub mod errors;
pub mod metrics;
pub mod net;
pub mod platform;
pub mod proxy_protocol;
pub mod relay;
pub mod runtime;
pub mod server;
pub mod socks5;
pub mod throttle;
pub mod tls;
pub mod util;
