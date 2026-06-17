//! Windows-specific service hosting and management.

pub mod event_log;
pub mod service;
pub mod service_manager;

pub use service_manager::handle_service_cli;
