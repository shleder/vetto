//! Reusable vetto components.
//!
//! The binary in [`main`](../main.rs) is intentionally a thin session
//! orchestrator.  Keeping the implementation modules behind this library
//! boundary lets integration tests, benchmarks, and downstream tooling use
//! the same policy, sandbox, observation, PTY, and report code as the CLI.

#[doc(hidden)]
pub mod bench_support;
pub mod classifier;
pub mod cli;
pub mod config;
pub mod daemon;
pub mod doctor;
pub mod error;
pub mod events;
pub mod init;
pub mod logger;
pub mod mcp;
pub mod multi;
pub mod policy;
#[cfg(unix)]
pub mod pty;
pub mod remote;
pub mod report;
pub mod rescue;
pub mod sandbox;
pub mod shim;
#[cfg(unix)]
pub mod tui;
pub mod verify;
