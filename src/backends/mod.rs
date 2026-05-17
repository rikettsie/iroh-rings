//! [`Registry`](crate::registry::Registry) backend implementations.
//!
//! Each backend provides the same ring-management and access-control semantics;
//! they differ only in persistence and operational characteristics:
//!
//! | Backend | Feature flag | Persistence |
//! |---------|-------------|-------------|
//! | [`memory`] | `mem` | In-process only, lost on drop |
//! | [`redb`] | `redb` | Durable, embedded database |
//!
//! Choose [`memory`] for tests or ephemeral nodes; choose [`redb`] for
//! production nodes that must survive restarts.

#[cfg(feature = "mem")]
pub mod memory;

#[cfg(feature = "redb")]
pub mod redb;
