#![warn(missing_docs)]
#![warn(unreachable_pub)]

//! Ring-based, permission-typed access control for resources over iroh protocols.
//!
//! A **ring** is a named group of peers. Resources are associated with rings together
//! with a set of [`Permission`]s; every member of a ring inherits those permissions on
//! the resource. There are no per-peer overrides — rings are the single access-control
//! unit.
//!
//! Three permissions cover the operations a remote peer may request:
//!
//! | [`Permission`] | Remote operation |
//! |---|---|
//! | `Read`   | Download the resource |
//! | `Write`  | Push or update the resource (only into rings the peer belongs to) |
//! | `Delete` | Remove the ring–resource association (underlying data is untouched) |
//!
//! The built-in [`OPEN_RING_NAME`] ring is read-only: it grants [`Permission::Read`]
//! to any peer regardless of membership.
//!
//! # Quick start
//!
//! 1. Choose a [`Registry`] backend ([`InMemoryRegistry`] or [`RedbRegistry`]).
//! 2. Create rings and add peers with [`Registry::create_ring`] /
//!    [`Registry::add_peer_to_ring`].
//! 3. Associate resources with rings and permissions via [`Registry::add_ring_to_resource`].
//! 4. Wrap your iroh endpoint with a [`protocol::RingGate`] to enforce access
//!    control on every incoming connection.

pub mod error;
pub mod protocol;
pub mod registry;

#[cfg(any(feature = "mem", feature = "redb"))]
pub mod backends;

#[cfg(feature = "fs")]
pub mod transfers;

mod ring;

pub use error::Error;
#[doc(inline)]
pub use protocol::{RingGate, Transfer, RINGS_ALPN as ALPN};
pub use registry::{Permission, Registry, ResourceId};
pub use ring::{Ring, OPEN_RING_NAME};

#[cfg(feature = "mem")]
pub use backends::memory::InMemoryRegistry;

#[cfg(feature = "redb")]
pub use backends::redb::RedbRegistry;

#[cfg(feature = "fs")]
pub use transfers::fs::FsTransfer;
