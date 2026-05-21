#![warn(missing_docs)]
#![warn(unreachable_pub)]

//! Ring-based access control for resources over iroh protocols.
//!
//! A **ring** is a named group of peers. Resources are associated with one or more
//! rings; a peer is granted access if it belongs to at least one of those rings.
//! The built-in [`OPEN_RING_NAME`] ring grants access to everyone, regardless of
//! membership.
//!
//! # Quick start
//!
//! 1. Choose a [`Registry`] backend ([`InMemoryRegistry`] or [`RedbRegistry`]).
//! 2. Create rings and add peers with [`Registry::create_ring`] /
//!    [`Registry::add_peer_to_ring`].
//! 3. Associate resources with rings via [`Registry::add_ring_to_resource`].
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
pub use protocol::{RingGate, Transfer, RINGS_ALPN as ALPN};
pub use registry::{Registry, ResourceId};
pub use ring::{Ring, OPEN_RING_NAME};

#[cfg(feature = "mem")]
pub use backends::memory::InMemoryRegistry;

#[cfg(feature = "redb")]
pub use backends::redb::RedbRegistry;

#[cfg(feature = "fs")]
pub use transfers::fs::FsTransfer;
