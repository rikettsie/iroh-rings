//! [`Transfer`](crate::protocol::gate::Transfer) implementations.
//!
//! A [`Transfer`](crate::protocol::gate::Transfer) defines the sub-protocol
//! that runs after the gate has verified ring membership. Implementations in
//! this module can be used as-is or as a reference for writing custom ones.
//!
//! | Implementation | Feature flag | Description |
//! |----------------|-------------|-------------|
//! | [`fs::FsTransfer`] | `fs` | Blob transfer via an iroh-blobs [`FsStore`](iroh_blobs::store::fs::Store) |
//!
//! See [`fs`] for a detailed explanation of the two-phase access check and the
//! bao-encoded streaming protocol, which you can follow when implementing other
//! transfer kinds (e.g. chat, video).

#[cfg(feature = "fs")]
pub mod fs;
