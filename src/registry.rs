//! Core registry traits and the shared contract test.
//!
//! This module defines the two central traits that every backend must implement:
//!
//! - [`ResourceId`] — identifies a resource by a stable byte sequence.
//! - [`Registry`] — manages rings, peer membership, and resource–ring associations.
//!
//! The access-control rule is simple: a peer may access a resource if it belongs
//! to at least one ring associated with that resource, or if the built-in open
//! ring (`"open"`) is associated with it (which grants access to everyone).
//!
//! # Implementing a custom backend
//!
//! 1. Implement [`Registry`] for your storage type.
//! 2. Run [`registry_contract`] in your test suite to verify behavioural correctness.

use anyhow::Result;
use iroh::EndpointId;

use crate::ring::Ring;

/// A type that identifies a resource by a byte sequence,
/// which is supposed to be unique.
///
/// The byte slice is transmitted over the wire and stored in the registry.
/// Implementations must return the same bytes for the same logical resource
/// across calls.
pub trait ResourceId {
    fn as_bytes(&self) -> &[u8];
}

impl ResourceId for [u8; 32] {
    fn as_bytes(&self) -> &[u8] {
        self
    }
}

/// Manages rings, their peer membership, and the association between
/// resources and rings.
///
/// A peer is granted access to a resource if it belongs to at least one ring
/// associated with that resource, or if the open ring (`"open"`) is associated with it.
///
/// Use [`registry_contract`] in tests, to verify that a custom backend
/// satisfies the required behavioural invariants.
pub trait Registry {
    /// Creates a new ring with the given name.
    ///
    /// Fails if the name is reserved (`"open"`) or already in use.
    fn create_ring(&self, ring_name: &str) -> Result<()>;

    /// Adds a peer to a ring.
    ///
    /// Idempotent: if the peer is already a member, only the nickname is
    /// updated when `nickname` is `Some`.
    fn add_peer_to_ring(
        &self,
        ring_name: &str,
        peer: EndpointId,
        nickname: Option<&str>,
    ) -> Result<()>;

    /// Removes a peer from a ring.
    fn remove_peer_from_ring(&self, ring_name: &str, peer: EndpointId) -> Result<()>;

    /// Returns all `(peer, nickname)` pairs in the ring.
    fn list_ring_peers(&self, ring_name: &str) -> Result<Vec<(EndpointId, Option<String>)>>;

    /// Returns all rings, including the built-in open ring.
    fn list_rings(&self) -> Result<Vec<Ring>>;

    /// Removes all rings from a resource, revoking access for all peers.
    fn remove_ring_from_resource<ResId: ResourceId>(&self, resource_id: ResId) -> Result<()>;

    /// Returns the rings currently associated with a resource.
    fn list_resource_rings<ResId: ResourceId>(&self, resource_id: ResId) -> Result<Vec<Ring>>;

    /// Associate a resource with a ring, granting ring members access to it.
    fn add_ring_to_resource<ResId: ResourceId>(
        &self,
        resource_id: ResId,
        ring_name: &str,
    ) -> Result<()>;

    /// Returns `true` if `peer` is allowed to access `resource_id`.
    ///
    /// A peer is allowed if it belongs to at least one ring associated with the
    /// resource, or if the open ring is associated with it.
    fn is_allowed<ResId: ResourceId>(&self, peer: &EndpointId, resource_id: &ResId)
        -> Result<bool>;
}

/// Shared contract test, to be run against every [`Registry`] implementation:
/// each assertion enforce the behaviour all backends must satisfy.
#[cfg(test)]
pub fn registry_contract<R: Registry>(reg: &R) {
    use crate::ring::OPEN_RING_NAME;

    fn make_resource(b: u8) -> [u8; 32] {
        [b; 32]
    }
    fn make_peer() -> EndpointId {
        iroh::SecretKey::generate().public()
    }

    // list_rings always includes the open ring
    let rings = reg.list_rings().unwrap();
    assert!(rings.iter().any(|r| r.is_open()));

    // create_ring / list_rings
    reg.create_ring("friends").unwrap();
    assert!(reg
        .list_rings()
        .unwrap()
        .iter()
        .any(|r| r.as_str() == "friends"));

    // duplicate ring is rejected
    assert!(reg.create_ring("friends").is_err());

    // reserved name is rejected
    assert!(reg.create_ring(OPEN_RING_NAME).is_err());

    // add_peer_to_ring / list_ring_peers
    let alice = make_peer();
    reg.add_peer_to_ring("friends", alice, Some("alice"))
        .unwrap();
    let peers = reg.list_ring_peers("friends").unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].1.as_deref(), Some("alice"));

    // add_peer is idempotent
    reg.add_peer_to_ring("friends", alice, None).unwrap();
    assert_eq!(reg.list_ring_peers("friends").unwrap().len(), 1);

    // remove_peer_from_ring
    reg.remove_peer_from_ring("friends", alice).unwrap();
    assert_eq!(reg.list_ring_peers("friends").unwrap().len(), 0);

    // resource with no ring associations denies everyone
    let resource = make_resource(0xab);
    let bob = make_peer();
    assert!(!reg.is_allowed(&bob, &resource).unwrap());

    // member of an associated ring is allowed
    reg.add_peer_to_ring("friends", bob, None).unwrap();
    reg.add_ring_to_resource(resource, "friends").unwrap();
    assert!(reg.is_allowed(&bob, &resource).unwrap());

    // non-member is denied
    let stranger = make_peer();
    assert!(!reg.is_allowed(&stranger, &resource).unwrap());

    // open ring allows everyone
    reg.add_ring_to_resource(resource, OPEN_RING_NAME).unwrap();
    assert!(reg.is_allowed(&stranger, &resource).unwrap());

    // remove_ring_from_resource clears all access
    reg.remove_ring_from_resource(resource).unwrap();
    assert_eq!(reg.list_resource_rings(resource).unwrap().len(), 0);
    assert!(!reg.is_allowed(&stranger, &resource).unwrap());
}
