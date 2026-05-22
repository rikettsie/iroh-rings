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
//! # Security model
//!
//! The registry enforces **what** is allowed: which peers may access which
//! resources, as declared by the operator. It does not authenticate **who** is
//! speaking — that is guaranteed by the transport layer (QUIC/TLS 1.3) before
//! the gate ever consults the registry. Custom backend implementations can
//! therefore trust that the [`EndpointId`] passed to [`Registry::is_allowed`]
//! has already been verified.
//!
//! # Implementing a custom backend
//!
//! 1. Implement [`Registry`] for your storage type.
//! 2. Run `registry_contract` in your test suite to verify behavioural correctness.

use iroh::EndpointId;

use crate::ring::{Ring, OPEN_RING_NAME};
use crate::Error;

/// An operation a peer may request on a resource.
///
/// Permissions are granted per ring–resource association: all members of a ring
/// share the same permission set on a given resource. There are no per-peer overrides.
///
/// The local registry owner implicitly holds all permissions on their own registry;
/// this enum governs what is delegated to remote peers.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Permission {
    /// Download a resource from the remote peer's registry.
    Read,
    /// Push or update a resource in a ring the peer is already a member of.
    ///
    /// A peer may only write into rings they belong to — WRITE does not bypass
    /// ring membership.
    Write,
    /// Remove the ring–resource association from the remote peer's registry.
    ///
    /// This does not destroy the underlying resource data. True deletion is a
    /// local-only operation reserved for the registry owner.
    Delete,
}

/// A type that identifies a resource by a byte sequence,
/// which is supposed to be unique.
///
/// The byte slice is transmitted over the wire and stored in the registry.
/// Implementations must return the same bytes for the same logical resource
/// across calls.
pub trait ResourceId {
    /// Returns the unique byte representation of this resource.
    fn as_bytes(&self) -> &[u8];
}

impl ResourceId for [u8; 32] {
    fn as_bytes(&self) -> &[u8] {
        self
    }
}

impl ResourceId for Vec<u8> {
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
/// Use `registry_contract` in tests to verify that a custom backend
/// satisfies the required behavioural invariants.
pub trait Registry {
    /// Creates a new ring with the given name.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RingNameEmpty`] or [`Error::RingNameInvalidChars`] if the
    /// name is invalid, [`Error::RingNameReserved`] if it is `"open"`,
    /// [`Error::RingAlreadyExists`] if a ring with that name already exists, or
    /// [`Error::Storage`] on a backend I/O failure.
    fn create_ring(&self, ring_name: &str) -> Result<(), Error>;

    /// Adds a peer to a ring.
    ///
    /// Idempotent: if the peer is already a member, only the nickname is
    /// updated when `nickname` is `Some`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RingNotFound`] if the ring does not exist, or
    /// [`Error::Storage`] on a backend I/O failure.
    fn add_peer_to_ring(
        &self,
        ring_name: &str,
        peer: EndpointId,
        nickname: Option<&str>,
    ) -> Result<(), Error>;

    /// Removes a peer from a ring.
    ///
    /// No-op if the peer is not a member.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RingNotFound`] if the ring does not exist, or
    /// [`Error::Storage`] on a backend I/O failure.
    fn remove_peer_from_ring(&self, ring_name: &str, peer: EndpointId) -> Result<(), Error>;

    /// Returns all `(peer, nickname)` pairs in the ring.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RingNotFound`] if the ring does not exist, or
    /// [`Error::Storage`] on a backend I/O failure.
    fn list_ring_peers(&self, ring_name: &str) -> Result<Vec<(EndpointId, Option<String>)>, Error>;

    /// Returns all rings, including the built-in open ring.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] on a backend I/O failure.
    fn list_rings(&self) -> Result<Vec<Ring>, Error>;

    /// Removes all ring associations from a resource, revoking access for all peers.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] on a backend I/O failure.
    fn remove_ring_from_resource<ResId: ResourceId>(&self, resource_id: ResId)
        -> Result<(), Error>;

    /// Returns the rings currently associated with a resource, together with
    /// the permission set each ring grants on it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] on a backend I/O failure.
    fn list_resource_rings<ResId: ResourceId>(
        &self,
        resource_id: ResId,
    ) -> Result<Vec<(Ring, Vec<Permission>)>, Error>;

    /// Associates a resource with a ring and grants the specified permissions
    /// to all members of that ring.
    ///
    /// If the ring is already associated with the resource, its permission set
    /// is replaced with the new one.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptyPermissionSet`] if `permissions` is empty,
    /// [`Error::RingNotFound`] if the ring does not exist, or
    /// [`Error::Storage`] on a backend I/O failure.
    fn add_ring_to_resource<ResId: ResourceId>(
        &self,
        resource_id: ResId,
        ring_name: &str,
        permissions: &[Permission],
    ) -> Result<(), Error>;

    /// Returns `true` if `peer` holds `permission` on `resource_id`.
    ///
    /// A peer holds a permission if it belongs to at least one ring associated
    /// with the resource that grants that permission — or if the open ring is
    /// associated with the resource and grants it (which applies to any peer).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] on a backend I/O failure.
    fn has_permission<ResId: ResourceId>(
        &self,
        peer: &EndpointId,
        resource_id: &ResId,
        permission: Permission,
    ) -> Result<bool, Error>;
}

/// Compute the updated ring–permission list when associating `ring_name` with a resource.
///
/// If `ring_name` is [`OPEN_RING_NAME`], all private rings are replaced with only
/// the open ring and its permissions. Otherwise, the open ring is removed and
/// `ring_name` is inserted (or its permissions updated if already present).
pub fn compute_resource_rings(
    existing: Vec<(String, Vec<Permission>)>,
    ring_name: &str,
    permissions: Vec<Permission>,
) -> Vec<(String, Vec<Permission>)> {
    if ring_name == OPEN_RING_NAME {
        vec![(OPEN_RING_NAME.to_string(), permissions)]
    } else {
        let mut kept: Vec<(String, Vec<Permission>)> = existing
            .into_iter()
            .filter(|(n, _)| n != OPEN_RING_NAME)
            .collect();
        if let Some(entry) = kept.iter_mut().find(|(n, _)| n == ring_name) {
            entry.1 = permissions;
        } else {
            kept.push((ring_name.to_string(), permissions));
        }
        kept
    }
}

/// Shared contract test, to be run against every [`Registry`] implementation:
/// each assertion enforces the behaviour all backends must satisfy.
#[cfg(test)]
pub fn registry_contract<R: Registry>(reg: &R) {
    fn make_resource(b: u8) -> [u8; 32] {
        [b; 32]
    }
    fn make_peer() -> EndpointId {
        iroh::SecretKey::generate().public()
    }

    // --- list_rings / create_ring ---

    assert!(reg.list_rings().unwrap().iter().any(|r| r.is_open()));

    reg.create_ring("friends").unwrap();
    assert!(reg
        .list_rings()
        .unwrap()
        .iter()
        .any(|r| r.as_str() == "friends"));

    assert!(reg.create_ring("friends").is_err()); // duplicate rejected
    assert!(reg.create_ring(OPEN_RING_NAME).is_err()); // reserved name rejected
    assert!(reg.create_ring("").is_err()); // empty name rejected
    assert!(reg.create_ring("my ring").is_err()); // whitespace rejected
    assert!(reg.create_ring("tab\there").is_err());
    assert!(reg.create_ring("ring\0name").is_err()); // nul rejected

    reg.create_ring("work").unwrap();
    let rings = reg.list_rings().unwrap();
    assert!(rings.iter().any(|r| r.as_str() == "friends"));
    assert!(rings.iter().any(|r| r.as_str() == "work"));
    assert_eq!(rings.len(), 3); // open + friends + work

    // --- add_peer_to_ring / remove_peer_from_ring / list_ring_peers ---

    let alice = make_peer();
    reg.add_peer_to_ring("friends", alice, Some("alice"))
        .unwrap();
    let peers = reg.list_ring_peers("friends").unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].1.as_deref(), Some("alice"));

    reg.add_peer_to_ring("friends", alice, None).unwrap(); // idempotent
    assert_eq!(reg.list_ring_peers("friends").unwrap().len(), 1);

    reg.remove_peer_from_ring("friends", alice).unwrap();
    assert_eq!(reg.list_ring_peers("friends").unwrap().len(), 0);

    assert!(reg.add_peer_to_ring("ghost", make_peer(), None).is_err());
    assert!(reg.remove_peer_from_ring("ghost", make_peer()).is_err());
    assert!(reg.list_ring_peers("ghost").is_err());

    let extra = make_peer();
    reg.remove_peer_from_ring("friends", extra).unwrap(); // noop when not a member
    assert_eq!(reg.list_ring_peers("friends").unwrap().len(), 0);

    // --- has_permission ---

    let resource = make_resource(0xab);
    let bob = make_peer();
    // no associations → all permissions denied
    assert!(!reg
        .has_permission(&bob, &resource, Permission::Read)
        .unwrap());
    assert!(!reg
        .has_permission(&bob, &resource, Permission::Write)
        .unwrap());
    assert!(!reg
        .has_permission(&bob, &resource, Permission::Delete)
        .unwrap());

    reg.add_peer_to_ring("friends", bob, None).unwrap();
    reg.add_ring_to_resource(resource, "friends", &[Permission::Read])
        .unwrap();
    assert!(reg
        .has_permission(&bob, &resource, Permission::Read)
        .unwrap()); // ring member with READ
    assert!(!reg
        .has_permission(&bob, &resource, Permission::Write)
        .unwrap()); // no WRITE granted

    reg.add_ring_to_resource(resource, "friends", &[Permission::Read, Permission::Write])
        .unwrap();
    assert!(reg
        .has_permission(&bob, &resource, Permission::Write)
        .unwrap()); // permissions updated

    let stranger = make_peer();
    assert!(!reg
        .has_permission(&stranger, &resource, Permission::Read)
        .unwrap()); // non-member denied

    reg.add_ring_to_resource(resource, OPEN_RING_NAME, &[Permission::Read])
        .unwrap();
    assert!(reg
        .has_permission(&stranger, &resource, Permission::Read)
        .unwrap()); // open ring allows anyone for READ
    assert!(!reg
        .has_permission(&stranger, &resource, Permission::Write)
        .unwrap()); // but not WRITE

    let resource_multi = make_resource(0x01);
    let peer_work = make_peer();
    reg.add_ring_to_resource(resource_multi, "friends", &[Permission::Read])
        .unwrap();
    reg.add_ring_to_resource(
        resource_multi,
        "work",
        &[Permission::Read, Permission::Write],
    )
    .unwrap();
    reg.add_peer_to_ring("work", peer_work, None).unwrap();
    assert!(reg
        .has_permission(&peer_work, &resource_multi, Permission::Write)
        .unwrap()); // member of ring with WRITE

    reg.remove_ring_from_resource(resource).unwrap();
    assert_eq!(reg.list_resource_rings(resource).unwrap().len(), 0);
    assert!(!reg
        .has_permission(&stranger, &resource, Permission::Read)
        .unwrap());

    // empty permission set is rejected
    assert!(reg
        .add_ring_to_resource(make_resource(0xac), "friends", &[])
        .is_err());

    // --- resource–ring association semantics ---

    assert_eq!(
        reg.list_resource_rings(make_resource(0xfe)).unwrap(),
        vec![]
    );
    assert!(reg
        .add_ring_to_resource(make_resource(0xfd), "ghost", &[Permission::Read])
        .is_err());

    // open ring clears all private rings
    let res_a = make_resource(0x02);
    reg.create_ring("ring_a").unwrap();
    reg.add_ring_to_resource(res_a, "ring_a", &[Permission::Read])
        .unwrap();
    reg.add_ring_to_resource(res_a, OPEN_RING_NAME, &[Permission::Read])
        .unwrap();
    let rings_a = reg.list_resource_rings(res_a).unwrap();
    assert_eq!(rings_a.len(), 1);
    assert_eq!(rings_a[0].0, Ring::new_open());

    // private ring clears the open ring
    let res_b = make_resource(0x03);
    reg.create_ring("ring_b").unwrap();
    reg.add_ring_to_resource(res_b, OPEN_RING_NAME, &[Permission::Read])
        .unwrap();
    reg.add_ring_to_resource(res_b, "ring_b", &[Permission::Read])
        .unwrap();
    let rings_b = reg.list_resource_rings(res_b).unwrap();
    assert_eq!(rings_b.len(), 1);
    assert_eq!(rings_b[0].0, Ring::new("ring_b").unwrap());

    // associating the same ring twice updates its permissions
    let res_c = make_resource(0x04);
    reg.create_ring("ring_c").unwrap();
    reg.add_ring_to_resource(res_c, "ring_c", &[Permission::Read])
        .unwrap();
    reg.add_ring_to_resource(res_c, "ring_c", &[Permission::Read, Permission::Write])
        .unwrap();
    let rings_c = reg.list_resource_rings(res_c).unwrap();
    assert_eq!(rings_c.len(), 1);
    assert!(rings_c[0].1.contains(&Permission::Write));

    // multiple private rings accumulate
    let res_d = make_resource(0x05);
    reg.create_ring("ring_d").unwrap();
    reg.create_ring("ring_e").unwrap();
    reg.add_ring_to_resource(res_d, "ring_d", &[Permission::Read])
        .unwrap();
    reg.add_ring_to_resource(res_d, "ring_e", &[Permission::Read, Permission::Write])
        .unwrap();
    let rings_d = reg.list_resource_rings(res_d).unwrap();
    assert_eq!(rings_d.len(), 2);
    assert!(rings_d
        .iter()
        .any(|(r, _)| r == &Ring::new("ring_d").unwrap()));
    assert!(rings_d
        .iter()
        .any(|(r, _)| r == &Ring::new("ring_e").unwrap()));

    // --- nicknames ---

    let nick_peer = make_peer();
    let no_nick_peer = make_peer();
    reg.create_ring("nick_ring").unwrap();

    reg.add_peer_to_ring("nick_ring", nick_peer, Some("alice"))
        .unwrap();
    let members = reg.list_ring_peers("nick_ring").unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].1.as_deref(), Some("alice"));

    reg.add_peer_to_ring("nick_ring", no_nick_peer, None)
        .unwrap();
    let found = reg.list_ring_peers("nick_ring").unwrap();
    assert_eq!(
        found.iter().find(|(p, _)| p == &no_nick_peer).unwrap().1,
        None
    );

    reg.add_peer_to_ring("nick_ring", nick_peer, Some("alice2"))
        .unwrap(); // update nickname
    let members = reg.list_ring_peers("nick_ring").unwrap();
    assert_eq!(members.len(), 2);
    assert_eq!(
        members
            .iter()
            .find(|(p, _)| p == &nick_peer)
            .unwrap()
            .1
            .as_deref(),
        Some("alice2")
    );

    reg.remove_peer_from_ring("nick_ring", nick_peer).unwrap();
    reg.add_peer_to_ring("nick_ring", nick_peer, None).unwrap(); // nickname cleared on removal
    let found = reg.list_ring_peers("nick_ring").unwrap();
    assert_eq!(found.iter().find(|(p, _)| p == &nick_peer).unwrap().1, None);

    // same peer can have different nicknames in different rings
    let cross_peer = make_peer();
    reg.create_ring("nick_ring2").unwrap();
    reg.add_peer_to_ring("nick_ring", cross_peer, Some("name_a"))
        .unwrap();
    reg.add_peer_to_ring("nick_ring2", cross_peer, Some("name_b"))
        .unwrap();
    let r1 = reg.list_ring_peers("nick_ring").unwrap();
    let r2 = reg.list_ring_peers("nick_ring2").unwrap();
    assert_eq!(
        r1.iter()
            .find(|(p, _)| p == &cross_peer)
            .unwrap()
            .1
            .as_deref(),
        Some("name_a")
    );
    assert_eq!(
        r2.iter()
            .find(|(p, _)| p == &cross_peer)
            .unwrap()
            .1
            .as_deref(),
        Some("name_b")
    );

    // members with and without nicknames coexist in the same ring
    let nicks: Vec<_> = reg
        .list_ring_peers("nick_ring")
        .unwrap()
        .into_iter()
        .map(|(_, n)| n)
        .collect();
    assert!(nicks.iter().any(|n| n.as_deref() == Some("name_a")));
    assert!(nicks.iter().any(|n| n.is_none()));
}
