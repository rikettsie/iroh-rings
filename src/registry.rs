//! Core registry traits and the shared contract test.
//!
//! This module defines the two central traits that every backend must implement:
//!
//! - [`ResourceId`] — identifies a resource by a stable byte sequence.
//! - [`Registry`] — manages rings, peer membership, and resource–ring associations.
//!
//! # Permission model
//!
//! Permissions are attached to ring–resource associations: when you associate a ring
//! with a resource you also declare which [`Permission`]s that ring grants on it.
//! Every member of the ring inherits those permissions — there are no per-peer
//! overrides. Rings are the single access-control unit.
//!
//! The three permissions map to the operations a remote peer may request:
//!
//! | [`Permission`] | Remote operation |
//! |---|---|
//! | `Read`   | Download the resource |
//! | `Write`  | Push or update the resource (only into rings the peer belongs to) |
//! | `Delete` | Remove the ring–resource association (underlying data is untouched) |
//!
//! The local registry owner implicitly holds all permissions on their own registry;
//! this trait governs what is delegated to remote peers.
//!
//! The built-in open ring (`"open"`) is read-only: it grants [`Permission::Read`] to
//! any peer regardless of membership, and may not be associated with `Write` or
//! `Delete`. The open ring and private rings may coexist on the same resource —
//! a resource can be publicly readable (via the open ring) while remaining
//! writable or deletable only by members of a private ring.
//!
//! # Security model
//!
//! The registry enforces **what** is allowed: which peers may perform which operations
//! on which resources, as declared by the operator. It does not authenticate **who** is
//! speaking — that is guaranteed by the transport layer (QUIC/TLS 1.3) before
//! the gate ever consults the registry. Custom backend implementations can
//! therefore trust that the [`EndpointId`] passed to [`Registry::has_permission`]
//! has already been verified.
//!
//! # Membership expiry
//!
//! A ring membership may carry an `expires_at` ([`Registry::add_peer_to_ring`]).
//! Expiry is checked against the host's wall clock (`SystemTime::now`), which the
//! registry trusts: setting the clock backwards revives memberships that had
//! already expired. Backends evaluate expiry lazily wherever it matters
//! ([`Registry::has_permission`], [`Registry::list_ring_peers`], re-adding a
//! peer); [`Registry::evict_expired`] additionally reclaims storage for expired
//! rows, but is not required for the expiry itself to be enforced.
//!
//! # Implementing a custom backend
//!
//! 1. Implement [`Registry`] for your storage type.
//! 2. Run `registry_contract` in your test suite to verify behavioural correctness.

use std::time::SystemTime;

use iroh::EndpointId;

use crate::ring::Ring;
#[cfg(any(feature = "mem", feature = "redb", test))]
use crate::ring::OPEN_RING_NAME;
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

/// A peer's membership in a ring, as returned by [`Registry::list_ring_peers`].
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingMember {
    /// The member's endpoint id.
    pub peer: EndpointId,
    /// Optional display label per-ring
    pub label: Option<String>,
    /// When the membership expires; `None` if it never expires.
    pub expires_at: Option<SystemTime>,
}

impl RingMember {
    /// Creates a ring member entry.
    pub fn new(peer: EndpointId, label: Option<String>, expires_at: Option<SystemTime>) -> Self {
        Self {
            peer,
            label,
            expires_at,
        }
    }
}

/// A membership [`Registry::evict_expired`] removed.
///
/// The order of evicted entries in a call's result is unspecified.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvictedMembership {
    /// The ring the membership was removed from.
    pub ring_name: String,
    /// The peer whose membership was removed.
    pub peer: EndpointId,
}

impl EvictedMembership {
    /// Creates an evicted-membership entry.
    pub fn new(ring_name: String, peer: EndpointId) -> Self {
        Self { ring_name, peer }
    }
}

/// Parses peer-id bytes read back from storage into an [`EndpointId`].
///
/// A failure here means the stored bytes are corrupt, not that the caller
/// passed something invalid, so it is wrapped as [`Error::Storage`].
#[cfg(any(feature = "mem", feature = "redb"))]
pub(crate) fn decode_endpoint_id(bytes: &[u8; 32]) -> Result<EndpointId, Error> {
    EndpointId::from_bytes(bytes)
        .map_err(|e| Error::Storage(Box::new(std::io::Error::other(e.to_string()))))
}

/// Manages rings, their peer membership, and the association between
/// resources and rings.
///
/// Access is governed by [`Permission`]-typed ring–resource associations.
/// A peer may perform an operation on a resource if it belongs to at least one
/// ring associated with that resource which grants the corresponding permission,
/// or if the open ring (`"open"`) is associated with it and grants that permission.
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

    /// Adds a peer to a ring, optionally with a display label and an expiry.
    ///
    /// Idempotent for live members: re-adding an existing member updates its
    /// label when `label` is `Some` and its expiry when `expires_at` is
    /// `Some`. `None` leaves the existing value untouched, so an expiry
    /// cannot be cleared this way — remove the peer and add it again.
    ///
    /// A membership whose `expires_at` has passed counts as absent: the peer
    /// is denied by [`Registry::has_permission`], omitted from
    /// [`Registry::list_ring_peers`], and re-adding it starts a fresh
    /// membership (the old label and expiry are discarded).
    ///
    /// # Errors
    ///
    /// Returns [`Error::RingNotFound`] if the ring does not exist, or
    /// [`Error::Storage`] on a backend I/O failure.
    fn add_peer_to_ring(
        &self,
        ring_name: &str,
        peer: EndpointId,
        label: Option<&str>,
        expires_at: Option<SystemTime>,
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

    /// Returns every current [`RingMember`] of the ring.
    ///
    /// Expired memberships are omitted, permanently — not just until the
    /// next [`Registry::evict_expired`] call.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RingNotFound`] if the ring does not exist, or
    /// [`Error::Storage`] on a backend I/O failure.
    fn list_ring_peers(&self, ring_name: &str) -> Result<Vec<RingMember>, Error>;

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

    /// Permanently removes every membership whose `expires_at` is at or before `now`.
    ///
    /// Expiry is already enforced lazily — [`Registry::has_permission`] denies,
    /// and [`Registry::list_ring_peers`] omits, an expired membership even if
    /// this is never called. Eviction only reclaims the storage those rows
    /// hold; it has no effect on access decisions.
    ///
    /// Callers that want expired rows cleaned up periodically must call this
    /// themselves (e.g. on a timer) — no backend does so on its own.
    ///
    /// Returns every membership that was evicted. The order is unspecified.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] on a backend I/O failure.
    fn evict_expired(&self, now: SystemTime) -> Result<Vec<EvictedMembership>, Error>;
}

#[cfg(any(feature = "mem", feature = "redb"))]
/// Validates that `permissions` is non-empty and that the open ring is only paired with `Read`.
///
/// Both backends call this as the first step of `add_ring_to_resource`.
///
/// # Errors
///
/// Returns [`Error::EmptyPermissionSet`] or [`Error::OpenRingReadOnly`].
pub(crate) fn validate_ring_permissions(
    ring_name: &str,
    permissions: &[Permission],
) -> Result<(), Error> {
    if permissions.is_empty() {
        return Err(Error::EmptyPermissionSet);
    }
    if ring_name == OPEN_RING_NAME && permissions.iter().any(|p| !matches!(p, Permission::Read)) {
        return Err(Error::OpenRingReadOnly);
    }
    Ok(())
}

/// Compute the updated ring–permission list when associating `ring_name` with a resource.
///
/// If `ring_name` is already in `existing` its permission set is replaced; otherwise
/// it is appended. The open ring and private rings may coexist on the same resource.
pub fn compute_resource_rings(
    mut existing: Vec<(String, Vec<Permission>)>,
    ring_name: &str,
    permissions: Vec<Permission>,
) -> Vec<(String, Vec<Permission>)> {
    if let Some(entry) = existing.iter_mut().find(|(n, _)| n == ring_name) {
        entry.1 = permissions;
    } else {
        existing.push((ring_name.to_string(), permissions));
    }
    existing
}

/// Shared contract test, to be run against every [`Registry`] implementation:
/// each assertion enforces the behaviour all backends must satisfy.
#[cfg(test)]
pub fn registry_contract<R: Registry>(reg: &R) {
    use std::{
        ops::Add,
        time::{Duration, UNIX_EPOCH},
    };

    fn make_resource(b: u8) -> [u8; 32] {
        [b; 32]
    }
    fn make_peer() -> EndpointId {
        iroh::SecretKey::generate().public()
    }

    // list_rings / create_ring

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

    // add_peer_to_ring / remove_peer_from_ring / list_ring_peers

    let alice = make_peer();
    reg.add_peer_to_ring("friends", alice, Some("alice"), None)
        .unwrap();
    let peers = reg.list_ring_peers("friends").unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].label.as_deref(), Some("alice"));

    reg.add_peer_to_ring("friends", alice, None, None).unwrap(); // idempotent
    assert_eq!(reg.list_ring_peers("friends").unwrap().len(), 1);

    reg.remove_peer_from_ring("friends", alice).unwrap();
    assert_eq!(reg.list_ring_peers("friends").unwrap().len(), 0);

    assert!(reg
        .add_peer_to_ring("ghost", make_peer(), None, None)
        .is_err());
    assert!(reg.remove_peer_from_ring("ghost", make_peer()).is_err());
    assert!(reg.list_ring_peers("ghost").is_err());

    let extra = make_peer();
    reg.remove_peer_from_ring("friends", extra).unwrap(); // noop when not a member
    assert_eq!(reg.list_ring_peers("friends").unwrap().len(), 0);

    // has_permission

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

    reg.add_peer_to_ring("friends", bob, None, None).unwrap();
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
    assert!(reg
        .has_permission(&bob, &resource, Permission::Write)
        .unwrap()); // friends ring Write survives adding the open ring

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
    reg.add_peer_to_ring("work", peer_work, None, None).unwrap();
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

    // resource–ring association semantics

    assert_eq!(
        reg.list_resource_rings(make_resource(0xfe)).unwrap(),
        vec![]
    );
    assert!(reg
        .add_ring_to_resource(make_resource(0xfd), "ghost", &[Permission::Read])
        .is_err());

    // open ring rejects Write and Delete permissions
    let res_open_guard = make_resource(0xb0);
    assert!(reg
        .add_ring_to_resource(res_open_guard, OPEN_RING_NAME, &[Permission::Write])
        .is_err());
    assert!(reg
        .add_ring_to_resource(res_open_guard, OPEN_RING_NAME, &[Permission::Delete])
        .is_err());
    assert!(reg
        .add_ring_to_resource(
            res_open_guard,
            OPEN_RING_NAME,
            &[Permission::Read, Permission::Write]
        )
        .is_err());
    assert!(reg
        .add_ring_to_resource(res_open_guard, OPEN_RING_NAME, &[Permission::Read])
        .is_ok());

    // open ring and private rings coexist on the same resource
    let res_a = make_resource(0x02);
    reg.create_ring("ring_a").unwrap();
    reg.add_ring_to_resource(res_a, "ring_a", &[Permission::Write])
        .unwrap();
    reg.add_ring_to_resource(res_a, OPEN_RING_NAME, &[Permission::Read])
        .unwrap();
    let rings_a = reg.list_resource_rings(res_a).unwrap();
    assert_eq!(rings_a.len(), 2);
    assert!(rings_a.iter().any(|(r, _)| r.is_open()));
    assert!(rings_a
        .iter()
        .any(|(r, _)| r == &Ring::new("ring_a").unwrap()));

    // any peer can read via the open ring; only ring_a members can write
    let ring_a_peer = make_peer();
    reg.add_peer_to_ring("ring_a", ring_a_peer, None, None)
        .unwrap();
    let outsider = make_peer();
    assert!(reg
        .has_permission(&outsider, &res_a, Permission::Read)
        .unwrap());
    assert!(!reg
        .has_permission(&outsider, &res_a, Permission::Write)
        .unwrap());
    assert!(reg
        .has_permission(&ring_a_peer, &res_a, Permission::Read)
        .unwrap());
    assert!(reg
        .has_permission(&ring_a_peer, &res_a, Permission::Write)
        .unwrap());

    // adding the open ring to a resource that already has private rings keeps both
    let res_b = make_resource(0x03);
    reg.create_ring("ring_b").unwrap();
    reg.add_ring_to_resource(res_b, "ring_b", &[Permission::Read])
        .unwrap();
    reg.add_ring_to_resource(res_b, OPEN_RING_NAME, &[Permission::Read])
        .unwrap();
    let rings_b = reg.list_resource_rings(res_b).unwrap();
    assert_eq!(rings_b.len(), 2);
    assert!(reg
        .has_permission(&outsider, &res_b, Permission::Read)
        .unwrap()); // non-member can read via open ring

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

    // permissions of an existing ring survive when a second ring is added to the same resource
    let res_perm_survival = make_resource(0x06);
    let peer_survival = make_peer();
    reg.create_ring("survival_a").unwrap();
    reg.create_ring("survival_b").unwrap();
    reg.add_peer_to_ring("survival_a", peer_survival, None, None)
        .unwrap();
    reg.add_ring_to_resource(res_perm_survival, "survival_a", &[Permission::Read])
        .unwrap();
    reg.add_ring_to_resource(res_perm_survival, "survival_b", &[Permission::Write])
        .unwrap();
    assert!(
        reg.has_permission(&peer_survival, &res_perm_survival, Permission::Read)
            .unwrap(),
        "survival_a Read permission must survive adding survival_b to the same resource",
    );

    // labels

    let labeled_peer = make_peer();
    let unlabeled_peer = make_peer();
    reg.create_ring("nick_ring").unwrap();

    reg.add_peer_to_ring("nick_ring", labeled_peer, Some("alice"), None)
        .unwrap();
    let members = reg.list_ring_peers("nick_ring").unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].label.as_deref(), Some("alice"));

    reg.add_peer_to_ring("nick_ring", unlabeled_peer, None, None)
        .unwrap();
    let found = reg.list_ring_peers("nick_ring").unwrap();
    assert_eq!(
        found
            .iter()
            .find(|m| m.peer == unlabeled_peer)
            .unwrap()
            .label,
        None
    );

    reg.add_peer_to_ring("nick_ring", labeled_peer, Some("alice2"), None)
        .unwrap(); // update label
    let members = reg.list_ring_peers("nick_ring").unwrap();
    assert_eq!(members.len(), 2);
    assert_eq!(
        members
            .iter()
            .find(|m| m.peer == labeled_peer)
            .unwrap()
            .label
            .as_deref(),
        Some("alice2")
    );

    reg.remove_peer_from_ring("nick_ring", labeled_peer)
        .unwrap();
    reg.add_peer_to_ring("nick_ring", labeled_peer, None, None)
        .unwrap(); // label cleared on removal
    let found = reg.list_ring_peers("nick_ring").unwrap();
    assert_eq!(
        found.iter().find(|m| m.peer == labeled_peer).unwrap().label,
        None
    );

    // same peer can have different labels in different rings
    let cross_peer = make_peer();
    reg.create_ring("nick_ring2").unwrap();
    reg.add_peer_to_ring("nick_ring", cross_peer, Some("name_a"), None)
        .unwrap();
    reg.add_peer_to_ring("nick_ring2", cross_peer, Some("name_b"), None)
        .unwrap();
    let r1 = reg.list_ring_peers("nick_ring").unwrap();
    let r2 = reg.list_ring_peers("nick_ring2").unwrap();
    assert_eq!(
        r1.iter()
            .find(|m| m.peer == cross_peer)
            .unwrap()
            .label
            .as_deref(),
        Some("name_a")
    );
    assert_eq!(
        r2.iter()
            .find(|m| m.peer == cross_peer)
            .unwrap()
            .label
            .as_deref(),
        Some("name_b")
    );

    // members with and without labels coexist in the same ring
    let labels: Vec<_> = reg
        .list_ring_peers("nick_ring")
        .unwrap()
        .into_iter()
        .map(|m| m.label)
        .collect();
    assert!(labels.iter().any(|n| n.as_deref() == Some("name_a")));
    assert!(labels.iter().any(|n| n.is_none()));

    // members with expires_at set
    let short_lived_peer = make_peer();
    reg.create_ring("exp_ring").unwrap();
    let expiration = SystemTime::now().add(Duration::from_secs(10 * 3600));
    reg.add_peer_to_ring(
        "exp_ring",
        short_lived_peer,
        Some("name_ex"),
        Some(expiration),
    )
    .unwrap();
    let r1 = reg.list_ring_peers("exp_ring").unwrap();
    assert_eq!(
        r1.iter()
            .find(|m| m.peer == short_lived_peer)
            .unwrap()
            .expires_at,
        Some(expiration)
    );

    // expiry behaviour: expired means denied, hidden, and treated as absent on re-add

    let res_exp = make_resource(0x10);
    reg.create_ring("exp_a").unwrap();
    reg.add_ring_to_resource(res_exp, "exp_a", &[Permission::Read])
        .unwrap();
    let in_one_hour = || SystemTime::now().add(Duration::from_secs(3600));

    // an already-expired membership is denied and omitted from the listing
    let expired_peer = make_peer();
    reg.add_peer_to_ring("exp_a", expired_peer, Some("old"), Some(UNIX_EPOCH))
        .unwrap();
    assert!(!reg
        .has_permission(&expired_peer, &res_exp, Permission::Read)
        .unwrap());
    assert!(reg
        .list_ring_peers("exp_a")
        .unwrap()
        .iter()
        .all(|m| m.peer != expired_peer));

    // a future expiry keeps the member active
    let live_peer = make_peer();
    let live_expiry = in_one_hour();
    reg.add_peer_to_ring("exp_a", live_peer, Some("alice"), Some(live_expiry))
        .unwrap();
    assert!(reg
        .has_permission(&live_peer, &res_exp, Permission::Read)
        .unwrap());
    assert_eq!(
        reg.list_ring_peers("exp_a")
            .unwrap()
            .into_iter()
            .find(|m| m.peer == live_peer),
        Some(RingMember::new(
            live_peer,
            Some("alice".to_string()),
            Some(live_expiry)
        ))
    );

    // re-adding a live member with `expires_at: None` keeps its existing expiry
    reg.add_peer_to_ring("exp_a", live_peer, None, None)
        .unwrap();
    assert_eq!(
        reg.list_ring_peers("exp_a")
            .unwrap()
            .into_iter()
            .find(|m| m.peer == live_peer)
            .unwrap()
            .expires_at,
        Some(live_expiry)
    );

    // re-adding an already-expired member starts a fresh membership: the stale
    // label and expiry are dropped, not carried forward
    reg.add_peer_to_ring("exp_a", expired_peer, None, None)
        .unwrap();
    assert!(reg
        .has_permission(&expired_peer, &res_exp, Permission::Read)
        .unwrap());
    assert_eq!(
        reg.list_ring_peers("exp_a")
            .unwrap()
            .into_iter()
            .find(|m| m.peer == expired_peer),
        Some(RingMember::new(expired_peer, None, None))
    );

    // removing a member clears its expiry, so re-adding it plainly has none
    reg.remove_peer_from_ring("exp_a", live_peer).unwrap();
    reg.add_peer_to_ring("exp_a", live_peer, None, None)
        .unwrap();
    assert_eq!(
        reg.list_ring_peers("exp_a")
            .unwrap()
            .into_iter()
            .find(|m| m.peer == live_peer)
            .unwrap()
            .expires_at,
        None
    );

    // expiry is scoped to the ring: the same peer can be expired in one ring
    // and live in another
    let res_exp_b = make_resource(0x11);
    reg.create_ring("exp_b").unwrap();
    reg.add_ring_to_resource(res_exp_b, "exp_b", &[Permission::Write])
        .unwrap();
    let cross_ring_peer = make_peer();
    reg.add_peer_to_ring("exp_a", cross_ring_peer, None, Some(UNIX_EPOCH))
        .unwrap();
    reg.add_peer_to_ring("exp_b", cross_ring_peer, None, None)
        .unwrap();
    assert!(!reg
        .has_permission(&cross_ring_peer, &res_exp, Permission::Read)
        .unwrap());
    assert!(reg
        .has_permission(&cross_ring_peer, &res_exp_b, Permission::Write)
        .unwrap());

    // evict_expired: reclaims storage for expired rows without changing what
    // has_permission / list_ring_peers already report (they enforce expiry
    // lazily, with or without eviction ever running)

    reg.create_ring("evict_a").unwrap();
    reg.create_ring("evict_b").unwrap();
    let evict_now = SystemTime::now();

    // drain the backlog left by earlier sections (e.g. `cross_ring_peer`, whose
    // expired membership was never re-added and so was never cleaned up — by
    // design, since expiry is enforced lazily whether or not this is ever
    // called) to get a clean baseline for the no-op assertion below
    reg.evict_expired(evict_now).unwrap();

    // calling it again with nothing (newly) expired is a no-op
    assert_eq!(reg.evict_expired(evict_now).unwrap(), Vec::new());

    let live_in_a = make_peer();
    let expired_in_a = make_peer();
    let no_expiry_in_a = make_peer();
    let expired_in_b = make_peer();
    reg.add_peer_to_ring("evict_a", live_in_a, None, Some(in_one_hour()))
        .unwrap();
    reg.add_peer_to_ring("evict_a", expired_in_a, None, Some(UNIX_EPOCH))
        .unwrap();
    reg.add_peer_to_ring("evict_a", no_expiry_in_a, None, None)
        .unwrap();
    reg.add_peer_to_ring("evict_b", expired_in_b, None, Some(UNIX_EPOCH))
        .unwrap();

    let mut evicted = reg.evict_expired(evict_now).unwrap();
    evicted.sort_by(|a, b| a.ring_name.cmp(&b.ring_name));
    assert_eq!(
        evicted,
        vec![
            EvictedMembership::new("evict_a".to_string(), expired_in_a),
            EvictedMembership::new("evict_b".to_string(), expired_in_b),
        ]
    );

    // the non-expired members of the ring evicted from are untouched
    let remaining: Vec<_> = reg
        .list_ring_peers("evict_a")
        .unwrap()
        .into_iter()
        .map(|m| m.peer)
        .collect();
    assert!(remaining.contains(&live_in_a));
    assert!(remaining.contains(&no_expiry_in_a));
    assert!(!remaining.contains(&expired_in_a));

    // an evicted membership can be added back as if it had never existed
    reg.add_peer_to_ring("evict_a", expired_in_a, None, None)
        .unwrap();
    assert_eq!(
        reg.list_ring_peers("evict_a")
            .unwrap()
            .into_iter()
            .find(|m| m.peer == expired_in_a),
        Some(RingMember::new(expired_in_a, None, None))
    );

    // already-evicted rows are not evicted again
    assert_eq!(reg.evict_expired(evict_now).unwrap(), Vec::new());
}
