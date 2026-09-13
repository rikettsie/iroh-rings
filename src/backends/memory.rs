//! Non-persistent, in-memory [`Registry`] backed by hash maps.
//!
//! [`InMemoryRegistry`] is useful for tests and short-lived nodes that do not
//! need to survive a restart. All state is lost when the registry is dropped.
//!
//! For persistent storage, use the [`redb`](super::redb) backend instead.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use iroh::EndpointId;

use crate::registry::{Permission, Registry, ResourceId};
use crate::ring::{Ring, OPEN_RING_NAME};
use crate::Error;

#[derive(Default)]
struct Inner {
    rings: HashMap<String, Vec<[u8; 32]>>,
    labels: HashMap<(String, [u8; 32]), String>,
    /// Maps (ring_name, peer_id) → the instant the membership expires.
    /// Absent means the membership never expires.
    expiries: HashMap<(String, [u8; 32]), SystemTime>,
    /// Maps resource id → ordered list of (ring_name, permissions) pairs.
    resource_rings: HashMap<Vec<u8>, Vec<(String, Vec<Permission>)>>,
}

impl Inner {
    /// Returns `true` if the membership of `peer` in `ring_name` has expired as of `now`.
    ///
    /// Expired memberships are evicted lazily: they are ignored by
    /// [`Registry::has_permission`] and [`Registry::list_ring_peers`], and
    /// [`Registry::add_peer_to_ring`] treats them as absent.
    fn is_expired(&self, ring_name: &str, peer: &[u8; 32], now: SystemTime) -> bool {
        self.expiries
            .get(&(ring_name.to_string(), *peer))
            .is_some_and(|t| now >= *t)
    }
}

/// Thread-safe, non-persistent registry backed by in-memory hash maps;
/// it's useful for testing and for ephemeral nodes.
#[derive(Clone)]
pub struct InMemoryRegistry {
    inner: Arc<RwLock<Inner>>,
}

impl Default for InMemoryRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryRegistry {
    /// Creates an empty in-memory registry with the open ring pre-installed.
    pub fn new() -> Self {
        let mut rings = HashMap::new();
        rings.insert(OPEN_RING_NAME.to_string(), Vec::new());
        InMemoryRegistry {
            inner: Arc::new(RwLock::new(Inner {
                rings,
                ..Default::default()
            })),
        }
    }
}

impl Registry for InMemoryRegistry {
    fn create_ring(&self, ring_name: &str) -> Result<(), Error> {
        let ring = Ring::new(ring_name)?;
        if ring.is_open() {
            return Err(Error::RingNameReserved(OPEN_RING_NAME.to_string()));
        }
        let mut inner = self.inner.write().unwrap();
        if inner.rings.contains_key(ring_name) {
            return Err(Error::RingAlreadyExists(ring_name.to_string()));
        }
        inner.rings.insert(ring_name.to_string(), Vec::new());
        Ok(())
    }

    fn add_peer_to_ring(
        &self,
        ring_name: &str,
        peer: EndpointId,
        label: Option<&str>,
        expires_at: Option<SystemTime>,
    ) -> Result<(), Error> {
        let now = SystemTime::now();
        let mut inner = self.inner.write().unwrap();
        let members = inner
            .rings
            .get_mut(ring_name)
            .ok_or_else(|| Error::RingNotFound(ring_name.to_string()))?;
        let peer_bytes = *peer.as_bytes();
        let key = (ring_name.to_string(), peer_bytes);
        if !members.contains(&peer_bytes) {
            members.push(peer_bytes);
        } else if inner.is_expired(ring_name, &peer_bytes, now) {
            // An expired membership is equivalent to a removed one, so re-adding
            // starts fresh while the stale label and expiry are dropped.
            inner.labels.remove(&key);
            inner.expiries.remove(&key);
        }
        if let Some(lbl) = label {
            inner.labels.insert(key.clone(), lbl.to_string());
        }
        // `None` leaves an existing expiry untouched, mirroring `label`
        // re-adding a live member never silently widens its access.
        if let Some(t) = expires_at {
            inner.expiries.insert(key, t);
        }
        Ok(())
    }

    fn remove_peer_from_ring(&self, ring_name: &str, peer: EndpointId) -> Result<(), Error> {
        let mut inner = self.inner.write().unwrap();
        let members = inner
            .rings
            .get_mut(ring_name)
            .ok_or_else(|| Error::RingNotFound(ring_name.to_string()))?;
        let peer_bytes = *peer.as_bytes();
        members.retain(|b| b != &peer_bytes);
        let key = (ring_name.to_string(), peer_bytes);
        inner.labels.remove(&key);
        inner.expiries.remove(&key);
        Ok(())
    }

    fn list_ring_peers(
        &self,
        ring_name: &str,
    ) -> Result<Vec<(EndpointId, Option<String>, Option<SystemTime>)>, Error> {
        let now = SystemTime::now();
        let inner = self.inner.read().unwrap();
        let members = inner
            .rings
            .get(ring_name)
            .ok_or_else(|| Error::RingNotFound(ring_name.to_string()))?;
        members
            .iter()
            .filter(|b| !inner.is_expired(ring_name, b, now))
            .map(|b| {
                let peer = EndpointId::from_bytes(b)
                    .map_err(|e| Error::Storage(Box::new(std::io::Error::other(e.to_string()))))?;
                let key = (ring_name.to_string(), *b);
                let label = inner.labels.get(&key).cloned();
                let expires_at = inner.expiries.get(&key).copied();
                Ok((peer, label, expires_at))
            })
            .collect()
    }

    fn list_rings(&self) -> Result<Vec<Ring>, Error> {
        let inner = self.inner.read().unwrap();
        let mut rings = vec![Ring::new_open()];
        for name in inner.rings.keys() {
            if name != OPEN_RING_NAME {
                rings.push(Ring::new(name).expect("invariant: ring names are always valid"));
            }
        }
        Ok(rings)
    }

    fn remove_ring_from_resource<ResId: ResourceId>(
        &self,
        resource_id: ResId,
    ) -> Result<(), Error> {
        self.inner
            .write()
            .unwrap()
            .resource_rings
            .remove(resource_id.as_bytes());
        Ok(())
    }

    fn list_resource_rings<ResId: ResourceId>(
        &self,
        resource_id: ResId,
    ) -> Result<Vec<(Ring, Vec<Permission>)>, Error> {
        let inner = self.inner.read().unwrap();
        Ok(inner
            .resource_rings
            .get(resource_id.as_bytes())
            .map(|entries| {
                entries
                    .iter()
                    .map(|(n, p)| {
                        (
                            Ring::new(n).expect("invariant: ring names are always valid"),
                            p.clone(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    fn add_ring_to_resource<ResId: ResourceId>(
        &self,
        resource_id: ResId,
        ring_name: &str,
        permissions: &[Permission],
    ) -> Result<(), Error> {
        crate::registry::validate_ring_permissions(ring_name, permissions)?;
        let mut inner = self.inner.write().unwrap();
        if !inner.rings.contains_key(ring_name) {
            return Err(Error::RingNotFound(ring_name.to_string()));
        }
        let key = resource_id.as_bytes().to_vec();
        let existing = inner.resource_rings.get(&key).cloned().unwrap_or_default();
        let updated =
            crate::registry::compute_resource_rings(existing, ring_name, permissions.to_vec());
        inner.resource_rings.insert(key, updated);
        Ok(())
    }

    fn has_permission<ResId: ResourceId>(
        &self,
        peer: &EndpointId,
        resource_id: &ResId,
        permission: Permission,
    ) -> Result<bool, Error> {
        let now = SystemTime::now();
        let inner = self.inner.read().unwrap();
        let entries = match inner.resource_rings.get(resource_id.as_bytes()) {
            None => return Ok(false),
            Some(e) => e,
        };
        if entries.is_empty() {
            return Ok(false);
        }
        let peer_bytes = *peer.as_bytes();
        for (name, perms) in entries {
            if !perms.contains(&permission) {
                continue;
            }
            if name == OPEN_RING_NAME {
                return Ok(true);
            }
            if let Some(members) = inner.rings.get(name.as_str()) {
                if members.contains(&peer_bytes) && !inner.is_expired(name, &peer_bytes, now) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;
    use crate::registry::registry_contract;

    const RES: [u8; 32] = [0xab; 32];

    fn make_peer() -> EndpointId {
        iroh::SecretKey::generate().public()
    }

    /// Registry with ring `r` granting `Read` on `RES`.
    fn registry_with_ring() -> InMemoryRegistry {
        let reg = InMemoryRegistry::new();
        reg.create_ring("r").unwrap();
        reg.add_ring_to_resource(RES, "r", &[Permission::Read])
            .unwrap();
        reg
    }

    fn in_one_hour() -> SystemTime {
        SystemTime::now() + Duration::from_secs(3600)
    }

    #[test]
    fn satisfies_registry_contract() {
        registry_contract(&InMemoryRegistry::new());
    }

    #[test]
    fn expired_member_is_denied_and_not_listed() {
        let reg = registry_with_ring();
        let peer = make_peer();
        reg.add_peer_to_ring("r", peer, Some("alice"), Some(UNIX_EPOCH))
            .unwrap();

        assert!(!reg.has_permission(&peer, &RES, Permission::Read).unwrap());
        assert!(reg.list_ring_peers("r").unwrap().is_empty());
    }

    #[test]
    fn member_with_future_expiry_is_active() {
        let reg = registry_with_ring();
        let peer = make_peer();
        let expires_at = in_one_hour();
        reg.add_peer_to_ring("r", peer, Some("alice"), Some(expires_at))
            .unwrap();

        assert!(reg.has_permission(&peer, &RES, Permission::Read).unwrap());
        assert_eq!(
            reg.list_ring_peers("r").unwrap(),
            vec![(peer, Some("alice".to_string()), Some(expires_at))]
        );
    }

    #[test]
    fn readding_live_member_without_expiry_keeps_existing_expiry() {
        let reg = registry_with_ring();
        let peer = make_peer();
        let expires_at = in_one_hour();
        reg.add_peer_to_ring("r", peer, None, Some(expires_at))
            .unwrap();
        reg.add_peer_to_ring("r", peer, None, None).unwrap();

        assert_eq!(reg.list_ring_peers("r").unwrap()[0].2, Some(expires_at));
    }

    #[test]
    fn readding_expired_member_starts_a_fresh_membership() {
        let reg = registry_with_ring();
        let peer = make_peer();
        reg.add_peer_to_ring("r", peer, Some("old"), Some(UNIX_EPOCH))
            .unwrap();
        assert!(!reg.has_permission(&peer, &RES, Permission::Read).unwrap());

        reg.add_peer_to_ring("r", peer, None, None).unwrap();
        assert!(reg.has_permission(&peer, &RES, Permission::Read).unwrap());
        assert_eq!(reg.list_ring_peers("r").unwrap(), vec![(peer, None, None)]);
    }

    #[test]
    fn remove_clears_expiry() {
        let reg = registry_with_ring();
        let peer = make_peer();
        reg.add_peer_to_ring("r", peer, None, Some(in_one_hour()))
            .unwrap();
        reg.remove_peer_from_ring("r", peer).unwrap();
        reg.add_peer_to_ring("r", peer, None, None).unwrap();

        assert_eq!(reg.list_ring_peers("r").unwrap()[0].2, None);
    }

    #[test]
    fn expiry_is_scoped_to_the_ring() {
        let reg = registry_with_ring();
        reg.create_ring("other").unwrap();
        reg.add_ring_to_resource(RES, "other", &[Permission::Write])
            .unwrap();
        let peer = make_peer();
        reg.add_peer_to_ring("r", peer, None, Some(UNIX_EPOCH))
            .unwrap();
        reg.add_peer_to_ring("other", peer, None, None).unwrap();

        assert!(!reg.has_permission(&peer, &RES, Permission::Read).unwrap());
        assert!(reg.has_permission(&peer, &RES, Permission::Write).unwrap());
    }
}
