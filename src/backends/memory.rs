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

use crate::registry::{
    decode_endpoint_id, EvictedMembership, Permission, Registry, ResourceId, RingMember,
};
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
            // it starts fresh: the stale label and expiry are dropped.
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

    fn list_ring_peers(&self, ring_name: &str) -> Result<Vec<RingMember>, Error> {
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
                let peer = decode_endpoint_id(b)?;
                let key = (ring_name.to_string(), *b);
                let label = inner.labels.get(&key).cloned();
                let expires_at = inner.expiries.get(&key).copied();
                Ok(RingMember::new(peer, label, expires_at))
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

    fn evict_expired(&self, now: SystemTime) -> Result<Vec<EvictedMembership>, Error> {
        let mut inner = self.inner.write().unwrap();
        let expired_keys: Vec<(String, [u8; 32])> = inner
            .expiries
            .iter()
            .filter(|(_, &expires_at)| now >= expires_at)
            .map(|(key, _)| key.clone())
            .collect();

        let mut evicted = Vec::with_capacity(expired_keys.len());
        for (ring_name, peer_bytes) in expired_keys {
            if let Some(members) = inner.rings.get_mut(&ring_name) {
                members.retain(|b| b != &peer_bytes);
            }
            inner.labels.remove(&(ring_name.clone(), peer_bytes));
            inner.expiries.remove(&(ring_name.clone(), peer_bytes));
            let peer = decode_endpoint_id(&peer_bytes)?;
            evicted.push(EvictedMembership::new(ring_name, peer));
        }
        Ok(evicted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::registry_contract;

    #[test]
    fn satisfies_registry_contract() {
        registry_contract(&InMemoryRegistry::new());
    }
}
