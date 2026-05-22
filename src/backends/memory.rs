//! Non-persistent, in-memory [`Registry`] backed by hash maps.
//!
//! [`InMemoryRegistry`] is useful for tests and short-lived nodes that do not
//! need to survive a restart. All state is lost when the registry is dropped.
//!
//! For persistent storage, use the [`redb`](super::redb) backend instead.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use iroh::EndpointId;

use crate::registry::{Permission, Registry, ResourceId};
use crate::ring::{Ring, OPEN_RING_NAME};
use crate::Error;

#[derive(Default)]
struct Inner {
    rings: HashMap<String, Vec<[u8; 32]>>,
    nicknames: HashMap<(String, [u8; 32]), String>,
    /// Maps resource id → ordered list of (ring_name, permissions) pairs.
    resource_rings: HashMap<Vec<u8>, Vec<(String, Vec<Permission>)>>,
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
        nickname: Option<&str>,
    ) -> Result<(), Error> {
        let mut inner = self.inner.write().unwrap();
        let members = inner
            .rings
            .get_mut(ring_name)
            .ok_or_else(|| Error::RingNotFound(ring_name.to_string()))?;
        let peer_bytes = *peer.as_bytes();
        if !members.contains(&peer_bytes) {
            members.push(peer_bytes);
        }
        if let Some(nick) = nickname {
            inner
                .nicknames
                .insert((ring_name.to_string(), peer_bytes), nick.to_string());
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
        inner.nicknames.remove(&(ring_name.to_string(), peer_bytes));
        Ok(())
    }

    fn list_ring_peers(&self, ring_name: &str) -> Result<Vec<(EndpointId, Option<String>)>, Error> {
        let inner = self.inner.read().unwrap();
        let members = inner
            .rings
            .get(ring_name)
            .ok_or_else(|| Error::RingNotFound(ring_name.to_string()))?;
        members
            .iter()
            .map(|b| {
                let peer = EndpointId::from_bytes(b)
                    .map_err(|e| Error::Storage(Box::new(std::io::Error::other(e.to_string()))))?;
                let nick = inner.nicknames.get(&(ring_name.to_string(), *b)).cloned();
                Ok((peer, nick))
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
        if permissions.is_empty() {
            return Err(Error::EmptyPermissionSet);
        }
        if ring_name == OPEN_RING_NAME && permissions.iter().any(|p| !matches!(p, Permission::Read))
        {
            return Err(Error::OpenRingReadOnly);
        }
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
                if members.contains(&peer_bytes) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
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
