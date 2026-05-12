use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use anyhow::{anyhow, Result};
use iroh::EndpointId;

use crate::registry::{Registry, ResourceId};
use crate::ring::{Ring, OPEN_RING_NAME};

#[derive(Default)]
struct Inner {
    rings: HashMap<String, Vec<[u8; 32]>>,
    nicknames: HashMap<(String, [u8; 32]), String>,
    resource_rings: HashMap<Vec<u8>, Vec<String>>,
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
    fn create_ring(&self, ring_name: &str) -> Result<()> {
        let ring = Ring::new(ring_name)?;
        if ring.is_open() {
            return Err(anyhow!("'{}' is a reserved ring name", OPEN_RING_NAME));
        }
        let mut inner = self.inner.write().unwrap();
        if inner.rings.contains_key(ring_name) {
            return Err(anyhow!("ring '{}' already exists", ring_name));
        }
        inner.rings.insert(ring_name.to_string(), Vec::new());
        Ok(())
    }

    fn add_peer_to_ring(&self, ring_name: &str, peer: EndpointId, nickname: Option<&str>) -> Result<()> {
        let mut inner = self.inner.write().unwrap();
        let members = inner
            .rings
            .get_mut(ring_name)
            .ok_or_else(|| anyhow!("ring '{}' not found", ring_name))?;
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

    fn remove_peer_from_ring(&self, ring_name: &str, peer: EndpointId) -> Result<()> {
        let mut inner = self.inner.write().unwrap();
        let members = inner
            .rings
            .get_mut(ring_name)
            .ok_or_else(|| anyhow!("ring '{}' not found", ring_name))?;
        let peer_bytes = *peer.as_bytes();
        members.retain(|b| b != &peer_bytes);
        inner.nicknames.remove(&(ring_name.to_string(), peer_bytes));
        Ok(())
    }

    fn list_ring_peers(&self, ring_name: &str) -> Result<Vec<(EndpointId, Option<String>)>> {
        let inner = self.inner.read().unwrap();
        let members = inner
            .rings
            .get(ring_name)
            .ok_or_else(|| anyhow!("ring '{}' not found", ring_name))?;
        members
            .iter()
            .map(|b| {
                let peer = EndpointId::from_bytes(b).map_err(|e| anyhow!("{e}"))?;
                let nick = inner.nicknames.get(&(ring_name.to_string(), *b)).cloned();
                Ok((peer, nick))
            })
            .collect()
    }

    fn list_rings(&self) -> Result<Vec<Ring>> {
        let inner = self.inner.read().unwrap();
        let mut rings = vec![Ring::new_open()];
        for name in inner.rings.keys() {
            if name != OPEN_RING_NAME {
                rings.push(Ring::new(name).expect("invariant: ring names are always valid"));
            }
        }
        Ok(rings)
    }

    fn remove_ring_from_resource<ResId: ResourceId>(&self, resource_id: ResId) -> Result<()> {
        self.inner
            .write()
            .unwrap()
            .resource_rings
            .remove(resource_id.as_bytes());
        Ok(())
    }

    fn list_resource_rings<ResId: ResourceId>(&self, resource_id: ResId) -> Result<Vec<Ring>> {
        let inner = self.inner.read().unwrap();
        Ok(inner
            .resource_rings
            .get(resource_id.as_bytes())
            .map(|names| {
                names
                    .iter()
                    .map(|n| Ring::new(n).expect("invariant: ring names are always valid"))
                    .collect()
            })
            .unwrap_or_default())
    }

    fn add_ring_to_resource<ResId: ResourceId>(
        &self,
        resource_id: ResId,
        ring_name: &str,
    ) -> Result<()> {
        let mut inner = self.inner.write().unwrap();
        if !inner.rings.contains_key(ring_name) {
            return Err(anyhow!("ring '{}' not found", ring_name));
        }
        let key = resource_id.as_bytes().to_vec();
        let existing = inner.resource_rings.get(&key).cloned().unwrap_or_default();
        let names = if ring_name == OPEN_RING_NAME {
            vec![OPEN_RING_NAME.to_string()]
        } else {
            let mut kept: Vec<String> = existing
                .into_iter()
                .filter(|n| n != OPEN_RING_NAME)
                .collect();
            if !kept.iter().any(|n| n == ring_name) {
                kept.push(ring_name.to_string());
            }
            kept
        };
        inner.resource_rings.insert(key, names);
        Ok(())
    }

    fn is_allowed<ResId: ResourceId>(
        &self,
        peer: &EndpointId,
        resource_id: &ResId,
    ) -> Result<bool> {
        let inner = self.inner.read().unwrap();
        let ring_names = match inner.resource_rings.get(resource_id.as_bytes()) {
            None => return Ok(false),
            Some(names) => names,
        };
        if ring_names.is_empty() {
            return Ok(false);
        }
        if ring_names.iter().any(|n| n == OPEN_RING_NAME) {
            return Ok(true);
        }
        let peer_bytes = *peer.as_bytes();
        for name in ring_names {
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

    fn make_reg() -> InMemoryRegistry {
        InMemoryRegistry::new()
    }

    #[test]
    fn satisfies_registry_contract() {
        registry_contract(&make_reg());
    }

    fn make_resource(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn make_peer() -> EndpointId {
        iroh::SecretKey::generate().public()
    }

    // add_ring_to_resource

    #[test]
    fn tag_open_ring_clears_private_rings() {
        let reg = make_reg();
        let resource = make_resource(1);
        reg.create_ring("friends").unwrap();
        reg.add_ring_to_resource(resource, "friends").unwrap();
        reg.add_ring_to_resource(resource, OPEN_RING_NAME).unwrap();
        let rings = reg.list_resource_rings(resource).unwrap();
        assert_eq!(rings, vec![Ring::new_open()]);
    }

    #[test]
    fn tag_private_ring_clears_open_ring() {
        let reg = make_reg();
        let resource = make_resource(1);
        reg.create_ring("friends").unwrap();
        reg.add_ring_to_resource(resource, OPEN_RING_NAME).unwrap();
        reg.add_ring_to_resource(resource, "friends").unwrap();
        let rings = reg.list_resource_rings(resource).unwrap();
        assert_eq!(rings, vec![Ring::new("friends").unwrap()]);
    }

    #[test]
    fn tag_private_ring_is_idempotent() {
        let reg = make_reg();
        let resource = make_resource(1);
        reg.create_ring("friends").unwrap();
        reg.add_ring_to_resource(resource, "friends").unwrap();
        reg.add_ring_to_resource(resource, "friends").unwrap();
        assert_eq!(reg.list_resource_rings(resource).unwrap().len(), 1);
    }

    #[test]
    fn tag_multiple_private_rings_accumulate() {
        let reg = make_reg();
        let resource = make_resource(1);
        reg.create_ring("friends").unwrap();
        reg.create_ring("work").unwrap();
        reg.add_ring_to_resource(resource, "friends").unwrap();
        reg.add_ring_to_resource(resource, "work").unwrap();
        let rings = reg.list_resource_rings(resource).unwrap();
        assert_eq!(rings.len(), 2);
        assert!(rings.contains(&Ring::new("friends").unwrap()));
        assert!(rings.contains(&Ring::new("work").unwrap()));
    }

    #[test]
    fn tag_resource_rejects_nonexistent_ring() {
        let reg = make_reg();
        assert!(reg.add_ring_to_resource(make_resource(1), "ghost").is_err());
    }

    // list_resource_rings

    #[test]
    fn resource_rings_untagged_returns_empty() {
        let reg = make_reg();
        assert_eq!(reg.list_resource_rings(make_resource(1)).unwrap(), vec![]);
    }

    // create_ring

    #[test]
    fn create_ring_rejects_reserved_name() {
        let reg = make_reg();
        assert!(reg.create_ring(OPEN_RING_NAME).is_err());
    }

    #[test]
    fn create_ring_rejects_duplicate() {
        let reg = make_reg();
        reg.create_ring("friends").unwrap();
        assert!(reg.create_ring("friends").is_err());
    }

    #[test]
    fn create_ring_rejects_empty_name() {
        let reg = make_reg();
        assert!(reg.create_ring("").is_err());
    }

    #[test]
    fn create_ring_rejects_name_with_whitespace() {
        let reg = make_reg();
        assert!(reg.create_ring("my ring").is_err());
        assert!(reg.create_ring("tab\there").is_err());
    }

    #[test]
    fn create_ring_rejects_name_with_nul() {
        let reg = make_reg();
        assert!(reg.create_ring("ring\0name").is_err());
    }

    // list_rings

    #[test]
    fn list_rings_always_includes_open_ring() {
        let reg = make_reg();
        let rings = reg.list_rings().unwrap();
        assert_eq!(rings[0], Ring::new_open());
    }

    #[test]
    fn list_rings_returns_all_created_rings() {
        let reg = make_reg();
        reg.create_ring("friends").unwrap();
        reg.create_ring("work").unwrap();
        let rings = reg.list_rings().unwrap();
        assert!(rings.contains(&Ring::new("friends").unwrap()));
        assert!(rings.contains(&Ring::new("work").unwrap()));
        assert_eq!(rings.len(), 3);
    }

    // add_peer_to_ring / remove_peer_from_ring

    #[test]
    fn add_member_is_idempotent() {
        let reg = make_reg();
        let peer = make_peer();
        reg.create_ring("friends").unwrap();
        reg.add_peer_to_ring("friends", peer, None).unwrap();
        reg.add_peer_to_ring("friends", peer, None).unwrap();
        assert_eq!(reg.list_ring_peers("friends").unwrap().len(), 1);
    }

    #[test]
    fn add_member_to_nonexistent_ring_errors() {
        let reg = make_reg();
        assert!(reg.add_peer_to_ring("ghost", make_peer(), None).is_err());
    }

    #[test]
    fn remove_member_from_nonexistent_ring_errors() {
        let reg = make_reg();
        assert!(reg.remove_peer_from_ring("ghost", make_peer()).is_err());
    }

    #[test]
    fn remove_member_noop_when_peer_not_in_ring() {
        let reg = make_reg();
        let peer = make_peer();
        reg.create_ring("friends").unwrap();
        reg.remove_peer_from_ring("friends", peer).unwrap();
        assert_eq!(reg.list_ring_peers("friends").unwrap().len(), 0);
    }

    // list_ring_peers

    #[test]
    fn list_members_nonexistent_ring_errors() {
        let reg = make_reg();
        assert!(reg.list_ring_peers("ghost").is_err());
    }

    // is_allowed

    #[test]
    fn is_allowed_untagged_resource_denied() {
        let reg = make_reg();
        let peer = make_peer();
        assert!(!reg.is_allowed(&peer, &make_resource(1)).unwrap());
    }

    #[test]
    fn is_allowed_open_ring_permits_any_peer() {
        let reg = make_reg();
        let resource = make_resource(1);
        let peer = make_peer();
        reg.add_ring_to_resource(resource, OPEN_RING_NAME).unwrap();
        assert!(reg.is_allowed(&peer, &resource).unwrap());
    }

    #[test]
    fn is_allowed_member_of_tagged_ring_permitted() {
        let reg = make_reg();
        let resource = make_resource(1);
        let peer = make_peer();
        reg.create_ring("friends").unwrap();
        reg.add_ring_to_resource(resource, "friends").unwrap();
        reg.add_peer_to_ring("friends", peer, None).unwrap();
        assert!(reg.is_allowed(&peer, &resource).unwrap());
    }

    #[test]
    fn is_allowed_non_member_denied() {
        let reg = make_reg();
        let resource = make_resource(1);
        let member = make_peer();
        let stranger = make_peer();
        reg.create_ring("friends").unwrap();
        reg.add_ring_to_resource(resource, "friends").unwrap();
        reg.add_peer_to_ring("friends", member, None).unwrap();
        assert!(!reg.is_allowed(&stranger, &resource).unwrap());
    }

    #[test]
    fn is_allowed_peer_in_one_of_multiple_tagged_rings_permitted() {
        let reg = make_reg();
        let resource = make_resource(1);
        let peer = make_peer();
        reg.create_ring("friends").unwrap();
        reg.create_ring("work").unwrap();
        reg.add_ring_to_resource(resource, "friends").unwrap();
        reg.add_ring_to_resource(resource, "work").unwrap();
        reg.add_peer_to_ring("work", peer, None).unwrap();
        assert!(reg.is_allowed(&peer, &resource).unwrap());
    }

    // nicknames

    #[test]
    fn nickname_stored_and_returned_by_list_members() {
        let reg = make_reg();
        let peer = make_peer();
        reg.create_ring("friends").unwrap();
        reg.add_peer_to_ring("friends", peer, Some("alice"))
            .unwrap();
        let members = reg.list_ring_peers("friends").unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].1.as_deref(), Some("alice"));
    }

    #[test]
    fn no_nickname_returns_none() {
        let reg = make_reg();
        let peer = make_peer();
        reg.create_ring("friends").unwrap();
        reg.add_peer_to_ring("friends", peer, None).unwrap();
        let members = reg.list_ring_peers("friends").unwrap();
        assert_eq!(members[0].1, None);
    }

    #[test]
    fn nickname_updated_on_readd() {
        let reg = make_reg();
        let peer = make_peer();
        reg.create_ring("friends").unwrap();
        reg.add_peer_to_ring("friends", peer, Some("alice"))
            .unwrap();
        reg.add_peer_to_ring("friends", peer, Some("alice2"))
            .unwrap();
        let members = reg.list_ring_peers("friends").unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].1.as_deref(), Some("alice2"));
    }

    #[test]
    fn nickname_removed_with_peer() {
        let reg = make_reg();
        let peer = make_peer();
        reg.create_ring("friends").unwrap();
        reg.add_peer_to_ring("friends", peer, Some("alice"))
            .unwrap();
        reg.remove_peer_from_ring("friends", peer).unwrap();
        reg.add_peer_to_ring("friends", peer, None).unwrap();
        let members = reg.list_ring_peers("friends").unwrap();
        assert_eq!(members[0].1, None);
    }

    #[test]
    fn nicknames_are_per_ring() {
        let reg = make_reg();
        let peer = make_peer();
        reg.create_ring("friends").unwrap();
        reg.create_ring("work").unwrap();
        reg.add_peer_to_ring("friends", peer, Some("alice"))
            .unwrap();
        reg.add_peer_to_ring("work", peer, Some("bob")).unwrap();
        let friends = reg.list_ring_peers("friends").unwrap();
        let work = reg.list_ring_peers("work").unwrap();
        assert_eq!(friends[0].1.as_deref(), Some("alice"));
        assert_eq!(work[0].1.as_deref(), Some("bob"));
    }
}
