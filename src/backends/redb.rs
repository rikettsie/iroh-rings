//! Persistent registry backed by an embedded redb database.
//!
//! It defines two redb tables for the entire data model:
//!
//! ```text
//! RINGS: maps ring names (&str) to lists of peers (EndpointIds, i.e. 32-byte Ed25519 pubkeys)
//! RESOURCE_RINGS: maps resource ids (bytes) to NULL-separated ring names
//! ```
//!
//! The critical operation is [`RedbRegistry::is_allowed`], which answers:
//! "may this EndpointId access this resource?" in a single read transaction.
//!
//! # Open ring
//!
//! `OPEN_RING_NAME` ("open") is a built-in, reserved ring name with a special
//! meaning: **any peer may access a resource tagged with the open ring**, regardless
//! of membership. It is automatically created on first `open()` and cannot be
//! deleted or renamed.

use std::{path::Path, sync::Arc};

use anyhow::{anyhow, Result};
use iroh::EndpointId;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

use crate::registry::{Registry, ResourceId};
use crate::ring::{Ring, OPEN_RING_NAME};

/// Maps ring name (&str) to serialised Vec<[u8; 32]> of member peer-ids.
const RINGS: TableDefinition<&str, &[u8]> = TableDefinition::new("rings");

/// Maps resource unique ids (bytes) to NUL-separated ring names.
const RESOURCE_RINGS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("resource_rings");

/// Maps `ring_name \0 peer_id_bytes` to nickname string (display label only).
/// Ring names are validated to contain no NUL, so the separator is unambiguous.
const NICKNAMES: TableDefinition<&[u8], &str> = TableDefinition::new("nicknames");

/// Persistent registry, cheaply cloneable via Arc.
#[derive(Clone)]
pub struct RedbRegistry {
    db: Arc<Database>,
}

impl RedbRegistry {
    /// Open (or create) the registry at `path`.
    ///
    /// On first creation the open ring is bootstrapped automatically.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let db = Database::create(path)?;
        let write = db.begin_write()?;
        {
            let mut rings = write.open_table(RINGS)?;
            write.open_table(RESOURCE_RINGS)?;
            write.open_table(NICKNAMES)?;

            if rings.get(OPEN_RING_NAME)?.is_none() {
                rings.insert(OPEN_RING_NAME, encode_peer_ids(&[]).as_slice())?;
            }
        }
        write.commit()?;
        Ok(Self { db: Arc::new(db) })
    }
}

impl Registry for RedbRegistry {
    fn create_ring(&self, ring_name: &str) -> Result<()> {
        let ring = Ring::new(ring_name)?;
        if ring.is_open() {
            return Err(anyhow!("'{}' is a reserved ring name", ring_name));
        }
        let write = self.db.begin_write()?;
        {
            let mut table = write.open_table(RINGS)?;
            if table.get(ring_name)?.is_some() {
                return Err(anyhow!("ring '{}' already exists", ring_name));
            }
            table.insert(ring_name, encode_peer_ids(&[]).as_slice())?;
        }
        write.commit()?;
        Ok(())
    }

    fn add_peer_to_ring(&self, ring_name: &str, peer: EndpointId, nickname: Option<&str>) -> Result<()> {
        let write = self.db.begin_write()?;
        {
            let mut table = write.open_table(RINGS)?;
            let mut members = match table.get(ring_name)? {
                Some(v) => decode_peer_ids(v.value()),
                None => return Err(anyhow!("ring '{}' not found", ring_name)),
            };
            let peer_bytes = *peer.as_bytes();
            if !members.contains(&peer_bytes) {
                members.push(peer_bytes);
            }
            table.insert(ring_name, encode_peer_ids(&members).as_slice())?;

            if let Some(nick) = nickname {
                let mut nick_table = write.open_table(NICKNAMES)?;
                nick_table.insert(nickname_key(ring_name, &peer).as_slice(), nick)?;
            }
        }
        write.commit()?;
        Ok(())
    }

    fn remove_peer_from_ring(&self, ring_name: &str, peer: EndpointId) -> Result<()> {
        let write = self.db.begin_write()?;
        {
            let mut table = write.open_table(RINGS)?;
            let mut members = match table.get(ring_name)? {
                Some(v) => decode_peer_ids(v.value()),
                None => return Err(anyhow!("ring '{}' not found", ring_name)),
            };
            let peer_bytes = *peer.as_bytes();
            members.retain(|b| b != &peer_bytes);
            table.insert(ring_name, encode_peer_ids(&members).as_slice())?;

            let mut nick_table = write.open_table(NICKNAMES)?;
            nick_table.remove(nickname_key(ring_name, &peer).as_slice())?;
        }
        write.commit()?;
        Ok(())
    }

    fn list_ring_peers(&self, ring_name: &str) -> Result<Vec<(EndpointId, Option<String>)>> {
        let read = self.db.begin_read()?;
        let table = read.open_table(RINGS)?;
        let nick_table = read.open_table(NICKNAMES)?;
        match table.get(ring_name)? {
            None => Err(anyhow!("ring '{}' not found", ring_name)),
            Some(v) => decode_peer_ids(v.value())
                .into_iter()
                .map(|b| {
                    let peer = EndpointId::from_bytes(&b).map_err(|e| anyhow!("{e}"))?;
                    let nick = nick_table
                        .get(nickname_key(ring_name, &peer).as_slice())?
                        .map(|v| v.value().to_owned());
                    Ok((peer, nick))
                })
                .collect(),
        }
    }

    fn list_rings(&self) -> Result<Vec<Ring>> {
        let read = self.db.begin_read()?;
        let table = read.open_table(RINGS)?;
        let mut ids = vec![Ring::new_open()];
        for entry in table.iter()? {
            let (k, _) = entry?;
            let name = k.value().to_owned();
            if name != OPEN_RING_NAME {
                ids.push(Ring::new(name).expect("invariant: db ring names are always valid"));
            }
        }
        Ok(ids)
    }

    fn remove_ring_from_resource<ResId: ResourceId>(&self, resource_id: ResId) -> Result<()> {
        let write = self.db.begin_write()?;
        {
            let mut table = write.open_table(RESOURCE_RINGS)?;
            table.remove(resource_id.as_bytes())?;
        }
        write.commit()?;
        Ok(())
    }

    fn list_resource_rings<ResId: ResourceId>(&self, resource_id: ResId) -> Result<Vec<Ring>> {
        let read = self.db.begin_read()?;
        let table = read.open_table(RESOURCE_RINGS)?;
        match table.get(resource_id.as_bytes())? {
            None => Ok(Vec::new()),
            Some(v) => Ok(decode_ring_names(v.value())
                .into_iter()
                .map(|ring_name| Ring::new(ring_name).expect("invariant: db ring names are always valid"))
                .collect()),
        }
    }

    fn add_ring_to_resource<ResId: ResourceId>(
        &self,
        resource_id: ResId,
        ring_name: &str,
    ) -> Result<()> {
        let write = self.db.begin_write()?;
        {
            let rings_table = write.open_table(RINGS)?;
            if rings_table.get(ring_name)?.is_none() {
                return Err(anyhow!("ring '{}' not found", ring_name));
            }
            drop(rings_table); // redb only allows one open at a time

            let mut table = write.open_table(RESOURCE_RINGS)?;
            let key = resource_id.as_bytes();
            let existing = match table.get(key)? {
                Some(v) => decode_ring_names(v.value()),
                None => Vec::new(),
            };

            let names = if ring_name == OPEN_RING_NAME {
                vec![OPEN_RING_NAME.to_owned()]
            } else {
                let mut kept: Vec<String> = existing
                    .into_iter()
                    .filter(|n| n != OPEN_RING_NAME)
                    .collect();
                if !kept.iter().any(|n| n == ring_name) {
                    kept.push(ring_name.to_owned());
                }
                kept
            };

            table.insert(key, encode_ring_names(&names).as_slice())?;
        }
        write.commit()?;
        Ok(())
    }

    fn is_allowed<ResId: ResourceId>(
        &self,
        peer: &EndpointId,
        resource_id: &ResId,
    ) -> Result<bool> {
        let read = self.db.begin_read()?;

        let fr_table = read.open_table(RESOURCE_RINGS)?;
        let ring_names = match fr_table.get(resource_id.as_bytes())? {
            None => return Ok(false),
            Some(v) => decode_ring_names(v.value()),
        };
        if ring_names.is_empty() {
            return Ok(false);
        }
        if ring_names.iter().any(|n| n == OPEN_RING_NAME) {
            return Ok(true);
        }

        let r_table = read.open_table(RINGS)?;
        let peer_bytes = *peer.as_bytes();
        for name in &ring_names {
            if let Some(members_raw) = r_table.get(name.as_str())? {
                let members = decode_peer_ids(members_raw.value());
                if members.iter().any(|b| b == &peer_bytes) {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }
}

// The same peer can have a different nickname in each ring.
// This is intentional, the label is a per-ring social convention,
// not a global identity as the peer-id is.
fn nickname_key(ring_name: &str, peer: &EndpointId) -> Vec<u8> {
    let mut key = ring_name.as_bytes().to_vec();
    key.push(b'\0');
    key.extend_from_slice(peer.as_bytes());
    key
}

fn encode_peer_ids(ids: &[[u8; 32]]) -> Vec<u8> {
    ids.iter().flat_map(|b| b.iter().copied()).collect()
}

fn decode_peer_ids(raw: &[u8]) -> Vec<[u8; 32]> {
    raw.chunks_exact(32)
        .map(|c| {
            c.try_into()
                .expect("invariant: chunks_exact(32) yields 32-byte slices")
        })
        .collect()
}

fn encode_ring_names(names: &[String]) -> Vec<u8> {
    names.join("\0").into_bytes()
}

fn decode_ring_names(raw: &[u8]) -> Vec<String> {
    if raw.is_empty() {
        return Vec::new();
    }
    raw.split(|&b| b == 0)
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::registry_contract;
    use tempfile::tempdir;

    fn make_reg() -> (RedbRegistry, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let reg = RedbRegistry::open(dir.path().join("test.redb")).unwrap();
        (reg, dir)
    }

    #[test]
    fn satisfies_registry_contract() {
        let (reg, _dir) = make_reg();
        registry_contract(&reg);
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
        let (reg, _dir) = make_reg();
        let resource = make_resource(1);
        reg.create_ring("friends").unwrap();
        reg.add_ring_to_resource(resource, "friends").unwrap();
        reg.add_ring_to_resource(resource, OPEN_RING_NAME).unwrap();
        let rings = reg.list_resource_rings(resource).unwrap();
        assert_eq!(rings, vec![Ring::new_open()]);
    }

    #[test]
    fn tag_private_ring_clears_open_ring() {
        let (reg, _dir) = make_reg();
        let resource = make_resource(1);
        reg.create_ring("friends").unwrap();
        reg.add_ring_to_resource(resource, OPEN_RING_NAME).unwrap();
        reg.add_ring_to_resource(resource, "friends").unwrap();
        let rings = reg.list_resource_rings(resource).unwrap();
        assert_eq!(rings, vec![Ring::new("friends").unwrap()]);
    }

    #[test]
    fn tag_private_ring_is_idempotent() {
        let (reg, _dir) = make_reg();
        let resource = make_resource(1);
        reg.create_ring("friends").unwrap();
        reg.add_ring_to_resource(resource, "friends").unwrap();
        reg.add_ring_to_resource(resource, "friends").unwrap();
        assert_eq!(reg.list_resource_rings(resource).unwrap().len(), 1);
    }

    #[test]
    fn tag_multiple_private_rings_accumulate() {
        let (reg, _dir) = make_reg();
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
        let (reg, _dir) = make_reg();
        assert!(reg.add_ring_to_resource(make_resource(1), "ghost").is_err());
    }

    // list_resource_rings

    #[test]
    fn resource_rings_untagged_returns_empty() {
        let (reg, _dir) = make_reg();
        assert_eq!(reg.list_resource_rings(make_resource(1)).unwrap(), vec![]);
    }

    // create_ring

    #[test]
    fn create_ring_rejects_reserved_name() {
        let (reg, _dir) = make_reg();
        assert!(reg.create_ring(OPEN_RING_NAME).is_err());
    }

    #[test]
    fn create_ring_rejects_duplicate() {
        let (reg, _dir) = make_reg();
        reg.create_ring("friends").unwrap();
        assert!(reg.create_ring("friends").is_err());
    }

    #[test]
    fn create_ring_rejects_empty_name() {
        let (reg, _dir) = make_reg();
        assert!(reg.create_ring("").is_err());
    }

    #[test]
    fn create_ring_rejects_name_with_whitespace() {
        let (reg, _dir) = make_reg();
        assert!(reg.create_ring("my ring").is_err());
        assert!(reg.create_ring("tab\there").is_err());
    }

    #[test]
    fn create_ring_rejects_name_with_nul() {
        let (reg, _dir) = make_reg();
        assert!(reg.create_ring("ring\0name").is_err());
    }

    // list_rings

    #[test]
    fn list_rings_always_includes_open_ring() {
        let (reg, _dir) = make_reg();
        let rings = reg.list_rings().unwrap();
        assert_eq!(rings[0], Ring::new_open());
    }

    #[test]
    fn list_rings_returns_all_created_rings() {
        let (reg, _dir) = make_reg();
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
        let (reg, _dir) = make_reg();
        let peer = make_peer();
        reg.create_ring("friends").unwrap();
        reg.add_peer_to_ring("friends", peer, None).unwrap();
        reg.add_peer_to_ring("friends", peer, None).unwrap();
        assert_eq!(reg.list_ring_peers("friends").unwrap().len(), 1);
    }

    #[test]
    fn add_member_to_nonexistent_ring_errors() {
        let (reg, _dir) = make_reg();
        assert!(reg.add_peer_to_ring("ghost", make_peer(), None).is_err());
    }

    #[test]
    fn remove_member_from_nonexistent_ring_errors() {
        let (reg, _dir) = make_reg();
        assert!(reg.remove_peer_from_ring("ghost", make_peer()).is_err());
    }

    #[test]
    fn remove_member_noop_when_peer_not_in_ring() {
        let (reg, _dir) = make_reg();
        let peer = make_peer();
        reg.create_ring("friends").unwrap();
        reg.remove_peer_from_ring("friends", peer).unwrap();
        assert_eq!(reg.list_ring_peers("friends").unwrap().len(), 0);
    }

    // list_ring_peers

    #[test]
    fn list_members_nonexistent_ring_errors() {
        let (reg, _dir) = make_reg();
        assert!(reg.list_ring_peers("ghost").is_err());
    }

    // is_allowed

    #[test]
    fn is_allowed_untagged_resource_denied() {
        let (reg, _dir) = make_reg();
        let peer = make_peer();
        assert!(!reg.is_allowed(&peer, &make_resource(1)).unwrap());
    }

    #[test]
    fn is_allowed_open_ring_permits_any_peer() {
        let (reg, _dir) = make_reg();
        let resource = make_resource(1);
        let peer = make_peer();
        reg.add_ring_to_resource(resource, OPEN_RING_NAME).unwrap();
        assert!(reg.is_allowed(&peer, &resource).unwrap());
    }

    #[test]
    fn is_allowed_member_of_tagged_ring_permitted() {
        let (reg, _dir) = make_reg();
        let resource = make_resource(1);
        let peer = make_peer();
        reg.create_ring("friends").unwrap();
        reg.add_ring_to_resource(resource, "friends").unwrap();
        reg.add_peer_to_ring("friends", peer, None).unwrap();
        assert!(reg.is_allowed(&peer, &resource).unwrap());
    }

    #[test]
    fn is_allowed_non_member_denied() {
        let (reg, _dir) = make_reg();
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
        let (reg, _dir) = make_reg();
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
        let (reg, _dir) = make_reg();
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
        let (reg, _dir) = make_reg();
        let peer = make_peer();
        reg.create_ring("friends").unwrap();
        reg.add_peer_to_ring("friends", peer, None).unwrap();
        let members = reg.list_ring_peers("friends").unwrap();
        assert_eq!(members[0].1, None);
    }

    #[test]
    fn nickname_updated_on_readd() {
        let (reg, _dir) = make_reg();
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
        let (reg, _dir) = make_reg();
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
        let (reg, _dir) = make_reg();
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

    #[test]
    fn members_mixed_nicknames_and_none() {
        let (reg, _dir) = make_reg();
        let alice = make_peer();
        let bob = make_peer();
        reg.create_ring("friends").unwrap();
        reg.add_peer_to_ring("friends", alice, Some("alice"))
            .unwrap();
        reg.add_peer_to_ring("friends", bob, None).unwrap();
        let members = reg.list_ring_peers("friends").unwrap();
        assert_eq!(members.len(), 2);
        let nicks: Vec<_> = members.iter().map(|(_, n)| n.as_deref()).collect();
        assert!(nicks.contains(&Some("alice")));
        assert!(nicks.contains(&None));
    }
}
