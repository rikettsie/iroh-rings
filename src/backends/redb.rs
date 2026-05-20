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
//! meaning: **any peer may access a resource associated with the open ring**, regardless
//! of membership. It is automatically created on first `open()` and cannot be
//! deleted or renamed.

use std::{path::Path, sync::Arc};

use iroh::EndpointId;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

use crate::registry::{Registry, ResourceId};
use crate::ring::{Ring, OPEN_RING_NAME};
use crate::Error;

/// Wraps any storage-level error into [`Error::Storage`].
fn storage<E: std::error::Error + Send + Sync + 'static>(e: E) -> Error {
    Error::Storage(Box::new(e))
}

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
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if the database cannot be opened or initialised.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        let db = Database::create(path).map_err(storage)?;
        let write = db.begin_write().map_err(storage)?;
        {
            let mut rings = write.open_table(RINGS).map_err(storage)?;
            write.open_table(RESOURCE_RINGS).map_err(storage)?;
            write.open_table(NICKNAMES).map_err(storage)?;

            if rings.get(OPEN_RING_NAME).map_err(storage)?.is_none() {
                rings
                    .insert(OPEN_RING_NAME, encode_peer_ids(&[]).as_slice())
                    .map_err(storage)?;
            }
        }
        write.commit().map_err(storage)?;
        Ok(Self { db: Arc::new(db) })
    }
}

impl Registry for RedbRegistry {
    fn create_ring(&self, ring_name: &str) -> Result<(), Error> {
        let ring = Ring::new(ring_name)?;
        if ring.is_open() {
            return Err(Error::RingNameReserved(OPEN_RING_NAME.to_string()));
        }
        let write = self.db.begin_write().map_err(storage)?;
        {
            let mut table = write.open_table(RINGS).map_err(storage)?;
            if table.get(ring_name).map_err(storage)?.is_some() {
                return Err(Error::RingAlreadyExists(ring_name.to_string()));
            }
            table
                .insert(ring_name, encode_peer_ids(&[]).as_slice())
                .map_err(storage)?;
        }
        write.commit().map_err(storage)?;
        Ok(())
    }

    fn add_peer_to_ring(
        &self,
        ring_name: &str,
        peer: EndpointId,
        nickname: Option<&str>,
    ) -> Result<(), Error> {
        let write = self.db.begin_write().map_err(storage)?;
        {
            let mut table = write.open_table(RINGS).map_err(storage)?;
            let mut members = match table.get(ring_name).map_err(storage)? {
                Some(v) => decode_peer_ids(v.value()),
                None => return Err(Error::RingNotFound(ring_name.to_string())),
            };
            let peer_bytes = *peer.as_bytes();
            if !members.contains(&peer_bytes) {
                members.push(peer_bytes);
            }
            table
                .insert(ring_name, encode_peer_ids(&members).as_slice())
                .map_err(storage)?;

            if let Some(nick) = nickname {
                let mut nick_table = write.open_table(NICKNAMES).map_err(storage)?;
                nick_table
                    .insert(nickname_key(ring_name, &peer).as_slice(), nick)
                    .map_err(storage)?;
            }
        }
        write.commit().map_err(storage)?;
        Ok(())
    }

    fn remove_peer_from_ring(&self, ring_name: &str, peer: EndpointId) -> Result<(), Error> {
        let write = self.db.begin_write().map_err(storage)?;
        {
            let mut table = write.open_table(RINGS).map_err(storage)?;
            let mut members = match table.get(ring_name).map_err(storage)? {
                Some(v) => decode_peer_ids(v.value()),
                None => return Err(Error::RingNotFound(ring_name.to_string())),
            };
            let peer_bytes = *peer.as_bytes();
            members.retain(|b| b != &peer_bytes);
            table
                .insert(ring_name, encode_peer_ids(&members).as_slice())
                .map_err(storage)?;

            let mut nick_table = write.open_table(NICKNAMES).map_err(storage)?;
            nick_table
                .remove(nickname_key(ring_name, &peer).as_slice())
                .map_err(storage)?;
        }
        write.commit().map_err(storage)?;
        Ok(())
    }

    fn list_ring_peers(&self, ring_name: &str) -> Result<Vec<(EndpointId, Option<String>)>, Error> {
        let read = self.db.begin_read().map_err(storage)?;
        let table = read.open_table(RINGS).map_err(storage)?;
        let nick_table = read.open_table(NICKNAMES).map_err(storage)?;
        match table.get(ring_name).map_err(storage)? {
            None => Err(Error::RingNotFound(ring_name.to_string())),
            Some(v) => decode_peer_ids(v.value())
                .into_iter()
                .map(|b| {
                    let peer = EndpointId::from_bytes(&b).map_err(|e| {
                        Error::Storage(Box::new(std::io::Error::other(e.to_string())))
                    })?;
                    let nick = nick_table
                        .get(nickname_key(ring_name, &peer).as_slice())
                        .map_err(storage)?
                        .map(|v| v.value().to_owned());
                    Ok((peer, nick))
                })
                .collect(),
        }
    }

    fn list_rings(&self) -> Result<Vec<Ring>, Error> {
        let read = self.db.begin_read().map_err(storage)?;
        let table = read.open_table(RINGS).map_err(storage)?;
        let mut ids = vec![Ring::new_open()];
        for entry in table.iter().map_err(storage)? {
            let (k, _) = entry.map_err(storage)?;
            let name = k.value().to_owned();
            if name != OPEN_RING_NAME {
                ids.push(Ring::new(name).expect("invariant: db ring names are always valid"));
            }
        }
        Ok(ids)
    }

    fn remove_ring_from_resource<ResId: ResourceId>(
        &self,
        resource_id: ResId,
    ) -> Result<(), Error> {
        let write = self.db.begin_write().map_err(storage)?;
        {
            let mut table = write.open_table(RESOURCE_RINGS).map_err(storage)?;
            table.remove(resource_id.as_bytes()).map_err(storage)?;
        }
        write.commit().map_err(storage)?;
        Ok(())
    }

    fn list_resource_rings<ResId: ResourceId>(
        &self,
        resource_id: ResId,
    ) -> Result<Vec<Ring>, Error> {
        let read = self.db.begin_read().map_err(storage)?;
        let table = read.open_table(RESOURCE_RINGS).map_err(storage)?;
        match table.get(resource_id.as_bytes()).map_err(storage)? {
            None => Ok(Vec::new()),
            Some(v) => Ok(decode_ring_names(v.value())
                .into_iter()
                .map(|ring_name| {
                    Ring::new(ring_name).expect("invariant: db ring names are always valid")
                })
                .collect()),
        }
    }

    fn add_ring_to_resource<ResId: ResourceId>(
        &self,
        resource_id: ResId,
        ring_name: &str,
    ) -> Result<(), Error> {
        let write = self.db.begin_write().map_err(storage)?;
        {
            let rings_table = write.open_table(RINGS).map_err(storage)?;
            if rings_table.get(ring_name).map_err(storage)?.is_none() {
                return Err(Error::RingNotFound(ring_name.to_string()));
            }
            drop(rings_table); // redb only allows one open at a time

            let mut table = write.open_table(RESOURCE_RINGS).map_err(storage)?;
            let key = resource_id.as_bytes();
            let existing = match table.get(key).map_err(storage)? {
                Some(v) => decode_ring_names(v.value()),
                None => Vec::new(),
            };

            let names = crate::registry::compute_resource_rings(existing, ring_name);
            table
                .insert(key, encode_ring_names(&names).as_slice())
                .map_err(storage)?;
        }
        write.commit().map_err(storage)?;
        Ok(())
    }

    fn is_allowed<ResId: ResourceId>(
        &self,
        peer: &EndpointId,
        resource_id: &ResId,
    ) -> Result<bool, Error> {
        let read = self.db.begin_read().map_err(storage)?;

        let fr_table = read.open_table(RESOURCE_RINGS).map_err(storage)?;
        let ring_names = match fr_table.get(resource_id.as_bytes()).map_err(storage)? {
            None => return Ok(false),
            Some(v) => decode_ring_names(v.value()),
        };
        if ring_names.is_empty() {
            return Ok(false);
        }
        if ring_names.iter().any(|n| n == OPEN_RING_NAME) {
            return Ok(true);
        }

        let r_table = read.open_table(RINGS).map_err(storage)?;
        let peer_bytes = *peer.as_bytes();
        for name in &ring_names {
            if let Some(members_raw) = r_table.get(name.as_str()).map_err(storage)? {
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

    #[test]
    fn satisfies_registry_contract() {
        let dir = tempdir().unwrap();
        let reg = RedbRegistry::open(dir.path().join("test.redb")).unwrap();
        registry_contract(&reg);
    }
}
