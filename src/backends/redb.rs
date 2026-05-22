//! Persistent registry backed by an embedded redb database.
//!
//! Three redb tables make up the data model:
//!
//! ```text
//! RINGS            ring_name → flat-concatenated peer-id bytes (32 B each)
//! RESOURCE_RINGS   resource_id → NUL-separated ring names
//! NICKNAMES        ring_name\0peer_id → display label (UTF-8)
//! RESOURCE_RING_PERMS  [2B len][resource_id][ring_name] → permission bitfield (u8)
//! ```
//!
//! The critical operation is [`RedbRegistry::has_permission`], which answers
//! "may this peer perform this operation on this resource?" in a single read
//! transaction by checking ring membership and the permission bitfield.
//!
//! # Open ring
//!
//! `OPEN_RING_NAME` ("open") is a built-in, reserved ring name. Resources
//! associated with it are readable by **any** peer regardless of membership.
//! The open ring is read-only: associating it with `Write` or `Delete`
//! permissions is rejected. It is bootstrapped on first `open()` and cannot
//! be deleted or renamed.

use std::{path::Path, sync::Arc};

use iroh::EndpointId;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

use crate::registry::{Permission, Registry, ResourceId};
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

/// Maps a composite key `[2B resource_id_len_le][resource_id][ring_name]` to a
/// permission bitfield (`u8`): bit 0 = Read, bit 1 = Write, bit 2 = Delete.
///
/// The 2-byte length prefix makes the key unambiguous for arbitrary resource id bytes.
const RESOURCE_RING_PERMS: TableDefinition<&[u8], u8> = TableDefinition::new("resource_ring_perms");

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
            write.open_table(RESOURCE_RING_PERMS).map_err(storage)?;

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
            let key = resource_id.as_bytes();
            let mut table = write.open_table(RESOURCE_RINGS).map_err(storage)?;
            let ring_names = table
                .remove(key)
                .map_err(storage)?
                .map(|v| decode_ring_names(v.value()))
                .unwrap_or_default();
            drop(table);

            if !ring_names.is_empty() {
                let mut perm_table = write.open_table(RESOURCE_RING_PERMS).map_err(storage)?;
                for name in &ring_names {
                    perm_table
                        .remove(perm_key(key, name).as_slice())
                        .map_err(storage)?;
                }
            }
        }
        write.commit().map_err(storage)?;
        Ok(())
    }

    fn list_resource_rings<ResId: ResourceId>(
        &self,
        resource_id: ResId,
    ) -> Result<Vec<(Ring, Vec<Permission>)>, Error> {
        let read = self.db.begin_read().map_err(storage)?;
        let rr_table = read.open_table(RESOURCE_RINGS).map_err(storage)?;
        let perm_table = read.open_table(RESOURCE_RING_PERMS).map_err(storage)?;
        match rr_table.get(resource_id.as_bytes()).map_err(storage)? {
            None => Ok(Vec::new()),
            Some(v) => decode_ring_names(v.value())
                .into_iter()
                .map(|ring_name| {
                    let ring =
                        Ring::new(&ring_name).expect("invariant: db ring names are always valid");
                    let key = perm_key(resource_id.as_bytes(), &ring_name);
                    let perms = perm_table
                        .get(key.as_slice())
                        .map_err(storage)?
                        .map(|v| byte_to_perms(v.value()))
                        .unwrap_or_default();
                    Ok((ring, perms))
                })
                .collect(),
        }
    }

    fn add_ring_to_resource<ResId: ResourceId>(
        &self,
        resource_id: ResId,
        ring_name: &str,
        permissions: &[Permission],
    ) -> Result<(), Error> {
        crate::registry::validate_ring_permissions(ring_name, permissions)?;
        let write = self.db.begin_write().map_err(storage)?;
        {
            let rings_table = write.open_table(RINGS).map_err(storage)?;
            if rings_table.get(ring_name).map_err(storage)?.is_none() {
                return Err(Error::RingNotFound(ring_name.to_string()));
            }
            drop(rings_table); // redb only allows one mutable table open at a time

            let key = resource_id.as_bytes();

            // Read existing ring names from RESOURCE_RINGS.
            let rr_table = write.open_table(RESOURCE_RINGS).map_err(storage)?;
            let ring_names = match rr_table.get(key).map_err(storage)? {
                Some(v) => decode_ring_names(v.value()),
                None => vec![],
            };
            drop(rr_table);

            // Look up stored permissions for each existing ring (preserves their permissions).
            let existing: Vec<(String, Vec<Permission>)> = if ring_names.is_empty() {
                vec![]
            } else {
                let perm_table = write.open_table(RESOURCE_RING_PERMS).map_err(storage)?;
                let result = ring_names
                    .into_iter()
                    .map(|n| {
                        let k = perm_key(key, &n);
                        let perms = perm_table
                            .get(k.as_slice())
                            .map_err(storage)?
                            .map(|v| byte_to_perms(v.value()))
                            .unwrap_or_default();
                        Ok((n, perms))
                    })
                    .collect::<Result<Vec<_>, Error>>();
                drop(perm_table);
                result?
            };

            let updated =
                crate::registry::compute_resource_rings(existing, ring_name, permissions.to_vec());

            let mut rr_table = write.open_table(RESOURCE_RINGS).map_err(storage)?;
            rr_table
                .insert(
                    key,
                    encode_ring_names(updated.iter().map(|(n, _)| n.as_str())).as_slice(),
                )
                .map_err(storage)?;
            drop(rr_table);

            // Only write the new ring's permission row; existing rings' rows are already correct.
            let mut perm_table = write.open_table(RESOURCE_RING_PERMS).map_err(storage)?;
            perm_table
                .insert(
                    perm_key(key, ring_name).as_slice(),
                    perms_to_byte(permissions),
                )
                .map_err(storage)?;
        }
        write.commit().map_err(storage)?;
        Ok(())
    }

    fn has_permission<ResId: ResourceId>(
        &self,
        peer: &EndpointId,
        resource_id: &ResId,
        permission: Permission,
    ) -> Result<bool, Error> {
        let read = self.db.begin_read().map_err(storage)?;

        let rr_table = read.open_table(RESOURCE_RINGS).map_err(storage)?;
        let ring_names = match rr_table.get(resource_id.as_bytes()).map_err(storage)? {
            None => return Ok(false),
            Some(v) => decode_ring_names(v.value()),
        };
        if ring_names.is_empty() {
            return Ok(false);
        }

        let perm_table = read.open_table(RESOURCE_RING_PERMS).map_err(storage)?;
        let r_table = read.open_table(RINGS).map_err(storage)?;
        let peer_bytes = *peer.as_bytes();
        let pbit = permission_bit(permission);

        for name in &ring_names {
            let k = perm_key(resource_id.as_bytes(), name);
            let bits = perm_table
                .get(k.as_slice())
                .map_err(storage)?
                .map(|v| v.value())
                .unwrap_or(0);
            if bits & pbit == 0 {
                continue;
            }
            if name == OPEN_RING_NAME {
                return Ok(true);
            }
            if let Some(members_raw) = r_table.get(name.as_str()).map_err(storage)? {
                if members_raw
                    .value()
                    .chunks_exact(32)
                    .any(|b| b == peer_bytes.as_slice())
                {
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

/// Composite key for the `RESOURCE_RING_PERMS` table.
///
/// Uses a 2-byte little-endian length prefix so the boundary between the
/// resource id bytes and the ring name bytes is always unambiguous, regardless
/// of the resource id content.
fn perm_key(resource_id: &[u8], ring_name: &str) -> Vec<u8> {
    let len = resource_id.len() as u16;
    let mut key = Vec::with_capacity(2 + resource_id.len() + ring_name.len());
    key.extend_from_slice(&len.to_le_bytes());
    key.extend_from_slice(resource_id);
    key.extend_from_slice(ring_name.as_bytes());
    key
}

fn permission_bit(p: Permission) -> u8 {
    match p {
        Permission::Read => 0b001,
        Permission::Write => 0b010,
        Permission::Delete => 0b100,
    }
}

fn perms_to_byte(perms: &[Permission]) -> u8 {
    perms.iter().fold(0u8, |bits, &p| bits | permission_bit(p))
}

fn byte_to_perms(bits: u8) -> Vec<Permission> {
    let mut perms = Vec::new();
    if bits & 0b001 != 0 {
        perms.push(Permission::Read);
    }
    if bits & 0b010 != 0 {
        perms.push(Permission::Write);
    }
    if bits & 0b100 != 0 {
        perms.push(Permission::Delete);
    }
    perms
}

fn encode_ring_names<'a>(names: impl Iterator<Item = &'a str>) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut first = true;
    for name in names {
        if !first {
            buf.push(b'\0');
        }
        buf.extend_from_slice(name.as_bytes());
        first = false;
    }
    buf
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
