//! Persistent registry backed by an embedded redb database.
//!
//! Five redb tables make up the data model:
//!
//! ```text
//! RINGS                ring_name → flat-concatenated peer-id bytes (32 B each)
//! RESOURCE_RINGS       resource_id → NUL-separated ring names
//! LABELS               ring_name\0peer_id → display label (UTF-8)
//! EXPIRIES             ring_name\0peer_id → membership expiry (secs, nanos) since UNIX epoch
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
//!
//! # Membership expiry
//!
//! A membership with an expiry in `EXPIRIES` is evicted lazily: once the
//! expiry has passed the peer is denied by `has_permission`, omitted from
//! `list_ring_peers`, and treated as absent by `add_peer_to_ring`. The rows
//! themselves are only removed when the peer is removed or re-added.

mod migrations;

use std::time::{Duration, SystemTime, UNIX_EPOCH};
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

/// Maps `ring_name \0 peer_id_bytes` to label string (display label only).
/// Ring names are validated to contain no NUL, so the separator is unambiguous.
const LABELS: TableDefinition<&[u8], &str> = TableDefinition::new("labels");

/// Maps `ring_name \0 peer_id_bytes` to the membership expiry as
/// `(secs, subsec_nanos)` since the UNIX epoch. Absent means the membership
/// never expires.
const EXPIRIES: TableDefinition<&[u8], (u64, u32)> = TableDefinition::new("expiries");

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
            write.open_table(LABELS).map_err(storage)?;
            write.open_table(EXPIRIES).map_err(storage)?;
            write.open_table(RESOURCE_RING_PERMS).map_err(storage)?;

            if rings.get(OPEN_RING_NAME).map_err(storage)?.is_none() {
                rings
                    .insert(OPEN_RING_NAME, encode_peer_ids(&[]).as_slice())
                    .map_err(storage)?;
            }
        }
        write.commit().map_err(storage)?;
        migrations::migrate(&db)?;
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
        label: Option<&str>,
        expires_at: Option<SystemTime>,
    ) -> Result<(), Error> {
        let now = SystemTime::now();
        let write = self.db.begin_write().map_err(storage)?;
        {
            let mut table = write.open_table(RINGS).map_err(storage)?;
            let mut members = match table.get(ring_name).map_err(storage)? {
                Some(v) => decode_peer_ids(v.value()),
                None => return Err(Error::RingNotFound(ring_name.to_string())),
            };
            let mut label_table = write.open_table(LABELS).map_err(storage)?;
            let mut exp_table = write.open_table(EXPIRIES).map_err(storage)?;
            let peer_bytes = *peer.as_bytes();
            let key = member_key(ring_name, &peer);
            if !members.contains(&peer_bytes) {
                members.push(peer_bytes);
                table
                    .insert(ring_name, encode_peer_ids(&members).as_slice())
                    .map_err(storage)?;
            } else if is_expired(&exp_table, ring_name, &peer, now)? {
                // An expired membership is equivalent to a removed one, so re-adding
                // starts fresh while the stale label and expiry are dropped.
                label_table.remove(key.as_slice()).map_err(storage)?;
                exp_table.remove(key.as_slice()).map_err(storage)?;
            }

            if let Some(lbl) = label {
                label_table.insert(key.as_slice(), lbl).map_err(storage)?;
            }
            // `None` leaves an existing expiry untouched, mirroring `label`
            // re-adding a live member never silently widens its access.
            if let Some(t) = expires_at {
                exp_table
                    .insert(key.as_slice(), encode_expiry(t))
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

            let key = member_key(ring_name, &peer);
            let mut label_table = write.open_table(LABELS).map_err(storage)?;
            label_table.remove(key.as_slice()).map_err(storage)?;
            let mut exp_table = write.open_table(EXPIRIES).map_err(storage)?;
            exp_table.remove(key.as_slice()).map_err(storage)?;
        }
        write.commit().map_err(storage)?;
        Ok(())
    }

    fn list_ring_peers(
        &self,
        ring_name: &str,
    ) -> Result<Vec<(EndpointId, Option<String>, Option<SystemTime>)>, Error> {
        let now = SystemTime::now();
        let read = self.db.begin_read().map_err(storage)?;
        let table = read.open_table(RINGS).map_err(storage)?;
        let label_table = read.open_table(LABELS).map_err(storage)?;
        let exp_table = read.open_table(EXPIRIES).map_err(storage)?;
        let Some(v) = table.get(ring_name).map_err(storage)? else {
            return Err(Error::RingNotFound(ring_name.to_string()));
        };
        let mut peers = Vec::new();
        for b in decode_peer_ids(v.value()) {
            let peer = EndpointId::from_bytes(&b)
                .map_err(|e| Error::Storage(Box::new(std::io::Error::other(e.to_string()))))?;
            let key = member_key(ring_name, &peer);
            let expires_at = exp_table
                .get(key.as_slice())
                .map_err(storage)?
                .map(|v| decode_expiry(v.value()));
            if expires_at.is_some_and(|t| now >= t) {
                continue; // expired memberships are evicted lazily
            }
            let label = label_table
                .get(key.as_slice())
                .map_err(storage)?
                .map(|v| v.value().to_owned());
            peers.push((peer, label, expires_at));
        }
        Ok(peers)
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
        let now = SystemTime::now();
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
        let exp_table = read.open_table(EXPIRIES).map_err(storage)?;
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
                    .as_chunks::<32>()
                    .0
                    .iter()
                    .any(|b| b == &peer_bytes)
                    && !is_expired(&exp_table, name, peer, now)?
                {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }
}

/// Composite key for the per-membership tables (`LABELS`, `EXPIRIES`).
///
/// The same peer can have a different label and expiry in each ring.
/// This is intentional: they are per-ring properties of the membership,
/// not a global identity as the peer-id is.
fn member_key(ring_name: &str, peer: &EndpointId) -> Vec<u8> {
    let mut key = ring_name.as_bytes().to_vec();
    key.push(b'\0');
    key.extend_from_slice(peer.as_bytes());
    key
}

/// Returns `true` if the membership of `peer` in `ring_name` has expired as of `now`.
fn is_expired(
    exp_table: &impl ReadableTable<&'static [u8], (u64, u32)>,
    ring_name: &str,
    peer: &EndpointId,
    now: SystemTime,
) -> Result<bool, Error> {
    Ok(exp_table
        .get(member_key(ring_name, peer).as_slice())
        .map_err(storage)?
        .is_some_and(|v| now >= decode_expiry(v.value())))
}

/// Encodes an expiry as `(secs, subsec_nanos)` since the UNIX epoch — the exact
/// representation of a [`Duration`], so the value round-trips losslessly.
///
/// Times before the epoch are clamped to the epoch: they are already expired
/// either way.
fn encode_expiry(t: SystemTime) -> (u64, u32) {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    (d.as_secs(), d.subsec_nanos())
}

fn decode_expiry((secs, nanos): (u64, u32)) -> SystemTime {
    UNIX_EPOCH
        .checked_add(Duration::new(secs, nanos))
        .expect("invariant: stored expiry was encoded from a valid SystemTime")
}

fn encode_peer_ids(ids: &[[u8; 32]]) -> Vec<u8> {
    ids.iter().flat_map(|b| b.iter().copied()).collect()
}

fn decode_peer_ids(raw: &[u8]) -> Vec<[u8; 32]> {
    raw.as_chunks::<32>().0.to_vec()
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
    use std::path::PathBuf;

    use super::*;
    use crate::registry::registry_contract;
    use tempfile::{tempdir, TempDir};

    const RES: [u8; 32] = [0xab; 32];

    fn make_peer() -> EndpointId {
        iroh::SecretKey::generate().public()
    }

    /// Registry with ring `r` granting `Read` on `RES`. The `TempDir` keeps the
    /// database file alive; the path allows reopening it.
    fn registry_with_ring() -> (RedbRegistry, TempDir, PathBuf) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.redb");
        let reg = RedbRegistry::open(&path).unwrap();
        reg.create_ring("r").unwrap();
        reg.add_ring_to_resource(RES, "r", &[Permission::Read])
            .unwrap();
        (reg, dir, path)
    }

    fn in_one_hour() -> SystemTime {
        SystemTime::now() + Duration::from_secs(3600)
    }

    #[test]
    fn satisfies_registry_contract() {
        let dir = tempdir().unwrap();
        let reg = RedbRegistry::open(dir.path().join("test.redb")).unwrap();
        registry_contract(&reg);
    }

    #[test]
    fn expired_member_is_denied_and_not_listed() {
        let (reg, _dir, _) = registry_with_ring();
        let peer = make_peer();
        reg.add_peer_to_ring("r", peer, Some("alice"), Some(UNIX_EPOCH))
            .unwrap();

        assert!(!reg.has_permission(&peer, &RES, Permission::Read).unwrap());
        assert!(reg.list_ring_peers("r").unwrap().is_empty());
    }

    #[test]
    fn member_with_future_expiry_is_active() {
        let (reg, _dir, _) = registry_with_ring();
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
    fn expiry_survives_reopen() {
        let (reg, _dir, path) = registry_with_ring();
        let live = make_peer();
        let expired = make_peer();
        let expires_at = in_one_hour();
        reg.add_peer_to_ring("r", live, None, Some(expires_at))
            .unwrap();
        reg.add_peer_to_ring("r", expired, None, Some(UNIX_EPOCH))
            .unwrap();
        drop(reg);

        let reg = RedbRegistry::open(&path).unwrap();
        assert!(reg.has_permission(&live, &RES, Permission::Read).unwrap());
        assert!(!reg
            .has_permission(&expired, &RES, Permission::Read)
            .unwrap());
        assert_eq!(
            reg.list_ring_peers("r").unwrap(),
            vec![(live, None, Some(expires_at))]
        );
    }

    #[test]
    fn readding_live_member_without_expiry_keeps_existing_expiry() {
        let (reg, _dir, _) = registry_with_ring();
        let peer = make_peer();
        let expires_at = in_one_hour();
        reg.add_peer_to_ring("r", peer, None, Some(expires_at))
            .unwrap();
        reg.add_peer_to_ring("r", peer, None, None).unwrap();

        assert_eq!(reg.list_ring_peers("r").unwrap()[0].2, Some(expires_at));
    }

    #[test]
    fn readding_expired_member_starts_a_fresh_membership() {
        let (reg, _dir, _) = registry_with_ring();
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
        let (reg, _dir, _) = registry_with_ring();
        let peer = make_peer();
        reg.add_peer_to_ring("r", peer, None, Some(in_one_hour()))
            .unwrap();
        reg.remove_peer_from_ring("r", peer).unwrap();
        reg.add_peer_to_ring("r", peer, None, None).unwrap();

        assert_eq!(reg.list_ring_peers("r").unwrap()[0].2, None);
    }

    #[test]
    fn expiry_is_scoped_to_the_ring() {
        let (reg, _dir, _) = registry_with_ring();
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

    #[test]
    fn pre_epoch_expiry_is_treated_as_expired() {
        let (reg, _dir, _) = registry_with_ring();
        let peer = make_peer();
        let before_epoch = UNIX_EPOCH - Duration::from_secs(1);
        reg.add_peer_to_ring("r", peer, None, Some(before_epoch))
            .unwrap();

        assert!(!reg.has_permission(&peer, &RES, Permission::Read).unwrap());
    }
}
