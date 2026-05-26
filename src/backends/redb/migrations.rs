//! Schema migrations for the redb registry backend.
//!
//! [`migrate`] is called by [`super::RedbRegistry::open`] on every startup.
//! It reads the stored schema version from the [`META`] table and runs all
//! pending migration steps in sequence. Each step executes in a single atomic
//! transaction that also bumps the version, so a crash mid-migration leaves
//! the database in a state where the step will be safely retried on the next
//! startup.
//!
//! ## Version history
//!
//! | Version | Change |
//! |---------|--------|
//! | 0 | Initial schema: `RINGS`, `RESOURCE_RINGS`, `NICKNAMES`. No permission data. |
//! | 1 | Added `RESOURCE_RING_PERMS`. All existing ring–resource associations are backfilled with `Read` permission. |
//! | 2 | Renamed `NICKNAMES` table to `LABELS`. All existing rows are copied and the old table is deleted. |

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

use crate::Error;

use super::{decode_ring_names, perm_key, storage, LABELS, RESOURCE_RINGS, RESOURCE_RING_PERMS};

/// Stores the single `schema_version` key.
const META: TableDefinition<&str, u32> = TableDefinition::new("meta");
const SCHEMA_VERSION_KEY: &str = "schema_version";

/// The schema version this code targets. Bump when adding a new migration step.
const CURRENT_VERSION: u32 = 2;

/// Legacy table name replaced by [`LABELS`] in schema v2.
const NICKNAMES_LEGACY: TableDefinition<&[u8], &str> = TableDefinition::new("nicknames");

/// Permission bitfield value for `Read`-only access.
const READ_BIT: u8 = 0b001;

/// Bring `db` up to [`CURRENT_VERSION`], running all pending migration steps.
///
/// Safe to call on a brand-new database (no data to backfill, only the version
/// is written) or an already-current database (early return after reading the
/// version).
///
/// # Errors
///
/// Returns [`Error::Storage`] if any read or write operation fails.
pub(super) fn migrate(db: &Database) -> Result<(), Error> {
    let version = read_version(db)?;
    if version >= CURRENT_VERSION {
        return Ok(());
    }
    if version < 1 {
        v0_to_v1(db)?;
    }
    if version < 2 {
        v1_to_v2(db)?;
    }
    Ok(())
}

fn read_version(db: &Database) -> Result<u32, Error> {
    let read = db.begin_read().map_err(storage)?;
    match read.open_table(META) {
        Ok(table) => Ok(table
            .get(SCHEMA_VERSION_KEY)
            .map_err(storage)?
            .map(|v| v.value())
            .unwrap_or(0)),
        Err(redb::TableError::TableDoesNotExist(_)) => Ok(0),
        Err(e) => Err(storage(e)),
    }
}

/// Backfill [`RESOURCE_RING_PERMS`] for every existing ring–resource
/// association, granting `Read` permission to all of them.
///
/// Before v1 the permission table did not exist; all associations are treated
/// as read-only, which matches the only operation the protocol exposed at the
/// time.
///
/// The schema version is bumped to `1` in the same transaction so the step is
/// atomic: either both the backfill and the version bump commit, or neither does.
fn v0_to_v1(db: &Database) -> Result<(), Error> {
    let write = db.begin_write().map_err(storage)?;
    {
        // Collect all existing resource → [ring names] associations.
        let rr_table = write.open_table(RESOURCE_RINGS).map_err(storage)?;
        let mut entries: Vec<(Vec<u8>, Vec<String>)> = Vec::new();
        for item in rr_table.iter().map_err(storage)? {
            let (k, v) = item.map_err(storage)?;
            entries.push((k.value().to_vec(), decode_ring_names(v.value())));
        }
        drop(rr_table);

        // Backfill: write a Read-only permission row for every missing entry.
        // The check for an existing row makes the step idempotent.
        let mut perm_table = write.open_table(RESOURCE_RING_PERMS).map_err(storage)?;
        for (resource_id, ring_names) in &entries {
            for ring_name in ring_names {
                let key = perm_key(resource_id, ring_name);
                if perm_table.get(key.as_slice()).map_err(storage)?.is_none() {
                    perm_table
                        .insert(key.as_slice(), READ_BIT)
                        .map_err(storage)?;
                }
            }
        }
        drop(perm_table);

        // Bump schema version atomically with the data migration.
        let mut meta = write.open_table(META).map_err(storage)?;
        meta.insert(SCHEMA_VERSION_KEY, 1u32).map_err(storage)?;
    }
    write.commit().map_err(storage)?;
    Ok(())
}

/// Copy all rows from the legacy `"nicknames"` table into `"labels"`, then
/// delete the old table. The `"labels"` table is already present because
/// [`super::RedbRegistry::open`] creates it before calling [`migrate`].
///
/// If the old table does not exist (fresh database never at v1 nickname data),
/// only the version bump is written.
fn v1_to_v2(db: &Database) -> Result<(), Error> {
    // Read rows from the old table in an isolated read transaction so we can
    // delete the table in the subsequent write transaction.
    let rows: Vec<(Vec<u8>, String)> = {
        let read = db.begin_read().map_err(storage)?;
        match read.open_table(NICKNAMES_LEGACY) {
            Ok(table) => table
                .iter()
                .map_err(storage)?
                .map(|r| {
                    let (k, v) = r.map_err(storage)?;
                    Ok((k.value().to_vec(), v.value().to_owned()))
                })
                .collect::<Result<_, Error>>()?,
            Err(redb::TableError::TableDoesNotExist(_)) => Vec::new(),
            Err(e) => return Err(storage(e)),
        }
    };

    let write = db.begin_write().map_err(storage)?;
    {
        if !rows.is_empty() {
            let mut label_table = write.open_table(LABELS).map_err(storage)?;
            for (key, value) in &rows {
                label_table
                    .insert(key.as_slice(), value.as_str())
                    .map_err(storage)?;
            }
        }

        // Returns Ok(false) if the table didn't exist — that's fine.
        write.delete_table(NICKNAMES_LEGACY).map_err(storage)?;

        let mut meta = write.open_table(META).map_err(storage)?;
        meta.insert(SCHEMA_VERSION_KEY, 2u32).map_err(storage)?;
    }
    write.commit().map_err(storage)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use redb::TableDefinition;
    use tempfile::tempdir;

    use super::*;

    const RINGS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("rings");
    const RESOURCE_RINGS_TABLE: TableDefinition<&[u8], &[u8]> =
        TableDefinition::new("resource_rings");

    fn open_bare(path: &std::path::Path) -> Database {
        Database::create(path).unwrap()
    }

    /// Simulate an old-schema database: create the pre-v1 tables without
    /// `RESOURCE_RING_PERMS` or `META`.
    fn bootstrap_old_schema(db: &Database) {
        let write = db.begin_write().unwrap();
        write.open_table(RINGS_TABLE).unwrap();
        write.open_table(RESOURCE_RINGS_TABLE).unwrap();
        write
            .open_table(TableDefinition::<&[u8], &str>::new("nicknames"))
            .unwrap();
        write.commit().unwrap();
    }

    /// Insert a ring–resource association directly into the old-schema tables.
    fn insert_old_association(db: &Database, resource_id: &[u8], ring_name: &str) {
        let write = db.begin_write().unwrap();
        {
            let mut rings = write.open_table(RINGS_TABLE).unwrap();
            if rings.get(ring_name).unwrap().is_none() {
                rings.insert(ring_name, &[][..]).unwrap();
            }
            drop(rings);
            let mut rr = write.open_table(RESOURCE_RINGS_TABLE).unwrap();
            rr.insert(resource_id, ring_name.as_bytes()).unwrap();
        }
        write.commit().unwrap();
    }

    #[test]
    fn new_database_migrates_to_current_version() {
        let dir = tempdir().unwrap();
        let db = open_bare(&dir.path().join("test.redb"));
        migrate(&db).unwrap();
        assert_eq!(read_version(&db).unwrap(), CURRENT_VERSION);
    }

    #[test]
    fn migration_is_idempotent() {
        let dir = tempdir().unwrap();
        let db = open_bare(&dir.path().join("test.redb"));
        migrate(&db).unwrap();
        migrate(&db).unwrap();
        assert_eq!(read_version(&db).unwrap(), CURRENT_VERSION);
    }

    #[test]
    fn v0_data_gets_read_permission_backfilled() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.redb");
        let resource_id = [0xabu8; 32];

        {
            let db = open_bare(&path);
            bootstrap_old_schema(&db);
            insert_old_association(&db, &resource_id, "friends");
        }

        let db = open_bare(&path);
        migrate(&db).unwrap();

        let read = db.begin_read().unwrap();
        let perm_table = read.open_table(RESOURCE_RING_PERMS).unwrap();
        let key = perm_key(&resource_id, "friends");
        let bits = perm_table
            .get(key.as_slice())
            .unwrap()
            .expect("perm row must exist after migration")
            .value();
        assert_eq!(bits & READ_BIT, READ_BIT, "Read bit must be set");
    }

    #[test]
    fn already_current_database_is_not_modified() {
        let dir = tempdir().unwrap();
        let db = open_bare(&dir.path().join("test.redb"));
        migrate(&db).unwrap();
        let version_before = read_version(&db).unwrap();
        migrate(&db).unwrap();
        assert_eq!(read_version(&db).unwrap(), version_before);
    }

    #[test]
    fn v1_nicknames_get_migrated_to_labels() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.redb");

        let peer_key = iroh::SecretKey::generate();
        let peer_id = peer_key.public();
        let ring_name = "friends";
        let label = "alice";

        // Build a v1 database: old schema + version set to 1 + a nickname row.
        {
            let db = open_bare(&path);
            bootstrap_old_schema(&db);
            insert_old_association(&db, &[0xabu8; 32], ring_name);

            // Set schema version to 1 and insert a nickname into the old table.
            let write = db.begin_write().unwrap();
            {
                let mut meta = write.open_table(META).unwrap();
                meta.insert(SCHEMA_VERSION_KEY, 1u32).unwrap();

                let mut nick_table = write
                    .open_table(TableDefinition::<&[u8], &str>::new("nicknames"))
                    .unwrap();
                // Build the key the same way label_key does: ring_name + NUL + peer_id bytes.
                let mut key = ring_name.as_bytes().to_vec();
                key.push(b'\0');
                key.extend_from_slice(peer_id.as_bytes());
                nick_table.insert(key.as_slice(), label).unwrap();
            }
            write.commit().unwrap();
        }

        // Run migration and verify the label is now in the LABELS table.
        {
            let db = open_bare(&path);
            migrate(&db).unwrap();
            assert_eq!(read_version(&db).unwrap(), CURRENT_VERSION);

            // Old table must be gone.
            let read = db.begin_read().unwrap();
            assert!(matches!(
                read.open_table(NICKNAMES_LEGACY),
                Err(redb::TableError::TableDoesNotExist(_))
            ));

            // New table must contain the migrated row.
            let label_table = read.open_table(LABELS).unwrap();
            let mut key = ring_name.as_bytes().to_vec();
            key.push(b'\0');
            key.extend_from_slice(peer_id.as_bytes());
            let stored = label_table
                .get(key.as_slice())
                .unwrap()
                .expect("label row must exist after migration")
                .value()
                .to_owned();
            assert_eq!(stored, label);
        }
    }
}
