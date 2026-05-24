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

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

use crate::Error;

use super::{decode_ring_names, perm_key, storage, RESOURCE_RINGS, RESOURCE_RING_PERMS};

/// Stores the single `schema_version` key.
const META: TableDefinition<&str, u32> = TableDefinition::new("meta");
const SCHEMA_VERSION_KEY: &str = "schema_version";

/// The schema version this code targets. Bump when adding a new migration step.
const CURRENT_VERSION: u32 = 1;

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
}
