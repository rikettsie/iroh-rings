use serde::{Deserialize, Serialize};
use std::time::Instant;

use crate::Error;

/// Reserved name for the built-in open ring (the public ring):
/// resources associated with this ring are accessible to any peer without membership checks.
pub const OPEN_RING_NAME: &str = "open";

/// A named group of peers.
///
/// Equality and hashing are based solely on the name; `timestamp` records
/// when the ring was created and is used for display ordering only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ring {
    /// Unique name. Must be non-empty, whitespace-free, and NUL-free.
    name: String,

    /// Creation time — not part of equality or hashing.
    #[serde(with = "serde_millis")]
    timestamp: Instant,
}

impl Ring {
    /// Creates a ring with the given name.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RingNameEmpty`] if `name` is empty, or
    /// [`Error::RingNameInvalidChars`] if it contains whitespace or NUL bytes.
    pub fn new<S: AsRef<str>>(name: S) -> Result<Self, Error> {
        let name = name.as_ref();
        if name.is_empty() {
            return Err(Error::RingNameEmpty);
        }
        if name.contains(|c: char| c.is_whitespace() || c == '\0') {
            return Err(Error::RingNameInvalidChars);
        }
        Ok(Self {
            name: name.to_string(),
            timestamp: Instant::now(),
        })
    }

    /// Creates the built-in open ring.
    #[must_use]
    pub fn new_open() -> Self {
        Self {
            name: OPEN_RING_NAME.to_string(),
            timestamp: Instant::now(),
        }
    }

    /// Returns the ring name as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.name
    }

    /// Returns `true` if this is the built-in open ring.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.name == OPEN_RING_NAME
    }

    /// Returns the creation timestamp, used for display ordering only.
    #[must_use]
    pub fn timestamp(&self) -> Instant {
        self.timestamp
    }
}

impl PartialEq for Ring {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for Ring {}

impl std::hash::Hash for Ring {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.name.hash(state);
    }
}

impl std::fmt::Display for Ring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_valid_name_succeeds() {
        let ring = Ring::new("friends").unwrap();
        assert_eq!(ring.as_str(), "friends");
    }

    #[test]
    fn new_empty_name_errors() {
        assert!(Ring::new("").is_err());
    }

    #[test]
    fn new_name_with_space_errors() {
        assert!(Ring::new("my ring").is_err());
    }

    #[test]
    fn new_name_with_tab_errors() {
        assert!(Ring::new("ring\there").is_err());
    }

    #[test]
    fn new_name_with_nul_errors() {
        assert!(Ring::new("ring\0name").is_err());
    }

    #[test]
    fn new_open_creates_open_ring() {
        let ring = Ring::new_open();
        assert_eq!(ring.as_str(), OPEN_RING_NAME);
        assert!(ring.is_open());
    }

    #[test]
    fn is_open_returns_false_for_non_open_ring() {
        let ring = Ring::new("friends").unwrap();
        assert!(!ring.is_open());
    }

    #[test]
    fn display_shows_name() {
        let ring = Ring::new("friends").unwrap();
        assert_eq!(ring.to_string(), "friends");
    }

    #[test]
    fn equality_is_based_on_name_not_timestamp() {
        let a = Ring::new("friends").unwrap();
        // Spin briefly so Instant::now() could differ, then create a second ring.
        let b = Ring::new("friends").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn rings_with_different_names_are_not_equal() {
        let a = Ring::new("friends").unwrap();
        let b = Ring::new("work").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn hash_is_consistent_with_equality() {
        use std::collections::HashSet;
        let a = Ring::new("friends").unwrap();
        let b = Ring::new("friends").unwrap();
        let mut set = HashSet::new();
        set.insert(a);
        // Inserting an equal ring must not grow the set.
        set.insert(b);
        assert_eq!(set.len(), 1);
    }
}
