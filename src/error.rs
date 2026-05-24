//! Public error type for iroh-rings.

/// All errors that can be returned by the iroh-rings public API.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Ring name must not be empty.
    #[error("ring name must not be empty")]
    RingNameEmpty,

    /// Ring name must not contain whitespace or NUL bytes.
    #[error("ring name must not contain whitespace or NUL bytes")]
    RingNameInvalidChars,

    /// The ring name is reserved by the implementation and cannot be used by callers.
    #[error("'{0}' is a reserved ring name")]
    RingNameReserved(String),

    /// A ring with this name already exists.
    #[error("ring '{0}' already exists")]
    RingAlreadyExists(String),

    /// No ring with this name was found in the registry.
    #[error("ring '{0}' not found")]
    RingNotFound(String),

    /// The resource id is longer than the protocol maximum.
    #[error("resource id length {0} exceeds maximum")]
    ResourceIdTooLong(usize),

    /// A status byte received on the wire was not recognised.
    #[error("unexpected status byte: {0:#04x}")]
    UnknownStatusByte(u8),

    /// The operation byte received on the wire was not a recognised [`Permission`](crate::Permission).
    #[error("unknown operation byte: {0:#04x}")]
    UnknownOperationByte(u8),

    /// The open ring may only be associated with [`Permission::Read`](crate::Permission::Read).
    ///
    /// Granting Write or Delete to the open ring would allow any unauthenticated peer
    /// to modify or disassociate resources.
    #[error("the open ring may only be associated with Read permission")]
    OpenRingReadOnly,

    /// A ring–resource association was requested with an empty permission set.
    ///
    /// Every association must grant at least one [`Permission`](crate::Permission);
    /// an empty set is meaningless and is rejected as a programming error.
    #[error("permission set must not be empty")]
    EmptyPermissionSet,

    /// An underlying storage backend returned an error.
    #[error("storage error: {0}")]
    Storage(Box<dyn std::error::Error + Send + Sync + 'static>),
}
