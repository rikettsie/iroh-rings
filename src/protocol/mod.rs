//! Wire protocol for `/iroh-rings/2`.
//!
//! # Wire protocol
//!
//! ```text
//! Request (initiator peer -> gate)
//!  [ 2 B]  u16-le: resource id length (N)
//!  [ N B]  resource id bytes
//!  [ 1 B]  operation: 0x01 = Read, 0x02 = Write, 0x03 = Delete
//!
//! Response (gate -> initiator peer)
//!  [ 1 B]  status: 0x00 = DENIED, 0x01 = ALLOWED
//!  if DENIED: stream closes.
//!  if ALLOWED: the rest of both streams are handed to the [`Transfer`]
//!              implementor, which defines its own sub-protocol from this point.
//! ```

mod gate;

pub use gate::{RingGate, Transfer};

use crate::registry::Permission;

/// ALPN identifier used to negotiate the iroh-rings protocol during the QUIC handshake.
pub const RINGS_ALPN: &[u8] = b"/iroh-rings/2";

/// Maximum number of bytes accepted for a resource id on the wire.
///
/// Enforced by the gate before any allocation so a malicious peer cannot
/// trigger an unbounded allocation by sending a large length field.
pub const MAX_RESOURCE_ID_BYTES: usize = 256;

/// Encodes a resource request for sending to a [`RingGate`].
///
/// Writes `[u16-le length][resource_id bytes][operation byte]` into a new buffer.
///
/// # Errors
///
/// Returns an error if `resource_id.len()` exceeds [`MAX_RESOURCE_ID_BYTES`].
pub fn encode_request(resource_id: &[u8], permission: Permission) -> Result<Vec<u8>, crate::Error> {
    if resource_id.len() > MAX_RESOURCE_ID_BYTES {
        return Err(crate::Error::ResourceIdTooLong(resource_id.len()));
    }
    let len = resource_id.len() as u16;
    let mut out = Vec::with_capacity(std::mem::size_of::<u16>() + resource_id.len() + 1);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(resource_id);
    out.push(encode_operation(permission));
    Ok(out)
}

/// Maps a [`Permission`] to its wire byte representation.
pub(crate) fn encode_operation(permission: Permission) -> u8 {
    match permission {
        Permission::Read => 0x01,
        Permission::Write => 0x02,
        Permission::Delete => 0x03,
    }
}

/// Parses a wire operation byte into a [`Permission`].
///
/// # Errors
///
/// Returns [`crate::Error::UnknownOperationByte`] if the byte does not map to a known operation.
pub(crate) fn parse_operation(byte: u8) -> Result<Permission, crate::Error> {
    match byte {
        0x01 => Ok(Permission::Read),
        0x02 => Ok(Permission::Write),
        0x03 => Ok(Permission::Delete),
        _ => Err(crate::Error::UnknownOperationByte(byte)),
    }
}

/// Gate response byte sent to the initiator after a resource request.
#[non_exhaustive]
#[repr(u8)]
pub enum Status {
    /// Access denied; the stream is closed immediately after this byte.
    Denied = 0x00,
    /// Access granted; the [`Transfer`] implementor takes over both streams.
    Allowed = 0x01,
}

impl TryFrom<u8> for Status {
    type Error = crate::Error;
    fn try_from(b: u8) -> Result<Self, crate::Error> {
        match b {
            0x00 => Ok(Status::Denied),
            0x01 => Ok(Status::Allowed),
            _ => Err(crate::Error::UnknownStatusByte(b)),
        }
    }
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Status::Denied => f.write_str("Denied"),
            Status::Allowed => f.write_str("Allowed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_denied_parses_from_byte() {
        assert!(matches!(Status::try_from(0x00).unwrap(), Status::Denied));
    }

    #[test]
    fn status_allowed_parses_from_byte() {
        assert!(matches!(Status::try_from(0x01).unwrap(), Status::Allowed));
    }

    #[test]
    fn status_unknown_byte_errors() {
        assert!(Status::try_from(0x02).is_err());
        assert!(Status::try_from(0xff).is_err());
    }

    #[test]
    fn encode_request_empty_resource_id_writes_zero_length_header() {
        let encoded = encode_request(&[], Permission::Read).unwrap();
        assert_eq!(encoded.len(), 3); // 2B len + 0B id + 1B op
        assert_eq!(u16::from_le_bytes(encoded[..2].try_into().unwrap()), 0);
        assert_eq!(encoded[2], encode_operation(Permission::Read));
    }

    #[test]
    fn encode_request_32_byte_id_round_trips() {
        let id = [0xabu8; 32];
        let encoded = encode_request(&id, Permission::Read).unwrap();
        let len = u16::from_le_bytes(encoded[..2].try_into().unwrap()) as usize;
        assert_eq!(len, 32);
        assert_eq!(&encoded[2..2 + 32], &id);
        assert_eq!(encoded[2 + 32], encode_operation(Permission::Read));
    }

    #[test]
    fn encode_request_write_operation_sets_correct_byte() {
        let id = [0x01u8; 16];
        let encoded = encode_request(&id, Permission::Write).unwrap();
        assert_eq!(
            *encoded.last().unwrap(),
            encode_operation(Permission::Write)
        );
    }

    #[test]
    fn encode_request_delete_operation_sets_correct_byte() {
        let id = [0x01u8; 16];
        let encoded = encode_request(&id, Permission::Delete).unwrap();
        assert_eq!(
            *encoded.last().unwrap(),
            encode_operation(Permission::Delete)
        );
    }

    #[test]
    fn encode_request_rejects_oversized_resource_id() {
        let id = vec![0u8; MAX_RESOURCE_ID_BYTES + 1];
        assert!(encode_request(&id, Permission::Read).is_err());
    }

    #[test]
    fn encode_request_accepts_maximum_size_resource_id() {
        let id = vec![0u8; MAX_RESOURCE_ID_BYTES];
        assert!(encode_request(&id, Permission::Read).is_ok());
    }

    #[test]
    fn operation_bytes_are_distinct() {
        assert_ne!(
            encode_operation(Permission::Read),
            encode_operation(Permission::Write)
        );
        assert_ne!(
            encode_operation(Permission::Write),
            encode_operation(Permission::Delete)
        );
    }

    #[test]
    fn parse_operation_round_trips() {
        for p in [Permission::Read, Permission::Write, Permission::Delete] {
            assert_eq!(parse_operation(encode_operation(p)).unwrap(), p);
        }
    }

    #[test]
    fn parse_operation_unknown_byte_errors() {
        assert!(parse_operation(0x00).is_err());
        assert!(parse_operation(0xff).is_err());
    }
}
