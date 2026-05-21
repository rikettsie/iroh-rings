//! Wire protocol for `/iroh-rings/1`.
//!
//! # Wire protocol
//!
//! ```text
//! Request (initiator peer -> gate)
//!  [ 2 B]  u16-le: resource id length (N)
//!  [ N B]  resource id bytes
//!
//! Response (gate -> initiator peer)
//!  [ 1 B]  status: 0x00 = DENIED, 0x01 = ALLOWED
//!  if DENIED: stream closes.
//!  if ALLOWED: the rest of both streams are handed to the [`Transfer`]
//!              implementor, which defines its own sub-protocol from this point.
//! ```

mod gate;

pub use gate::{RingGate, Transfer};

/// ALPN identifier used to negotiate the iroh-rings protocol during the QUIC handshake.
pub const RINGS_ALPN: &[u8] = b"/iroh-rings/1";

/// Maximum number of bytes accepted for a resource id on the wire.
///
/// Enforced by the gate before any allocation so a malicious peer cannot
/// trigger an unbounded allocation by sending a large length field.
pub const MAX_RESOURCE_ID_BYTES: usize = 256;

/// Encodes a resource id request for sending to a [`RingGate`].
///
/// Writes `[u16-le length][resource_id bytes]` into a new buffer.
///
/// # Errors
///
/// Returns an error if `resource_id.len()` exceeds [`MAX_RESOURCE_ID_BYTES`].
pub fn encode_request(resource_id: &[u8]) -> Result<Vec<u8>, crate::Error> {
    if resource_id.len() > MAX_RESOURCE_ID_BYTES {
        return Err(crate::Error::ResourceIdTooLong(resource_id.len()));
    }
    let len = resource_id.len() as u16;
    let mut out = Vec::with_capacity(std::mem::size_of::<u16>() + resource_id.len());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(resource_id);
    Ok(out)
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
    fn status_denied_from_byte() {
        assert!(matches!(Status::try_from(0x00).unwrap(), Status::Denied));
    }

    #[test]
    fn status_allowed_from_byte() {
        assert!(matches!(Status::try_from(0x01).unwrap(), Status::Allowed));
    }

    #[test]
    fn status_unknown_byte_errors() {
        assert!(Status::try_from(0x02).is_err());
        assert!(Status::try_from(0xff).is_err());
    }

    #[test]
    fn encode_request_empty_resource_id_writes_zero_length_header() {
        let encoded = encode_request(&[]).unwrap();
        assert_eq!(encoded.len(), 2);
        assert_eq!(u16::from_le_bytes(encoded[..2].try_into().unwrap()), 0);
    }

    #[test]
    fn encode_request_32_byte_id_round_trips() {
        let id = [0xabu8; 32];
        let encoded = encode_request(&id).unwrap();
        let len = u16::from_le_bytes(encoded[..2].try_into().unwrap()) as usize;
        assert_eq!(len, 32);
        assert_eq!(&encoded[2..], &id);
    }

    #[test]
    fn encode_request_16_byte_id_round_trips() {
        let id = [0x42u8; 16];
        let encoded = encode_request(&id).unwrap();
        let len = u16::from_le_bytes(encoded[..2].try_into().unwrap()) as usize;
        assert_eq!(len, 16);
        assert_eq!(&encoded[2..], &id);
    }

    #[test]
    fn encode_request_rejects_oversized_resource_id() {
        let id = vec![0u8; MAX_RESOURCE_ID_BYTES + 1];
        assert!(encode_request(&id).is_err());
    }

    #[test]
    fn encode_request_accepts_maximum_size_resource_id() {
        let id = vec![0u8; MAX_RESOURCE_ID_BYTES];
        assert!(encode_request(&id).is_ok());
    }
}
