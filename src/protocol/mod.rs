//! Wire protocol for `/iroh-rings/0`.
//!
//! # Wire protocol
//!
//! ```text
//! Request (initiator peer -> gate)
//!  [32 B]  resource id: identifies the resource being requested
//!
//! Response (gate -> initiator peer)
//!  [ 1 B]  status: 0x00 = DENIED, 0x01 = ALLOWED
//!  if DENIED: stream closes.
//!  if ALLOWED: the rest of both streams are handed to the [`Transfer`]
//!              implementor, which defines its own sub-protocol from this point.
//! ```

mod gate;

pub use gate::{RingGate, Transfer};

pub const SC_ALPN: &[u8] = b"/iroh-rings/0";

#[repr(u8)]
pub enum Status {
    Denied = 0x00,
    Allowed = 0x01,
}

impl TryFrom<u8> for Status {
    type Error = anyhow::Error;
    fn try_from(b: u8) -> anyhow::Result<Self> {
        match b {
            0x00 => Ok(Status::Denied),
            0x01 => Ok(Status::Allowed),
            _ => Err(anyhow::anyhow!("unexpected status byte: 0x{b:02x}")),
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
}
