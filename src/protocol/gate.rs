//! [`RingGate`]: the iroh [`ProtocolHandler`] that enforces ring-based access control.
//!
//! When a peer opens a bi-directional stream, [`RingGate`] reads the
//! length-prefixed resource id, checks [`Registry::is_allowed`] (and [`Transfer::can_access`]
//! for application-level checks), then either closes the stream with a DENIED
//! byte or writes ALLOWED and delegates the rest of the stream to the
//! [`Transfer`] concrete implementations.
//!
//! # Security
//!
//! Peer identity is authenticated by the QUIC/TLS 1.3 handshake before any
//! application byte is exchanged. Each peer's [`EndpointId`] is their Ed25519
//! public key; completing the handshake proves possession of the corresponding
//! private key. By the time [`RingGate`] reads the resource id, the caller's
//! identity is cryptographically guaranteed — it cannot be spoofed by a peer
//! who does not hold the matching private key.
//!
//! # Extension point
//!
//! [`Transfer`] is the trait to implement when adding new resource kinds.
//! See [`crate::transfers::fs`] for a working example.

use std::fmt;

use anyhow::{Context, Result};
use iroh::{
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler},
    EndpointId,
};
use tracing::{debug, info, instrument, warn};

use crate::registry::Registry;

use super::{Status, MAX_RESOURCE_ID_BYTES};

/// Defines the sub-protocol that runs after the gate grants access.
///
/// The gate handles ring membership checks and the wire handshake; `Transfer`
/// implementors take over from the ALLOWED byte onward and define what is
/// actually exchanged between peers.
///
/// Implement this trait to build application-specific sub-protocols on top of
/// the ring-based access control layer.
pub trait Transfer: Clone + Send + Sync + 'static {
    /// Application-level access check performed before [`Transfer::transfer`].
    ///
    /// Return `true` to allow the transfer to proceed, `false` to deny it.
    /// The gate already verified ring membership; use this for additional
    /// checks (e.g. collection membership, quota, rate-limiting).
    fn can_access(
        &self,
        peer: &EndpointId,
        resource_id: &[u8],
    ) -> impl std::future::Future<Output = bool> + Send;

    /// Called after the gate has verified access.
    ///
    /// Both streams are fully handed over:
    /// - `recv` contains whatever the initiator sent after the resource id
    /// - `send` is ready for the implementor's response payload
    ///
    /// The gate writes the ALLOWED status byte before calling this; the implementor
    /// writes everything after.
    fn transfer(
        &self,
        resource_id: &[u8],
        send: &mut iroh::endpoint::SendStream,
        recv: &mut iroh::endpoint::RecvStream,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
}

/// iroh [`ProtocolHandler`] that enforces ring-based access control on incoming connections.
#[derive(Clone)]
pub struct RingGate<R, T> {
    registry: R,
    transfer: T,
}

impl<R, T> fmt::Debug for RingGate<R, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RingGate").finish_non_exhaustive()
    }
}

impl<R: Registry + Clone + Send + Sync + 'static, T: Transfer> RingGate<R, T> {
    /// Creates a new gate backed by the given registry and transfer handler.
    pub fn new(registry: R, transfer: T) -> Self {
        RingGate { registry, transfer }
    }
}

impl<R: Registry + Clone + Send + Sync + 'static, T: Transfer> ProtocolHandler for RingGate<R, T> {
    fn accept(
        &self,
        conn: Connection,
    ) -> impl std::future::Future<Output = Result<(), AcceptError>> + Send {
        let gate = self.clone();
        async move {
            gate.handle(conn)
                .await
                .map_err(|e| AcceptError::from_boxed(e.into()))
        }
    }
}

impl<R: Registry + Clone + Send + Sync + 'static, T: Transfer> RingGate<R, T> {
    async fn handle(&self, conn: Connection) -> Result<()> {
        let peer: EndpointId = conn.remote_id();
        while let Ok((send, recv)) = conn.accept_bi().await {
            let gate = self.clone();
            tokio::spawn(async move {
                if let Err(e) = gate.handle_request(peer, send, recv).await {
                    warn!(%peer, "request error: {e:#}");
                }
            });
        }
        Ok(())
    }

    #[instrument(skip(self, send, recv), fields(peer = %peer))]
    async fn handle_request(
        &self,
        peer: EndpointId,
        mut send: iroh::endpoint::SendStream,
        mut recv: iroh::endpoint::RecvStream,
    ) -> Result<()> {
        let mut len_buf = [0u8; std::mem::size_of::<u16>()];
        recv.read_exact(&mut len_buf)
            .await
            .context("reading resource_id length")?;
        let len = parse_resource_id_len(&len_buf)?;

        let mut resource_id = vec![0u8; len];
        recv.read_exact(&mut resource_id)
            .await
            .context("reading resource_id")?;

        debug!(%peer, resource_id = %hex::encode(&resource_id), "request received");

        let allowed = self
            .registry
            .is_allowed(&peer, &resource_id)
            .unwrap_or(false)
            || self.transfer.can_access(&peer, &resource_id).await;

        if !allowed {
            warn!(%peer, resource_id = %hex::encode(&resource_id), "DENIED");
            send.write_all(&[Status::Denied as u8]).await?;
            send.finish()?;
            return Ok(());
        }

        send.write_all(&[Status::Allowed as u8]).await?;
        info!(%peer, resource_id = %hex::encode(&resource_id), "TRANSFER ALLOWED");

        match self
            .transfer
            .transfer(&resource_id, &mut send, &mut recv)
            .await
        {
            Ok(()) => {
                send.finish()?;
                info!(%peer, resource_id = %hex::encode(&resource_id), "TRANSFER COMPLETED");
            }
            Err(e) => {
                warn!(%peer, resource_id = %hex::encode(&resource_id), "TRANSFER FAILED");
                return Err(e).context("transfer failed");
            }
        }

        Ok(())
    }
}

fn parse_resource_id_len(buf: &[u8; 2]) -> Result<usize> {
    let len = u16::from_le_bytes(*buf) as usize;
    anyhow::ensure!(
        len <= MAX_RESOURCE_ID_BYTES,
        "resource id length {len} exceeds maximum {MAX_RESOURCE_ID_BYTES}",
    );
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_resource_id_len_zero_is_valid() {
        assert_eq!(parse_resource_id_len(&0u16.to_le_bytes()).unwrap(), 0);
    }

    #[test]
    fn parse_resource_id_len_typical_is_valid() {
        assert_eq!(parse_resource_id_len(&32u16.to_le_bytes()).unwrap(), 32);
    }

    #[test]
    fn parse_resource_id_len_maximum_is_valid() {
        let max = MAX_RESOURCE_ID_BYTES as u16;
        assert_eq!(
            parse_resource_id_len(&max.to_le_bytes()).unwrap(),
            MAX_RESOURCE_ID_BYTES,
        );
    }

    #[test]
    fn parse_resource_id_len_exceeding_maximum_errors() {
        let over = (MAX_RESOURCE_ID_BYTES + 1) as u16;
        assert!(parse_resource_id_len(&over.to_le_bytes()).is_err());
    }
}
