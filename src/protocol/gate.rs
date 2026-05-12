use std::fmt;

use anyhow::{Context, Result};
use iroh::{
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler},
    EndpointId,
};
use tracing::{debug, info, warn};

use crate::registry::Registry;

use super::Status;

pub trait Transfer: Clone + Send + Sync + 'static {
    fn can_access(
        &self,
        peer: &EndpointId,
        resource_id: &[u8],
    ) -> impl std::future::Future<Output = bool> + Send;

    /// Called after the gate has verified access.
    ///
    /// Both streams are handed over in full: `recv` still contains whatever
    /// the initiator sent after the 32-byte resource id, and `send` is ready
    /// for the implementor's response payload. The gate writes the ALLOWED
    /// status byte before calling this; the implementor writes everything after.
    fn transfer(
        &self,
        resource_id: &[u8],
        send: &mut iroh::endpoint::SendStream,
        recv: &mut iroh::endpoint::RecvStream,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
}

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

    async fn handle_request(
        &self,
        peer: EndpointId,
        mut send: iroh::endpoint::SendStream,
        mut recv: iroh::endpoint::RecvStream,
    ) -> Result<()> {
        let mut resource_id = [0u8; 32];
        recv.read_exact(&mut resource_id)
            .await
            .context("reading resource_id")?;

        debug!(%peer, resource_id = %hex::encode(resource_id), "request received");

        let allowed = self
            .registry
            .is_allowed(&peer, &resource_id)
            .unwrap_or(false)
            || self.transfer.can_access(&peer, &resource_id).await;

        if !allowed {
            warn!(%peer, resource_id = %hex::encode(resource_id), "DENIED");
            send.write_all(&[Status::Denied as u8]).await?;
            send.finish()?;
            return Ok(());
        }

        send.write_all(&[Status::Allowed as u8]).await?;
        info!(%peer, resource_id = %hex::encode(resource_id), "TRANSFER ALLOWED");

        match self
            .transfer
            .transfer(&resource_id, &mut send, &mut recv)
            .await
        {
            Ok(()) => {
                send.finish()?;
                info!(%peer, resource_id = %hex::encode(resource_id), "TRANSFER COMPLETED");
            }
            Err(e) => {
                warn!(%peer, resource_id = %hex::encode(resource_id), "TRANSFER FAILED");
                return Err(e).context("transfer failed");
            }
        }

        Ok(())
    }
}
