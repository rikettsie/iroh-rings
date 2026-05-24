//! Integration tests for [`RingGate`] access-control enforcement.
//!
//! Each test spins up a real in-process iroh endpoint pair to exercise the
//! full wire protocol, verifying that ring membership and
//! [`iroh_rings::Transfer::can_access`] are both required for access to be
//! granted (i.e. the gate uses `&&`, not `||`).

#![cfg(feature = "mem")]

use std::collections::BTreeSet;

use anyhow::Result;
use iroh::{
    endpoint::{presets, Connection, RecvStream, SendStream},
    protocol::Router,
    Endpoint, EndpointAddr, SecretKey, TransportAddr,
};
use iroh_rings::{
    protocol::{encode_request, Status},
    InMemoryRegistry, Permission, Registry, RingGate, ALPN,
};

const RESOURCE: &[u8] = b"gate-test-resource";

/// A [`iroh_rings::Transfer`] whose `can_access` verdict is fixed at construction.
#[derive(Clone)]
struct FixedTransfer(bool);

impl iroh_rings::Transfer for FixedTransfer {
    async fn can_access(&self, _peer: &iroh::EndpointId, _resource_id: &[u8]) -> bool {
        self.0
    }

    async fn transfer(
        &self,
        _resource_id: &[u8],
        send: &mut SendStream,
        _recv: &mut RecvStream,
    ) -> Result<()> {
        send.write_all(b"ok").await?;
        Ok(())
    }
}

struct Server {
    addr: EndpointAddr,
    _router: Router,
}

/// Starts a server with one ring member registered on `RESOURCE`.
/// `can_access` controls what `FixedTransfer` returns for every peer.
async fn start_server(can_access: bool) -> Result<(Server, SecretKey)> {
    let member_key = SecretKey::generate();
    let member_id = member_key.public();

    let registry = InMemoryRegistry::new();
    registry.create_ring("members")?;
    registry.add_ring_to_resource(RESOURCE.to_vec(), "members", &[Permission::Read])?;
    registry.add_peer_to_ring("members", member_id, None)?;

    let endpoint = Endpoint::builder(presets::Minimal).bind().await?;
    let gate = RingGate::new(registry, FixedTransfer(can_access));
    let router = Router::builder(endpoint.clone()).accept(ALPN, gate).spawn();

    let addr = EndpointAddr {
        id: endpoint.id(),
        addrs: endpoint
            .bound_sockets()
            .into_iter()
            .map(TransportAddr::Ip)
            .collect::<BTreeSet<_>>(),
    };

    Ok((
        Server {
            addr,
            _router: router,
        },
        member_key,
    ))
}

/// Connects `endpoint` to `server`, requests `RESOURCE` with Read permission,
/// and returns `Some(payload)` if ALLOWED or `None` if DENIED.
async fn fetch(endpoint: &Endpoint, server_addr: EndpointAddr) -> Result<Option<Vec<u8>>> {
    let conn: Connection = endpoint.connect(server_addr, ALPN).await?;
    let (mut send, mut recv): (SendStream, RecvStream) = conn.open_bi().await?;
    send.write_all(&encode_request(RESOURCE, Permission::Read)?)
        .await?;
    send.finish()?;

    let mut status = [0u8; 1];
    recv.read_exact(&mut status).await?;
    match Status::try_from(status[0])? {
        Status::Allowed => Ok(Some(recv.read_to_end(1024).await?)),
        Status::Denied => Ok(None),
        _ => anyhow::bail!("unexpected status byte: {}", status[0]),
    }
}

/// Ring member with can_access=true is allowed.
#[tokio::test]
async fn member_with_can_access_true_is_allowed() -> Result<()> {
    let (server, member_key) = start_server(true).await?;
    let member = Endpoint::builder(presets::Minimal)
        .secret_key(member_key)
        .bind()
        .await?;
    assert!(fetch(&member, server.addr).await?.is_some());
    Ok(())
}

/// Ring member with can_access=false is denied — both checks must pass.
#[tokio::test]
async fn member_with_can_access_false_is_denied() -> Result<()> {
    let (server, member_key) = start_server(false).await?;
    let member = Endpoint::builder(presets::Minimal)
        .secret_key(member_key)
        .bind()
        .await?;
    assert!(fetch(&member, server.addr).await?.is_none());
    Ok(())
}

/// Stranger with can_access=true is denied — ring membership is required.
/// This is the exact case that caught the `||` vs `&&` bug in the gate.
#[tokio::test]
async fn stranger_with_can_access_true_is_denied() -> Result<()> {
    let (server, _) = start_server(true).await?;
    let stranger = Endpoint::builder(presets::Minimal).bind().await?;
    assert!(fetch(&stranger, server.addr).await?.is_none());
    Ok(())
}

/// Stranger with can_access=false is denied.
#[tokio::test]
async fn stranger_with_can_access_false_is_denied() -> Result<()> {
    let (server, _) = start_server(false).await?;
    let stranger = Endpoint::builder(presets::Minimal).bind().await?;
    assert!(fetch(&stranger, server.addr).await?.is_none());
    Ok(())
}
