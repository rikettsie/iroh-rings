//! Demonstrates `Permission::Read` with a fixed in-memory payload.
//!
//! Run with:
//!   cargo run --example read --features mem
//!
//! What this shows:
//!   1. A node creates a ring, associates a resource with Read permission, and
//!      starts a [`RingGate`]-protected endpoint.
//!   2. A "member" peer that was added to the ring connects, requests the resource,
//!      and receives the payload.
//!   3. A "stranger" peer that was never added to the ring connects, requests the
//!      same resource, and is denied — no payload is sent.

use anyhow::Result;
use std::collections::BTreeSet;

use iroh::{
    endpoint::{presets, Connection, RecvStream, SendStream},
    protocol::Router,
    Endpoint, EndpointAddr, EndpointId, SecretKey, TransportAddr,
};
use iroh_rings::{
    protocol::{encode_request, Status},
    InMemoryRegistry, Permission, Registry, RingGate, ALPN,
};

// The resource identifier — any stable byte sequence up to 256 bytes.
const RESOURCE_ID: &[u8] = b"example-document-v1";

// The payload served when access is granted.
const CONTENT: &[u8] = b"the content of example-document-v1";

/// A minimal [`iroh_rings::Transfer`] that serves a fixed in-memory payload.
///
/// Real implementations would look up `resource_id` in a local store and
/// stream the corresponding data over `send`.
#[derive(Clone)]
struct StaticTransfer;

impl iroh_rings::Transfer for StaticTransfer {
    async fn can_access(&self, _peer: &EndpointId, _resource_id: &[u8]) -> bool {
        // Implementing this is optional; typical use is subranges of a blob
        // whose ancestor hashes have already been validated by the ring mechanism.
        false
    }

    async fn transfer(
        &self,
        _resource_id: &[u8],
        send: &mut SendStream,
        _recv: &mut RecvStream,
    ) -> Result<()> {
        send.write_all(CONTENT).await?;
        Ok(())
    }
}

/// Connects to `node_addr`, requests `RESOURCE_ID` with `Read` permission,
/// and returns the payload if access was granted or `None` if denied.
async fn fetch(endpoint: &Endpoint, node_addr: EndpointAddr) -> Result<Option<Vec<u8>>> {
    let conn: Connection = endpoint.connect(node_addr, ALPN).await?;
    let (mut send, mut recv): (SendStream, RecvStream) = conn.open_bi().await?;

    send.write_all(&encode_request(RESOURCE_ID, Permission::Read)?)
        .await?;
    send.finish()?;

    let mut status_buf = [0u8; 1];
    recv.read_exact(&mut status_buf).await?;

    match Status::try_from(status_buf[0])? {
        Status::Allowed => {
            let data = recv.read_to_end(64 * 1024).await?;
            Ok(Some(data))
        }
        Status::Denied => Ok(None),
        _ => anyhow::bail!("unexpected status byte: {}", status_buf[0]),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Generate member key upfront so we can register it before it connects.
    let member_key = SecretKey::generate();
    let member_id: EndpointId = member_key.public();

    let registry = InMemoryRegistry::new();
    registry.create_ring("readers")?;
    registry.add_ring_to_resource(RESOURCE_ID.to_vec(), "readers", &[Permission::Read])?;
    registry.add_peer_to_ring("readers", member_id, Some("alice"))?;

    let node = Endpoint::builder(presets::Minimal).bind().await?;
    let gate = RingGate::new(registry, StaticTransfer);
    let _router = Router::builder(node.clone()).accept(ALPN, gate).spawn();

    let node_addr = EndpointAddr {
        id: node.id(),
        addrs: node
            .bound_sockets()
            .into_iter()
            .map(TransportAddr::Ip)
            .collect::<BTreeSet<_>>(),
    };

    println!("node    : {}", node.id());
    println!("resource: {}", String::from_utf8_lossy(RESOURCE_ID));
    println!();

    let member = Endpoint::builder(presets::Minimal)
        .secret_key(member_key)
        .bind()
        .await?;

    print!("member  (in ring)  … ");
    match fetch(&member, node_addr.clone()).await? {
        Some(data) => println!("ALLOWED — payload: {:?}", String::from_utf8_lossy(&data)),
        None => println!("DENIED (unexpected)"),
    }

    let stranger = Endpoint::builder(presets::Minimal).bind().await?;

    print!("stranger (no ring) … ");
    match fetch(&stranger, node_addr).await? {
        Some(_) => println!("ALLOWED (unexpected)"),
        None => println!("DENIED (expected)"),
    }

    Ok(())
}
