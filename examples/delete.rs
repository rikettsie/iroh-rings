//! Demonstrates `Permission::Delete` — removing a ring–resource association remotely.
//!
//! Run with:
//!   cargo run --example delete --features mem
//!
//! What this shows:
//!   1. A "stranger" peer (not in the ring) tries to delete — DENIED.
//!   2. A "curator" peer (ring member with Delete permission) deletes the
//!      ring–resource association — ALLOWED.
//!   3. After deletion, `list_resource_rings` returns empty, confirming access
//!      has been fully revoked for all peers on that resource.
//!
//! Sub-protocol (after the gate sends ALLOWED):
//!
//! ```text
//! node → initiator  [ 2 B]  "ok" acknowledgment (no initiator payload expected)
//! ```

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

const RESOURCE_ID: &[u8] = b"example-doc";

/// Removes the ring–resource association from the registry when access is granted.
#[derive(Clone)]
struct DeleteTransfer {
    registry: InMemoryRegistry,
}

impl iroh_rings::Transfer for DeleteTransfer {
    async fn can_access(&self, _peer: &EndpointId, _resource_id: &[u8]) -> bool {
        // Implementing this is optional; typical use is subranges of a blob
        // whose ancestor hashes have already been validated by the ring mechanism.
        false
    }

    async fn transfer(
        &self,
        resource_id: &[u8],
        send: &mut SendStream,
        _recv: &mut RecvStream,
    ) -> Result<()> {
        self.registry
            .remove_ring_from_resource(resource_id.to_vec())?;
        send.write_all(b"ok").await?;
        Ok(())
    }
}

/// Sends a Delete request; returns `true` if ALLOWED.
async fn delete(endpoint: &Endpoint, node_addr: EndpointAddr, resource_id: &[u8]) -> Result<bool> {
    let conn: Connection = endpoint.connect(node_addr, ALPN).await?;
    let (mut send, mut recv): (SendStream, RecvStream) = conn.open_bi().await?;

    send.write_all(&encode_request(resource_id, Permission::Delete)?)
        .await?;
    send.finish()?;

    let mut status = [0u8; 1];
    recv.read_exact(&mut status).await?;
    match Status::try_from(status[0])? {
        Status::Allowed => {
            recv.read_to_end(16).await?; // consume "ok"
            Ok(true)
        }
        Status::Denied => Ok(false),
        _ => anyhow::bail!("unexpected status byte: {:#04x}", status[0]),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let curator_key = SecretKey::generate();
    let curator_id: EndpointId = curator_key.public();

    let registry = InMemoryRegistry::new();
    registry.create_ring("curators")?;
    registry.add_ring_to_resource(RESOURCE_ID.to_vec(), "curators", &[Permission::Delete])?;
    registry.add_peer_to_ring("curators", curator_id, Some("alice"))?;

    let node = Endpoint::builder(presets::Minimal).bind().await?;
    let transfer = DeleteTransfer {
        registry: registry.clone(),
    };
    let gate = RingGate::new(registry.clone(), transfer);
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

    let stranger = Endpoint::builder(presets::Minimal).bind().await?;

    print!("stranger (no ring) … ");
    match delete(&stranger, node_addr.clone(), RESOURCE_ID).await? {
        true => println!("ALLOWED (unexpected)"),
        false => println!("DENIED (expected)"),
    }

    let curator = Endpoint::builder(presets::Minimal)
        .secret_key(curator_key)
        .bind()
        .await?;

    print!("curator  (in ring) … ");
    match delete(&curator, node_addr, RESOURCE_ID).await? {
        true => println!("ALLOWED — ring association removed"),
        false => println!("DENIED (unexpected)"),
    }

    let remaining = registry.list_resource_rings(RESOURCE_ID.to_vec())?;
    println!();
    println!(
        "ring associations after delete: {} (access fully revoked)",
        remaining.len()
    );

    Ok(())
}
