//! Demonstrates `Permission::Write` with a simple push-to-store sub-protocol.
//!
//! Run with:
//!   cargo run --example write --features mem
//!
//! What this shows:
//!   1. A node stores incoming bytes in a shared in-memory map.
//!   2. A "writer" peer (ring member) pushes content -> access ALLOWED, bytes are stored.
//!   3. A "stranger" peer (not in the ring) attempts the same push -> access DENIED.
//!
//! Sub-protocol (after the gate sends ALLOWED):
//!
//! ```text
//! initiator → node  [rest]  raw content bytes
//! node → initiator  [ 2 B]  "ok" acknowledgment
//! ```

use anyhow::Result;
use std::{
    collections::{BTreeSet, HashMap},
    sync::{Arc, Mutex},
};

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

/// Receives content bytes over the stream and stores them keyed by resource id.
#[derive(Clone)]
struct WriteTransfer {
    store: Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>,
}

impl iroh_rings::Transfer for WriteTransfer {
    async fn can_access(&self, _peer: &EndpointId, _resource_id: &[u8]) -> bool {
        // Implementing this is optional; typical use is subranges of a blob
        // whose ancestor hashes have already been validated by the ring mechanism.
        false
    }

    async fn transfer(
        &self,
        resource_id: &[u8],
        send: &mut SendStream,
        recv: &mut RecvStream,
    ) -> Result<()> {
        let content = recv.read_to_end(1024 * 1024).await?;
        self.store
            .lock()
            .unwrap()
            .insert(resource_id.to_vec(), content);
        send.write_all(b"ok").await?;
        Ok(())
    }
}

/// Pushes `content` to `resource_id` on the node; returns `true` if ALLOWED.
async fn push(
    endpoint: &Endpoint,
    node_addr: EndpointAddr,
    resource_id: &[u8],
    content: &[u8],
) -> Result<bool> {
    let conn: Connection = endpoint.connect(node_addr, ALPN).await?;
    let (mut send, mut recv): (SendStream, RecvStream) = conn.open_bi().await?;

    send.write_all(&encode_request(resource_id, Permission::Write)?)
        .await?;
    send.write_all(content).await?;
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
    let writer_key = SecretKey::generate();
    let writer_id: EndpointId = writer_key.public();

    let registry = InMemoryRegistry::new();
    registry.create_ring("writers")?;
    registry.add_ring_to_resource(RESOURCE_ID.to_vec(), "writers", &[Permission::Write])?;
    registry.add_peer_to_ring("writers", writer_id, Some("alice"))?;

    let store: Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>> = Arc::new(Mutex::new(HashMap::new()));
    let transfer = WriteTransfer {
        store: Arc::clone(&store),
    };

    let node = Endpoint::builder(presets::Minimal).bind().await?;
    let gate = RingGate::new(registry, transfer);
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

    let writer = Endpoint::builder(presets::Minimal)
        .secret_key(writer_key)
        .bind()
        .await?;

    print!("writer  (in ring)  … ");
    match push(&writer, node_addr.clone(), RESOURCE_ID, b"hello from alice").await? {
        true => {
            let stored = store.lock().unwrap();
            let content = stored
                .get(RESOURCE_ID)
                .map(|v| String::from_utf8_lossy(v).into_owned());
            println!("ALLOWED — stored: {:?}", content.unwrap_or_default());
        }
        false => println!("DENIED (unexpected)"),
    }

    let stranger = Endpoint::builder(presets::Minimal).bind().await?;

    print!("stranger (no ring) … ");
    match push(&stranger, node_addr, RESOURCE_ID, b"intruder content").await? {
        true => println!("ALLOWED (unexpected)"),
        false => println!("DENIED (expected)"),
    }

    Ok(())
}
