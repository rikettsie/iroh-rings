# iroh-rings

![CI](https://github.com/rikettsie/iroh-rings/actions/workflows/ci.yml/badge.svg)
[![codecov](https://codecov.io/gh/rikettsie/iroh-rings/graph/badge.svg)](https://codecov.io/gh/rikettsie/iroh-rings)
[![crates.io](https://img.shields.io/crates/v/iroh-rings.svg)](https://crates.io/crates/iroh-rings)
[![docs.rs](https://docs.rs/iroh-rings/badge.svg)](https://docs.rs/iroh-rings)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE-MIT)

Ring-based, permission-typed access control for resources over [iroh](https://github.com/n0-computer/iroh) protocols.

## At a glance

```rust
let reg = InMemoryRegistry::new();
reg.create_ring("friends")?;
reg.add_peer_to_ring("friends", alice_id, None)?;
reg.add_ring_to_resource(&photo_id, "friends", &[Permission::Read, Permission::Write])?;

// Alice is in the ring -> access granted
assert!(reg.has_permission(&alice_id, &photo_id, Permission::Read)?);
// Bob is not -> access denied
assert!(!reg.has_permission(&bob_id, &photo_id, Permission::Read)?);
```

Runnable examples for each permission: [`read`](examples/read.rs) · [`write`](examples/write.rs) · [`delete`](examples/delete.rs)

```sh
cargo run --example read --features mem
```

## How it works

A **ring** is a named group of peers. Resources (identified by an arbitrary byte
sequence via the `ResourceId` trait) are associated with one or more rings together
with a set of permissions (`Read`, `Write`, `Delete`). A peer is granted a permission
only if it belongs to a ring that carries it on that resource.

One built-in ring — the **open ring** (`"open"`) — grants `Read` to any peer regardless
of membership. It is read-only and may coexist with private rings on the same resource,
enabling "publicly readable, privately writable" resources.

```
peer request (resource_id + permission)
        │
        ▼
    ┌───────┐    has_permission?   ┌──────────┐
    │ Gate  │ ───────────────────▶│ Registry │
    └───────┘                      └──────────┘
        │                               │
        │◀── DENIED ───────────────────┤ (no ring / no permission)
        │◀── ALLOWED ──────────────────┘ (peer in ring with permission)
        │
        ▼
   [ Transfer ] <- here is where your app (or sub-protocol) is attached
```

| Layer | What it does |
|---|---|
| **Registry** | Stores rings, membership, and resource-ring associations |
| **Gate** | iroh protocol handler — checks access, hands streams to a `Transfer` |
| **Transfer** | Defines what happens after access is granted (your application) |

**Invariants:**
- Implicit deny: a resource with no ring associations is always denied.
- The `"open"` ring grants `Read` to any authenticated peer; `Write` and `Delete` still require explicit ring membership.
- Permissions are additive: a peer in multiple rings holds the union of permissions across all rings.

## Threat model

iroh-rings handles **authorisation**, not authentication. Authentication is delegated
to iroh: every peer is identified by its public key, and the QUIC handshake verifies
identity before the gate runs.

**What iroh-rings enforces:**
- A peer with no matching ring membership is always denied, for every permission.
- The gate sends `DENIED` and closes the stream **before** any payload is transferred, no data leaks on a failed check.
- The `"open"` ring grants `Read` to any *authenticated* iroh peer, not to anonymous connections.

## Background

Originally, this ring-based access control library lived inside the [ringdrop](https://github.com/rikettsie/ringdrop)
program as a tightly coupled implementation.
The purpose of this extraction is to expose reusable building blocks,
to easily plug this ring-access concept into other programs.

## Installation

Specify the version and the feature list in your `Cargo.toml`:

```toml
[dependencies]
iroh-rings = { version = "*", features = ["mem"] }  # or "redb", "fs"
```

## Concepts

### Ring

A ring is a named set of peers. Names must be non-empty, whitespace-free, and
NULL-free. The reserved name `"open"` is the open ring.

### Registry

The `Registry` trait manages rings and resource-ring associations:

```rust
use iroh_rings::{InMemoryRegistry, Permission};

let reg = InMemoryRegistry::new(); // or RedbRegistry::open("rings.db")?
reg.create_ring("friends")?;
reg.add_peer_to_ring("friends", peer_id, Some("alice"))?;
reg.add_ring_to_resource(resource_id, "friends", &[Permission::Read, Permission::Write])?;

assert!(reg.has_permission(&peer_id, &resource_id, Permission::Read)?);
```

Two backends are provided behind feature flags:

- **`mem`** — `InMemoryRegistry`: in-process hash maps, useful for tests and
  ephemeral nodes only.
- **`redb`** — `RedbRegistry`: persistent on a
  [redb](https://github.com/cberner/redb) database.

You can implement `Registry` in your concrete types directly, to use any other store (SQL, etcd, etc).

### Gate

`RingGate<R, T>` is an iroh `ProtocolHandler`. Wire protocol:

```text
Initiator -> gate  [ 2 B]  u16-le: resource id length (N)
                   [ N B]  resource id bytes
                   [ 1 B]  operation: 0x01 = Read, 0x02 = Write, 0x03 = Delete
Gate -> initiator  [ 1 B]  0x00 = DENIED  /  0x01 = ALLOWED
                   [rest]  sub-protocol defined by the Transfer implementor
```

`Read`, `Write`, and `Delete` are typed labels. The gate verifies ring membership
for the requested permission and then passes the stream to the `Transfer` — it does
not enforce any specific behaviour beyond that check. What "Write" or "Delete" means
for a given resource is defined entirely by the `Transfer` implementation. The crate
only guarantees that a peer without the required permission never reaches the `Transfer`.

Wire the gate into an iroh `Router` using the provided `ALPN` (`b"/iroh-rings/2"`):

```rust
use iroh_rings::{ALPN, RingGate};

let gate = RingGate::new(registry, transfer);
let router = Router::builder(endpoint) // endpoint: iroh::Endpoint
    .accept(ALPN, gate)
    .spawn();
```

### Transfer

`Transfer` defines what happens after access is granted.
Implement it to build your own sub-protocol:

```rust
use iroh::endpoint::{RecvStream, SendStream};
use iroh::EndpointId;
use iroh_rings::Transfer;

impl Transfer for MyTransfer {
    async fn can_access(&self, peer: &EndpointId, resource_id: &[u8]) -> bool {
        // alternative authorization path — return true to allow even if
        // the peer is not a direct ring member (e.g. sub-blob of an
        // accessible collection, quota check, rate-limiting)
    }

    async fn transfer(
        &self,
        resource_id: &[u8],
        send: &mut SendStream,
        recv: &mut RecvStream,
    ) -> Result<()> {
        // your sub-protocol: read from recv, write to send
    }
}
```

### FsTransfer (feature `fs`)

`FsTransfer` is the reference `Transfer` implementation.
It streams BLAKE3-verified blobs from an iroh-blobs `FsStore` using the bao encoded format.
The sub-protocol it speaks after the gate's ALLOWED byte:

```text
Initiator -> sender [ 4 B]  u32-le: number of already-have chunk-group ranges (N)
                    [N×16B] N × (start u64-le, end u64-le) chunk-group indices
Sender -> initiator [ 8 B]  u64-le: total blob size
                    [rest]  bao-encoded stream for the missing ranges
```

It also handles the indirect case where a requested blob is a member of an
iroh-blobs `Collection` (directory) that the peer has access to.

## Feature flags

| Flag | Enables |
|---|---|
| `mem` | `InMemoryRegistry` |
| `redb` | `RedbRegistry` |
| `fs` | `FsTransfer`, `encode_ranges_wire`, `decode_ranges_wire` |

No features are enabled by default.

## Testing your Registry implementation

`registry::registry_contract` is a shared contract test you can run against
any `Registry` backend:

```rust
#[test]
fn satisfies_registry_contract() {
    registry_contract(&MyRegistry::new());
}
```

## Examples

Three self-contained examples in [`examples/`](examples/), one per permission:

| Example | What it shows |
|---|---|
| [`read.rs`](examples/read.rs) | Member receives a payload; stranger is denied |
| [`write.rs`](examples/write.rs) | Member pushes content to the node's store; stranger is denied |
| [`delete.rs`](examples/delete.rs) | Member removes the ring–resource association; stranger is denied |

```sh
cargo run --example read   --features mem
cargo run --example write  --features mem
cargo run --example delete --features mem
```

## Contributing

If you have ideas/contributions or anything is not working the way you expect, feel free to open an issue or PR.

After cloning, activate the pre-commit hooks (it runs `cargo fmt --check` and `cargo clippy` before every commit, and tag verifications before every push):

```sh
git config core.hooksPath .githooks
```

## License

MIT
