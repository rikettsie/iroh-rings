# iroh-rings

![CI](https://github.com/rikettsie/iroh-rings/actions/workflows/ci.yml/badge.svg)
[![codecov](https://codecov.io/gh/rikettsie/iroh-rings/graph/badge.svg)](https://codecov.io/gh/rikettsie/iroh-rings)
[![crates.io](https://img.shields.io/crates/v/iroh-rings.svg)](https://crates.io/crates/iroh-rings)
[![docs.rs](https://docs.rs/iroh-rings/badge.svg)](https://docs.rs/iroh-rings)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE-MIT)

Ring-based, permission-typed access control for resources over [iroh](https://github.com/n0-computer/iroh) protocols.

A **ring** is a named group of peers. Resources (identified by an arbitrary byte
sequence via the `ResourceId` trait) are associated with one or more rings together
with a set of permissions (`Read`, `Write`, `Delete`). A peer is granted a permission
only if it belongs to a ring that carries it on that resource.

One built-in ring — the **open ring** (`"open"`) — grants `Read` to any peer regardless
of membership. It is read-only and may coexist with private rings on the same resource,
enabling "publicly readable, privately writable" resources.

The crate is split into three concerns:

| Layer | What it does |
|---|---|
| **Registry** | Stores rings, membership, and resource-ring associations |
| **Gate** | iroh protocol handler — checks access, hands streams to a `Transfer` |
| **Transfer** | Defines what happens after access is granted (your sub-protocol) |

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

## Example

A self-contained end-to-end example is in [`examples/access_control.rs`](examples/access_control.rs).
It spins up one server, one authorized member, and one stranger, and shows the full
request/response cycle:

```sh
cargo run --example access_control --features mem
```

## Contributing

If you have ideas/contributions or anything is not working the way you expect, feel free to open an issue or PR.

After cloning, activate the pre-commit hooks (it runs `cargo fmt --check` and `cargo clippy` before every commit, and tag verifications before every push):

```sh
git config core.hooksPath .githooks
```

## License

MIT
