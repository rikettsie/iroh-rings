# iroh-rings

![CI](https://github.com/rikettsie/iroh-rings/actions/workflows/ci.yml/badge.svg)
[![crates.io](https://img.shields.io/crates/v/iroh-rings.svg)](https://crates.io/crates/iroh-rings)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE-MIT)

Ring-based access control for resources over [iroh](https://github.com/n0-computer/iroh) protocols.

A **ring** is a named group of peers. Resources (identified by an arbitrary byte
sequence via the `ResourceId` trait) are associated with one or more rings; a peer
is granted access only if it belongs to at least one of those rings. One
built-in ring — the **open ring** (`"open"`) — grants access to any peer unconditionally.

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
let reg = InMemoryRegistry::new(); // or RedbRegistry::open("rings.db")?
reg.create_ring("friends")?;
reg.add_peer_to_ring("friends", peer_id, Some("alice"))?;
reg.add_ring_to_resource(resource_id, "friends")?;

assert!(reg.is_allowed(&peer_id, &resource_id)?);
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
Initiator -> gate  [32 B]  resource id
Gate -> initiator  [ 1 B]  0x00 = DENIED  /  0x01 = ALLOWED
                   [rest]  sub-protocol defined by the Transfer implementor
```

Wire the gate into an iroh `Router` using the provided `SC_ALPN` (`b"/iroh-rings/0"`):

```rust
let gate = RingGate::new(registry, transfer);
let router = Router::builder(endpoint) // endpoint: iroh::Endpoint
    .accept(SC_ALPN, gate)
    .spawn();
```

### Transfer

`Transfer` defines what happens after access is granted.
Implement it to build your own sub-protocol:

```rust
impl Transfer for MyTransfer {
    async fn can_access(&self, peer: &EndpointId, resource_id: &[u8]) -> bool {
        // secondary access check (e.g. collection membership)
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

## Contributing

After cloning, activate the pre-commit hooks (it runs `cargo fmt --check` and `cargo clippy` before every commit, and tag verifications before every push):

```sh
git config core.hooksPath .githooks
```

## License

MIT
