pub mod protocol;
pub mod registry;

#[cfg(any(feature = "mem", feature = "redb"))]
pub mod backends;

#[cfg(feature = "fs")]
pub mod transfers;

mod ring;

pub use registry::{Registry, ResourceId};
pub use ring::{Ring, OPEN_RING_NAME};

#[cfg(feature = "mem")]
pub use backends::memory::InMemoryRegistry;

#[cfg(feature = "redb")]
pub use backends::redb::RedbRegistry;

#[cfg(feature = "fs")]
pub use transfers::fs::FsTransfer;
