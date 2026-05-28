//! [`FsTransfer`]: a blob-transfer [`Transfer`] implementation backed by an
//! iroh-blobs [`FsStore`].
//!
//! This is the reference [`Transfer`] implementation. It shows how to:
//!
//! - implement the two-phase access check (`can_access` handles the indirect
//!   case where a blob is a member of an allowed iroh-blob's collection)
//! - read the sub-protocol header from `recv` (bao chunk-range negotiation)
//! - stream a bao-encoded response on `send`
//!
//! To implement other transfer kinds (e.g. chat, video) you can follow the
//! same pattern eventually including a specific sub-protocol in place of
//! the range negotiation used here.

use std::io;
use std::mem::size_of;

// Each range entry on the wire is two little-endian u64 values: (start, end).
const RANGE_ENTRY_BYTES: usize = 2 * size_of::<u64>();

use anyhow::{Context, Result};
use bytes::Bytes;
use futures_lite::StreamExt;
use iroh::EndpointId;
use iroh_blobs::{hashseq::HashSeq, store::fs::FsStore, BlobFormat, Hash};
use iroh_io::AsyncStreamWriter;
use tracing::instrument;

use crate::protocol::Transfer;
use crate::registry::{Permission, Registry};

/// Encode chunk-group ranges into wire bytes:
///   [u32-le count] [count × (start u64-le, end u64-le)]
pub fn encode_ranges_wire(ranges: &bao_tree::ChunkRanges) -> Vec<u8> {
    let boundaries = ranges.boundaries();
    debug_assert!(
        boundaries.len().is_multiple_of(2),
        "invariant: already-have ranges are always bounded"
    );
    // boundaries are interleaved [start, end) pairs, so range count = half the boundary count
    let pair_count = (boundaries.len() / 2) as u32;
    let mut out = Vec::with_capacity(size_of::<u32>() + pair_count as usize * RANGE_ENTRY_BYTES);
    out.extend_from_slice(&pair_count.to_le_bytes());
    let mut i = 0;
    while i + 1 < boundaries.len() {
        out.extend_from_slice(&boundaries[i].0.to_le_bytes());
        out.extend_from_slice(&boundaries[i + 1].0.to_le_bytes());
        i += 2;
    }
    out
}

/// Decode chunk-group ranges from wire bytes.
pub fn decode_ranges_wire(count: u32, raw: &[u8]) -> anyhow::Result<bao_tree::ChunkRanges> {
    use anyhow::bail;
    use bao_tree::{ChunkNum, ChunkRanges};
    let mut ranges = ChunkRanges::empty();
    for i in 0..count as usize {
        let base = i * RANGE_ENTRY_BYTES;
        if base + RANGE_ENTRY_BYTES > raw.len() {
            bail!("range data truncated at index {i}");
        }
        let start = u64::from_le_bytes(
            raw[base..base + size_of::<u64>()]
                .try_into()
                .expect("invariant: slice is exactly 8 bytes"),
        );
        let end = u64::from_le_bytes(
            raw[base + size_of::<u64>()..base + RANGE_ENTRY_BYTES]
                .try_into()
                .expect("invariant: slice is exactly 8 bytes"),
        );
        ranges |= ChunkRanges::from(ChunkNum(start)..ChunkNum(end));
    }
    Ok(ranges)
}

struct SendStreamWriter<'a>(&'a mut iroh::endpoint::SendStream);

impl AsyncStreamWriter for SendStreamWriter<'_> {
    async fn write(&mut self, data: &[u8]) -> io::Result<()> {
        Ok(self.0.write_all(data).await?)
    }

    async fn write_bytes(&mut self, data: Bytes) -> io::Result<()> {
        Ok(self.0.write_chunk(data).await?)
    }

    async fn sync(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A [`Transfer`] implementation that streams blobs from an iroh-blobs [`FsStore`].
///
/// Sub-protocol (after the gate has written the ALLOWED byte):
/// ```text
/// peer initiator -> sender  [ 4 B]  u32-le: number of already-have chunk-group ranges (N)
///                           [N×16B] N × (start u64-le, end u64-le) chunk-group indices
/// sender -> peer initiator  [ 8 B]  u64-le: total blob size
///                           [rest]  bao-encoded stream for the missing ranges
/// ```
#[derive(Clone)]
pub struct FsTransfer<R> {
    store: FsStore,
    registry: R,
}

impl<R: Registry + Clone + Send + Sync + 'static> FsTransfer<R> {
    /// Creates an `FsTransfer` backed by the given blob store and registry.
    pub fn new(store: FsStore, registry: R) -> Self {
        FsTransfer { store, registry }
    }
}

impl<R: Registry + Clone + Send + Sync + 'static> Transfer for FsTransfer<R> {
    async fn can_access(&self, peer: &EndpointId, resource_id: &[u8]) -> bool {
        if self
            .registry
            .has_permission(peer, &resource_id.to_vec(), Permission::Read)
            .unwrap_or(false)
        {
            return true;
        }
        let Ok(hash_bytes) = resource_id.try_into() else {
            return false;
        };
        self.is_member_of_allowed_collection(peer, &Hash::from_bytes(hash_bytes))
            .await
    }

    #[instrument(skip(self, send, recv), fields(resource_id = %hex::encode(resource_id)))]
    async fn transfer(
        &self,
        resource_id: &[u8],
        send: &mut iroh::endpoint::SendStream,
        recv: &mut iroh::endpoint::RecvStream,
    ) -> Result<()> {
        // Read bao chunk-range negotiation from recv.
        let mut count_buf = [0u8; 4];
        recv.read_exact(&mut count_buf)
            .await
            .context("reading range count")?;
        let range_count = u32::from_le_bytes(count_buf);

        let range_data_len = range_count as usize * RANGE_ENTRY_BYTES;
        let mut range_data = vec![0u8; range_data_len];
        if range_data_len > 0 {
            recv.read_exact(&mut range_data)
                .await
                .context("reading ranges")?;
        }

        let already_have = decode_ranges_wire(range_count, &range_data)?;
        let missing = bao_tree::ChunkRanges::all() & !already_have;

        let hash_bytes: [u8; 32] = resource_id
            .try_into()
            .context("resource_id must be 32 bytes")?;
        let hash = Hash::from_bytes(hash_bytes);
        self.store
            .blobs()
            .export_bao(hash, missing)
            .write(&mut SendStreamWriter(send))
            .await
            .context("bao streaming failed")
    }
}

impl<R: Registry + Clone + Send + Sync + 'static> FsTransfer<R> {
    /// Returns true if `hash` is referenced by any collection the peer may access.
    /// Called only when the direct registry check fails (blob is a collection member).
    async fn is_member_of_allowed_collection(&self, peer: &EndpointId, hash: &Hash) -> bool {
        let Ok(mut stream) = self.store.tags().list().await else {
            return false;
        };
        while let Some(Ok(info)) = stream.next().await {
            if info.format != BlobFormat::HashSeq {
                continue;
            }
            if !self
                .registry
                .has_permission(peer, info.hash.as_bytes(), Permission::Read)
                .unwrap_or(false)
            {
                continue;
            }
            if let Ok(bytes) = self.store.blobs().get_bytes(info.hash).await {
                if let Ok(seq) = HashSeq::try_from(bytes) {
                    if seq.into_iter().any(|h| &h == hash) {
                        return true;
                    }
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bao_tree::ChunkNum;

    fn assert_ranges_roundtrip(ranges: bao_tree::ChunkRanges) {
        let encoded = encode_ranges_wire(&ranges);
        let count = u32::from_le_bytes(encoded[..4].try_into().unwrap());
        let decoded = decode_ranges_wire(count, &encoded[4..]).unwrap();
        assert_eq!(decoded, ranges);
    }

    #[test]
    fn encode_decode_empty_ranges_succeeds() {
        let ranges = bao_tree::ChunkRanges::empty();
        let encoded = encode_ranges_wire(&ranges);
        assert_eq!(&encoded[..4], &0u32.to_le_bytes());
        let decoded = decode_ranges_wire(0, &[]).unwrap();
        assert_eq!(decoded, bao_tree::ChunkRanges::empty());
    }

    #[test]
    fn encode_decode_single_range_succeeds() {
        assert_ranges_roundtrip(bao_tree::ChunkRanges::from(ChunkNum(0)..ChunkNum(10)));
    }

    #[test]
    fn encode_decode_multiple_ranges_succeeds() {
        let r1 = bao_tree::ChunkRanges::from(ChunkNum(0)..ChunkNum(4));
        let r2 = bao_tree::ChunkRanges::from(ChunkNum(10)..ChunkNum(20));
        assert_ranges_roundtrip(r1 | r2);
    }

    #[test]
    fn decode_truncated_data_errors() {
        let result = decode_ranges_wire(1, &[0u8; 8]);
        assert!(result.is_err());
    }
}
