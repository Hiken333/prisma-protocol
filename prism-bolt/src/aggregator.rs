//! Batch TUN IP packets into one BOLT bulk frame (fits MAX_PLAINTEXT).

use crate::frame::{WireLayout, HEADER_LEN};

/// Max IP packets per bulk frame (perf: more small-packet batching).
pub const MAX_CHUNKS: usize = 32;

pub struct PacketAggregator {
    layout: WireLayout,
    chunks: Vec<Vec<u8>>,
    bytes: usize,
}

impl PacketAggregator {
    pub fn new(layout: WireLayout) -> Self {
        Self {
            layout,
            chunks: Vec::with_capacity(MAX_CHUNKS),
            bytes: 0,
        }
    }

    pub fn layout(&self) -> WireLayout {
        self.layout
    }

    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    fn encoded_len_after(&self, pkt_len: usize) -> usize {
        let n = self.chunks.len() + 1;
        HEADER_LEN + n * 2 + self.bytes + pkt_len
    }

    pub fn would_overflow(&self, pkt_len: usize) -> bool {
        pkt_len > self.layout.max_chunk_bytes
            || self.chunks.len() >= MAX_CHUNKS
            || self.encoded_len_after(pkt_len) > self.layout.max_plaintext
    }

    /// Push one IP packet; returns `true` when the aggregator is full and should flush.
    pub fn push(&mut self, pkt: &[u8]) -> bool {
        if self.would_overflow(pkt.len()) {
            return true;
        }
        self.bytes += pkt.len();
        self.chunks.push(pkt.to_vec());
        self.chunks.len() >= MAX_CHUNKS
            || self.encoded_len_after(0) >= self.layout.max_plaintext
    }

    pub fn take_chunks(&mut self) -> Vec<Vec<u8>> {
        self.bytes = 0;
        std::mem::take(&mut self.chunks)
    }
}

impl Default for PacketAggregator {
    fn default() -> Self {
        Self::new(WireLayout::new(crate::frame::WIRE_SIZE).expect("4096"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::WIRE_SIZE;

    #[test]
    fn fits_mtu_1280_single() {
        let layout = WireLayout::new(WIRE_SIZE).unwrap();
        let mut a = PacketAggregator::new(layout);
        let pkt = vec![0u8; 1280];
        assert!(!a.would_overflow(pkt.len()));
        assert!(!a.push(&pkt));
    }
}
