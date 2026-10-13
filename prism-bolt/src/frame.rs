//! Fixed-size BOLT wire frames with batched IP packet payloads.

use thiserror::Error;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const MAGIC: [u8; 2] = *b"B1";

/// Legacy default; perf sessions use [`wire_layout_from_env`].
pub const WIRE_SIZE: usize = 4096;
pub const WIRE_SIZE_MAX: usize = 16384;

pub const HEADER_LEN: usize = 8; // magic(2) + flags(1) + seq(4) + n_chunks(1)

/// Max plaintext buffer for stack arrays (largest supported wire size).
pub const MAX_PLAINTEXT_CAP: usize = WIRE_SIZE_MAX - NONCE_LEN - TAG_LEN;

/// Derived sizes for one on-wire frame length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireLayout {
    pub wire_size: usize,
    pub max_plaintext: usize,
    pub max_chunk_bytes: usize,
    pub max_frame_chunk_bytes: usize,
}

impl WireLayout {
    pub fn new(wire_size: usize) -> Result<Self, FrameError> {
        if !(4096..=WIRE_SIZE_MAX).contains(&wire_size) || !wire_size.is_power_of_two() {
            return Err(FrameError::BadWireSize(wire_size));
        }
        let max_plaintext = wire_size - NONCE_LEN - TAG_LEN;
        Ok(Self {
            wire_size,
            max_plaintext,
            max_chunk_bytes: max_plaintext - HEADER_LEN - 2,
            max_frame_chunk_bytes: max_plaintext - HEADER_LEN - 2,
        })
    }

    pub fn tag_len(&self) -> usize {
        TAG_LEN
    }

    pub fn ciphertext_len(&self) -> usize {
        self.max_plaintext + TAG_LEN
    }
}

pub fn wire_layout_from_env() -> WireLayout {
    if let Ok(raw) = std::env::var("PRISM_BOLT_WIRE_SIZE") {
        if let Ok(n) = raw.parse::<usize>() {
            if let Ok(layout) = WireLayout::new(n) {
                return layout;
            }
        }
    }
    WireLayout::new(WIRE_SIZE).expect("4096")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameKind {
    Bulk,
    Keepalive,
}

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("wire size {0}, unsupported")]
    BadWireSize(usize),
    #[error("bad magic")]
    BadMagic,
    #[error("plaintext too large")]
    PlaintextTooLarge,
    #[error("chunk parse error")]
    BadChunks,
}

/// One BOLT frame (plaintext view before AEAD).
pub struct BoltFrame {
    pub kind: FrameKind,
    pub seq: u32,
    pub chunks: Vec<Vec<u8>>,
}

impl BoltFrame {
    pub fn keepalive(seq: u32) -> Self {
        Self {
            kind: FrameKind::Keepalive,
            seq,
            chunks: Vec::new(),
        }
    }

    pub fn bulk(seq: u32, chunks: Vec<Vec<u8>>) -> Self {
        Self {
            kind: FrameKind::Bulk,
            seq,
            chunks,
        }
    }

    pub fn encode_plaintext(&self, layout: WireLayout, out: &mut [u8]) -> Result<usize, FrameError> {
        if out.len() < layout.max_plaintext {
            return Err(FrameError::PlaintextTooLarge);
        }
        out[0..2].copy_from_slice(&MAGIC);
        out[2] = match self.kind {
            FrameKind::Bulk => 0x01,
            FrameKind::Keepalive => 0x02,
        };
        out[3..7].copy_from_slice(&self.seq.to_be_bytes());
        out[7] = self.chunks.len().min(255) as u8;
        let mut off = HEADER_LEN;
        for ch in &self.chunks {
            let len = ch.len();
            if len > u16::MAX as usize || off + 2 + len > layout.max_plaintext {
                return Err(FrameError::PlaintextTooLarge);
            }
            out[off..off + 2].copy_from_slice(&(len as u16).to_be_bytes());
            off += 2;
            out[off..off + len].copy_from_slice(ch);
            off += len;
        }
        if off > layout.max_plaintext {
            return Err(FrameError::PlaintextTooLarge);
        }
        out[off..layout.max_plaintext].fill(0);
        Ok(layout.max_plaintext)
    }

    pub fn decode_plaintext(layout: WireLayout, buf: &[u8]) -> Result<Self, FrameError> {
        if buf.len() < HEADER_LEN {
            return Err(FrameError::BadChunks);
        }
        if buf[0..2] != MAGIC {
            return Err(FrameError::BadMagic);
        }
        let kind = match buf[2] {
            0x01 => FrameKind::Bulk,
            0x02 => FrameKind::Keepalive,
            _ => return Err(FrameError::BadMagic),
        };
        let seq = u32::from_be_bytes(buf[3..7].try_into().unwrap());
        let n = buf[7] as usize;
        let mut chunks = Vec::with_capacity(n);
        let mut off = HEADER_LEN;
        for _ in 0..n {
            if off + 2 > buf.len() {
                return Err(FrameError::BadChunks);
            }
            let len = u16::from_be_bytes(buf[off..off + 2].try_into().unwrap()) as usize;
            off += 2;
            if off + len > buf.len() {
                return Err(FrameError::BadChunks);
            }
            chunks.push(buf[off..off + len].to_vec());
            off += len;
        }
        let _ = layout;
        Ok(Self { kind, seq, chunks })
    }

    pub fn nonce_prefix(seq: u32, lane: u8, dir: u8) -> [u8; NONCE_LEN] {
        let mut n = [0u8; NONCE_LEN];
        n[0..4].copy_from_slice(&seq.to_be_bytes());
        n[4] = lane;
        n[5] = dir;
        n
    }

    pub fn wire_nonce(layout: WireLayout, buf: &[u8]) -> Result<&[u8; NONCE_LEN], FrameError> {
        if buf.len() != layout.wire_size {
            return Err(FrameError::BadWireSize(buf.len()));
        }
        Ok(buf[0..NONCE_LEN].try_into().unwrap())
    }

    pub fn wire_ciphertext(layout: WireLayout, buf: &[u8]) -> Result<&[u8], FrameError> {
        if buf.len() != layout.wire_size {
            return Err(FrameError::BadWireSize(buf.len()));
        }
        Ok(&buf[NONCE_LEN..])
    }

    pub fn assemble_wire(
        layout: WireLayout,
        nonce: &[u8; NONCE_LEN],
        ct: &[u8],
        out: &mut [u8],
    ) -> Result<(), FrameError> {
        if out.len() != layout.wire_size || ct.len() != layout.ciphertext_len() {
            return Err(FrameError::BadWireSize(out.len()));
        }
        out[0..NONCE_LEN].copy_from_slice(nonce);
        out[NONCE_LEN..].copy_from_slice(ct);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_bulk() {
        let layout = WireLayout::new(WIRE_SIZE).unwrap();
        let f = BoltFrame::bulk(42, vec![vec![1, 2, 3], vec![4; 100]]);
        let mut pt = [0u8; MAX_PLAINTEXT_CAP];
        let n = f.encode_plaintext(layout, &mut pt).unwrap();
        assert_eq!(n, layout.max_plaintext);
        let g = BoltFrame::decode_plaintext(layout, &pt).unwrap();
        assert_eq!(g.seq, 42);
        assert_eq!(g.chunks.len(), 2);
        assert_eq!(g.chunks[0], vec![1, 2, 3]);
    }

    #[test]
    fn perf_wire_layout_fits_three_mtu() {
        let layout = WireLayout::new(WIRE_SIZE_MAX).unwrap();
        let mut a = crate::aggregator::PacketAggregator::new(layout);
        let pkt = vec![0u8; 1280];
        for _ in 0..3 {
            assert!(!a.would_overflow(pkt.len()));
            assert!(!a.push(&pkt));
        }
    }
}
