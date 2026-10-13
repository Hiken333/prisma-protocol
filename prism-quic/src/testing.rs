//! In-memory `QuicBackend` used by unit tests (no native QUIC build required).
//!
//! It models the parts of QUIC semantics PRISM relies on — per-stream byte
//! buffers, datagram serialization and AEAD-internal padding — without real
//! crypto. It is **not** wire-compatible and must never be used in production.

use std::collections::BTreeMap;

use crate::backend::{AckReport, QuicBackend};
use crate::error::{QuicError, Result};

#[derive(Default)]
struct StreamState {
    send_buf: Vec<u8>,
    recv_buf: Vec<u8>,
    send_fin: bool,
    recv_fin: bool,
}

/// A trivial loopback backend.
pub struct LoopbackBackend {
    streams: BTreeMap<u64, StreamState>,
    established: bool,
    closed: bool,
    morph_target: Option<usize>,
}

impl LoopbackBackend {
    pub fn new() -> Self {
        Self {
            streams: BTreeMap::new(),
            established: true,
            closed: false,
            morph_target: None,
        }
    }

    /// Move queued send-side bytes onto the recv side (simulates delivery).
    pub fn flush_streams(&mut self) {
        for st in self.streams.values_mut() {
            st.recv_buf.append(&mut st.send_buf);
            if st.send_fin {
                st.recv_fin = true;
            }
        }
    }

    fn entry(&mut self, sid: u64) -> &mut StreamState {
        self.streams.entry(sid).or_default()
    }
}

impl Default for LoopbackBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl QuicBackend for LoopbackBackend {
    fn stream_send(&mut self, stream_id: u64, data: &[u8], fin: bool) -> Result<usize> {
        let st = self.entry(stream_id);
        st.send_buf.extend_from_slice(data);
        st.send_fin |= fin;
        Ok(data.len())
    }

    fn stream_recv(&mut self, stream_id: u64, out: &mut [u8]) -> Result<(usize, bool)> {
        let st = self.entry(stream_id);
        let n = out.len().min(st.recv_buf.len());
        out[..n].copy_from_slice(&st.recv_buf[..n]);
        st.recv_buf.drain(..n);
        let fin = st.recv_fin && st.recv_buf.is_empty();
        Ok((n, fin))
    }

    fn readable(&self) -> Vec<u64> {
        self.streams
            .iter()
            .filter(|(_, s)| !s.recv_buf.is_empty() || s.recv_fin)
            .map(|(id, _)| *id)
            .collect()
    }

    fn set_morph_target(&mut self, target: usize) {
        self.morph_target = Some(target);
    }

    fn send(&mut self, out: &mut [u8]) -> Result<usize> {
        // Serialize all queued stream data into a single pseudo-datagram:
        // [1-byte fake short header][per-stream: sid(1) len(2) bytes...]
        let mut pos = 0;
        if out.is_empty() {
            return Ok(0);
        }
        out[pos] = 0x40; // fake short-header first byte
        pos += 1;
        let sids: Vec<u64> = self.streams.keys().copied().collect();
        let mut any = false;
        for sid in sids {
            let bytes = std::mem::take(&mut self.entry(sid).send_buf);
            if bytes.is_empty() {
                continue;
            }
            if pos + 3 + bytes.len() > out.len() {
                // Put it back; datagram is full.
                self.entry(sid).send_buf = bytes;
                break;
            }
            out[pos] = sid as u8;
            out[pos + 1..pos + 3].copy_from_slice(&(bytes.len() as u16).to_be_bytes());
            pos += 3;
            out[pos..pos + bytes.len()].copy_from_slice(&bytes);
            pos += bytes.len();
            any = true;
        }
        // Emulate the fork's in-AEAD PADDING: pad up to the morph target.
        let target = self.morph_target.take();
        if any {
            if let Some(target) = target {
                let target = target.min(out.len());
                if target > pos {
                    for b in &mut out[pos..target] {
                        *b = 0x00; // PADDING frame
                    }
                    pos = target;
                }
            }
            Ok(pos)
        } else {
            Ok(0)
        }
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        Ok(buf.len())
    }

    fn send_ping(&mut self) -> Result<()> {
        Ok(())
    }

    fn export_keying_material(
        &mut self,
        label: &[u8],
        _context: &[u8],
        out: &mut [u8],
    ) -> Result<()> {
        // Deterministic stand-in for tests.
        for (i, b) in out.iter_mut().enumerate() {
            *b = label.get(i % label.len().max(1)).copied().unwrap_or(0) ^ (i as u8);
        }
        Ok(())
    }

    fn take_ack_report(&mut self) -> AckReport {
        AckReport::default()
    }

    fn bytes_in_flight(&self) -> usize {
        0
    }

    fn is_established(&self) -> bool {
        self.established
    }

    fn is_closed(&self) -> bool {
        self.closed
    }

    fn close(&mut self, _app: bool, _err: u64, _reason: &[u8]) -> Result<()> {
        self.closed = true;
        Ok(())
    }
}

/// Helper used by the datagram test to assert the backend reports `Done`.
#[allow(dead_code)]
pub(crate) fn is_done(e: &QuicError) -> bool {
    matches!(e, QuicError::Done)
}
