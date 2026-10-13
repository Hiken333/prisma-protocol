//! BOLT session: seq counters + encrypt/send/recv helpers.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use futures::future::join_all;
use tracing::debug;

use crate::aggregator::PacketAggregator;
use crate::crypto::{BoltCipher, BoltDirection, CryptoError};
use crate::frame::{BoltFrame, FrameKind, WireLayout, wire_layout_from_env};
use crate::lanes::BoltLanes;
use crate::pacer::BrutalPacer;

pub struct BoltSession {
    layout: WireLayout,
    cipher: BoltCipher,
    lanes: BoltLanes,
    pacer: BrutalPacer,
    tx_seq: u32,
    agg: PacketAggregator,
    pub frames_sent: Arc<AtomicU64>,
    pub frames_recv: Arc<AtomicU64>,
    pub bytes_sent: Arc<AtomicU64>,
    pub bytes_recv: Arc<AtomicU64>,
    pub peak_mbps_bits: Arc<AtomicU64>,
}

impl BoltSession {
    pub fn new(cipher: BoltCipher, lanes: BoltLanes, pacer: BrutalPacer) -> Self {
        let layout = wire_layout_from_env();
        Self {
            agg: PacketAggregator::new(layout),
            layout,
            cipher,
            lanes,
            pacer,
            tx_seq: 0,
            frames_sent: Arc::new(AtomicU64::new(0)),
            frames_recv: Arc::new(AtomicU64::new(0)),
            bytes_sent: Arc::new(AtomicU64::new(0)),
            bytes_recv: Arc::new(AtomicU64::new(0)),
            peak_mbps_bits: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn wire_layout(&self) -> WireLayout {
        self.layout
    }

    pub fn direction(&self) -> BoltDirection {
        self.cipher.role_up()
    }

    pub fn pacer_mbps(&self) -> f64 {
        self.pacer.rate_mbps()
    }

    pub fn pacer_peak_mbps(&self) -> f64 {
        let bits = self.peak_mbps_bits.load(Ordering::Relaxed);
        if bits == 0 {
            0.0
        } else {
            f64::from_bits(bits)
        }
    }

    fn record_peak(&self) {
        let peak = self.pacer.peak_mbps();
        self.peak_mbps_bits
            .fetch_max(peak.to_bits(), Ordering::Relaxed);
    }

    pub fn pacer_turbo(&self) -> bool {
        self.pacer.is_turbo()
    }

    pub fn lanes(&self) -> &BoltLanes {
        &self.lanes
    }

    pub fn has_pending(&self) -> bool {
        !self.agg.is_empty()
    }

    pub fn needs_flush_before(&self, pkt_len: usize) -> bool {
        self.agg.would_overflow(pkt_len) && !self.agg.is_empty()
    }

    /// Queue one TUN packet; flush via [`Self::flush_burst`] when full or after a read burst.
    pub fn ingest_packet(&mut self, pkt: &[u8]) -> Result<(), CryptoError> {
        use crate::frame::FrameError;

        if pkt.len() > self.layout.max_chunk_bytes {
            return Err(CryptoError::Frame(FrameError::PlaintextTooLarge));
        }
        if self.needs_flush_before(pkt.len()) {
            return Err(CryptoError::Frame(FrameError::PlaintextTooLarge));
        }
        let _full = self.agg.push(pkt);
        Ok(())
    }

    pub async fn flush_bulk(&mut self) -> Result<(), CryptoError> {
        if self.flush_burst(1).await? == 0 {
            return Ok(());
        }
        Ok(())
    }

    /// Seal (parallel thread batch) and parallel-UDP-send up to `max_frames` bulk frames.
    pub async fn flush_burst(&mut self, max_frames: usize) -> Result<usize, CryptoError> {
        let max_frames = max_frames.max(1);
        let layout = self.layout;
        let mut specs: Vec<(u32, u8, BoltFrame)> = Vec::with_capacity(max_frames);

        while specs.len() < max_frames {
            if self.agg.is_empty() {
                break;
            }
            let chunks = self.agg.take_chunks();
            let n_chunks = chunks.len();
            let total: usize = chunks.iter().map(|c| c.len()).sum();
            let seq = self.tx_seq;
            let frame = BoltFrame::bulk(seq, chunks);
            self.tx_seq = self.tx_seq.wrapping_add(1);
            let lane = self.lanes.pick_lane() as u8;
            debug!(n_chunks, total, seq, lane, "bolt flush queue");
            specs.push((seq, lane, frame));
        }

        if specs.is_empty() {
            return Ok(0);
        }

        if !self.pacer.is_turbo() {
            self.pacer
                .await_bytes(layout.wire_size * specs.len())
                .await;
        }

        let cipher = self.cipher.clone();
        let mut sealed: Vec<(u8, Vec<u8>)> = Vec::with_capacity(specs.len());
        for (_seq, lane, frame) in &specs {
            let mut wire = vec![0u8; layout.wire_size];
            cipher.seal_frame(frame, *lane, layout, &mut wire)?;
            sealed.push((*lane, wire));
        }
        let sends: Vec<_> = sealed
            .iter()
            .map(|(lane, wire)| self.lanes.send_wire(*lane as usize, wire))
            .collect();
        let results = join_all(sends).await;

        let mut sent = 0usize;
        for (n, (_lane, wire)) in results.into_iter().zip(sealed.iter()) {
            let n = n.map_err(|_| CryptoError::Aead)?;
            if n == 0 {
                continue;
            }
            self.pacer.pulse(n);
            self.record_peak();
            self.frames_sent.fetch_add(1, Ordering::Relaxed);
            self.bytes_sent.fetch_add(wire.len() as u64, Ordering::Relaxed);
            sent += 1;
        }
        Ok(sent)
    }

    pub async fn send_keepalive(&mut self) -> Result<(), CryptoError> {
        let frame = BoltFrame::keepalive(self.tx_seq);
        self.tx_seq = self.tx_seq.wrapping_add(1);
        self.send_frame(&frame).await
    }

    async fn send_frame(&mut self, frame: &BoltFrame) -> Result<(), CryptoError> {
        let layout = self.layout;
        self.pacer.await_bytes(layout.wire_size).await;
        let lane = self.lanes.pick_lane();
        let mut wire = vec![0u8; layout.wire_size];
        self.cipher.seal_frame(frame, lane as u8, layout, &mut wire)?;
        let n = self
            .lanes
            .send_wire(lane, &wire)
            .await
            .map_err(|_| CryptoError::Aead)?;
        if n == 0 {
            return Ok(());
        }
        self.pacer.pulse(n);
        self.record_peak();
        self.frames_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
        debug!(lane, seq = frame.seq, kind = ?frame.kind, "bolt tx");
        Ok(())
    }

    pub fn open_wire(&self, wire: &[u8]) -> Result<BoltFrame, CryptoError> {
        let frame = self.cipher.open_wire(wire)?;
        self.frames_recv.fetch_add(1, Ordering::Relaxed);
        let bytes: u64 = frame.chunks.iter().map(|c| c.len() as u64).sum();
        self.bytes_recv.fetch_add(bytes, Ordering::Relaxed);
        Ok(frame)
    }

    pub fn is_keepalive(frame: &BoltFrame) -> bool {
        frame.kind == FrameKind::Keepalive
    }
}
