//! Connection state: crypto, reliability, streams, FEC and scheduling.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use bytes::Bytes;
use prism_cc::{BbrPrism, CcGate};
use prism_core::config::FecMode;
use prism_fec::{FecGroupAssembler, DEFAULT_K, DEFAULT_M};
use prism_morph::{CdnProfile, EntropyRegulator, MorphEngine};

use crate::crypto::SessionKeys;
use crate::error::{Result, TransportError};
use crate::frame::{self, Frame, FrameDecoder};
use crate::reliability::{ReliabilityState, SentEntry};
use crate::scheduler::SendScheduler;
use crate::stream::StreamMap;
use crate::wire::{self, SHORT_HEADER_LEN};

const TAG_LEN: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Client,
    Server,
}

/// A decoded inbound stream chunk (zero-copy payload).
#[derive(Clone, Debug)]
pub struct StreamChunk {
    pub stream_id: u64,
    pub offset: u64,
    pub fin: bool,
    pub data: Bytes,
}

/// Full connection state for the native UDP transport.
pub struct ConnectionState {
    keys: SessionKeys,
    send_morph: MorphEngine,
    gate: CcGate,
    entropy: EntropyRegulator,
    send_pn: AtomicU64,
    mtu: usize,
    perf_mode: bool,
    reliability: ReliabilityState,
    streams: StreamMap,
    scheduler: SendScheduler,
    fec_mode: FecMode,
    fec_enabled: bool,
    fec_assemblers: HashMap<u64, FecGroupAssembler>,
    fec_group_id: u64,
    fec_recovered: Vec<Vec<u8>>,
    side: Side,
}

impl ConnectionState {
    pub fn new(
        keys: SessionKeys,
        side: Side,
        profile: CdnProfile,
        jitter_pct: f64,
        mtu: usize,
    ) -> Result<Self> {
        Self::with_options(keys, side, profile, jitter_pct, mtu, false, FecMode::Auto)
    }

    pub fn with_options(
        keys: SessionKeys,
        side: Side,
        profile: CdnProfile,
        jitter_pct: f64,
        mtu: usize,
        perf_mode: bool,
        fec_mode: FecMode,
    ) -> Result<Self> {
        let send_seed = match side {
            Side::Client => keys.exporter.morph_up_seed()?,
            Side::Server => keys.exporter.morph_dn_seed()?,
        };
        let bbr = BbrPrism::from_seed(keys.exporter.bbr_seed()?);
        Ok(Self {
            send_morph: MorphEngine::from_seed(send_seed, profile, jitter_pct, mtu),
            gate: CcGate::new(Box::new(bbr)),
            entropy: EntropyRegulator::with_default_period(),
            keys,
            send_pn: AtomicU64::new(1),
            mtu,
            perf_mode,
            reliability: ReliabilityState::default(),
            streams: StreamMap::new(256),
            scheduler: SendScheduler::new(),
            fec_mode,
            fec_enabled: fec_mode == FecMode::On,
            fec_assemblers: HashMap::new(),
            fec_group_id: 0,
            fec_recovered: Vec::new(),
            side,
        })
    }

    pub fn gate(&self) -> &CcGate {
        &self.gate
    }

    pub fn perf_mode(&self) -> bool {
        self.perf_mode
    }

    pub fn set_stream_priority(&mut self, stream_id: u64, priority: u32) -> Result<()> {
        self.streams.set_priority(stream_id, priority)
    }

    /// Queue payload on a stream for the send scheduler.
    pub fn queue_send(&mut self, stream_id: u64, payload: Bytes, fin: bool) -> Result<()> {
        let st = self.streams.open(stream_id)?;
        st.queue_send(payload, fin)?;
        Ok(())
    }

    /// Build the next datagram from scheduler + pending ACK/retransmit.
    pub fn build_datagram(&mut self) -> Result<Option<Vec<u8>>> {
        let now = Instant::now();

        // Retransmit first if needed.
        let lost = self.reliability.detect_loss_for_retransmit(now);
        if let Some(pn) = lost.first().copied() {
            if let Some(wire) = self.reliability.retransmits(&[pn]).into_iter().next() {
                return Ok(Some(wire));
            }
        }

        let mut frames = Vec::new();

        if let Some(ack) = self.reliability.take_ack_frame() {
            frames.extend_from_slice(&ack);
        }

        let candidates: Vec<(u64, u32)> = self
            .streams
            .ids_with_pending_send()
            .into_iter()
            .filter_map(|id| self.streams.get_mut(id).map(|s| (id, s.priority())))
            .collect();

        if let Some(sid) = self.scheduler.pick(&candidates) {
            if let Some(st) = self.streams.get_mut(sid) {
                if let Some(chunk) = st.pop_send() {
                    if self.perf_mode {
                        frame::encode_stream_with_mode(
                            &mut frames,
                            sid,
                            chunk.offset,
                            chunk.fin,
                            &chunk.data,
                            true,
                        );
                    } else {
                        frame::encode_stream(&mut frames, sid, chunk.offset, chunk.fin, &chunk.data);
                    }
                }
            }
        }

        if frames.is_empty() {
            return Ok(None);
        }

        self.seal_frames(frames, true)
    }

    fn seal_frames(&mut self, mut frames: Vec<u8>, ack_eliciting: bool) -> Result<Option<Vec<u8>>> {
        if !self.perf_mode {
            let overhead = SHORT_HEADER_LEN + TAG_LEN;
            let current_dgram = overhead + frames.len();
            let target = self.send_morph.target_size(current_dgram).min(self.mtu);
            if target > current_dgram {
                frame::encode_padding(&mut frames, target - current_dgram);
            }
            if self.entropy.should_inject(frames.len()) {
                frame::encode_ping(&mut frames);
            }
        }

        let pn = self.send_pn.fetch_add(1, Ordering::Relaxed);
        let ciphertext = self.keys.seal(pn, &frames)?;
        let mut out = vec![0u8; SHORT_HEADER_LEN + ciphertext.len()];
        let off = wire::write_short_header(&mut out, pn);
        out[off..].copy_from_slice(&ciphertext);

        let now = Instant::now();
        self.reliability.on_sent(SentEntry {
            pn,
            bytes: out.len(),
            wire: out.clone(),
            sent_at: now,
            ack_eliciting,
        });

        Ok(Some(out))
    }

    /// Seal pre-encoded frame bytes (legacy API).
    pub fn seal_datagram(&mut self, frames: Vec<u8>) -> Result<Vec<u8>> {
        self.seal_frames(frames, true)?.ok_or(TransportError::Malformed("empty datagram".into()))
    }

    /// Open inbound datagram; returns stream chunks and drives ACK/CC.
    pub async fn open_datagram(&mut self, datagram: &[u8]) -> Result<Vec<StreamChunk>> {
        let (pn, ciphertext) = wire::read_short_header(datagram)?;
        self.reliability.on_pn_received(pn);

        let plaintext = Bytes::from(self.keys.open(pn, ciphertext)?);
        let mut decoder = FrameDecoder::with_capacity(plaintext.len());
        decoder.feed(plaintext);

        let mut chunks = Vec::new();
        let now = Instant::now();
        let mut acked_for_gate = Vec::new();
        let mut lost_for_gate = Vec::new();

        while let Some(frame) = decoder.decode_frame()? {
            match frame {
                Frame::Stream { id, offset, fin, data } => {
                    let st = self.streams.get_or_open(id)?;
                    for part in st.recv_push(offset, data, fin) {
                        let part_len = part.len() as u64;
                        let off = st.recv_next_offset() - part_len;
                        chunks.push(StreamChunk {
                            stream_id: id,
                            offset: off,
                            fin: fin && st.recv_fin(),
                            data: part,
                        });
                    }
                }
                Frame::Ack { largest, first_range, .. } => {
                    let first_pn = largest.saturating_sub(first_range.saturating_sub(1));
                    for ack_pn in first_pn..=largest {
                        if let Some(entry) = self.reliability.sent_entry(ack_pn) {
                            acked_for_gate.push((ack_pn, entry.bytes, entry.sent_at));
                        }
                    }
                    let lost = self
                        .reliability
                        .process_ack_loss_only(largest, first_range, now);
                    for lp in &lost {
                        if let Some(entry) = self.reliability.sent_entry(*lp) {
                            lost_for_gate.push((*lp, entry.bytes));
                        }
                    }
                }
                Frame::Fec {
                    group_id,
                    shard_index,
                    shard_total,
                    data,
                } => {
                    self.handle_fec_shard(group_id, shard_index, shard_total, data);
                }
                Frame::Ping | Frame::Padding(_) => {}
            }
        }

        if !acked_for_gate.is_empty() || !lost_for_gate.is_empty() {
            crate::reliability::ReliabilityState::notify_ack(
                &self.gate,
                &acked_for_gate,
                &lost_for_gate,
                now,
            )
            .await;
        }

        // Auto-enable FEC when loss is high.
        if self.fec_mode == FecMode::Auto {
            let loss = self.reliability.loss_rate();
            self.fec_enabled = loss > 0.05;
        }

        Ok(chunks)
    }

    /// Encode pending data as FEC shards on stream 2 when enabled.
    pub fn maybe_emit_fec(&mut self, payload: &[u8]) -> Result<Vec<Vec<u8>>> {
        if !self.fec_enabled || payload.is_empty() {
            return Ok(Vec::new());
        }
        let shard_size = (payload.len() / DEFAULT_K).max(64);
        let mut data_shards: Vec<Vec<u8>> = payload
            .chunks(shard_size)
            .map(|c| {
                let mut v = c.to_vec();
                v.resize(shard_size, 0);
                v
            })
            .collect();
        while data_shards.len() < DEFAULT_K {
            data_shards.push(vec![0u8; shard_size]);
        }
        data_shards.truncate(DEFAULT_K);
        let block = prism_fec::FecBlock::encode(data_shards).map_err(|_| TransportError::Malformed("fec".into()))?;
        let gid = self.fec_group_id;
        self.fec_group_id += 1;
        let mut out = Vec::new();
        for i in 0..block.total_shards() {
            let mut frame = Vec::new();
            frame::encode_fec(
                &mut frame,
                gid,
                i as u64,
                block.total_shards() as u64,
                block.shard(i).map_err(|_| TransportError::Malformed("fec shard".into()))?,
            );
            out.push(frame);
        }
        Ok(out)
    }

    fn handle_fec_shard(&mut self, group_id: u64, shard_index: u64, shard_total: u64, data: Bytes) {
        let k = DEFAULT_K;
        let m = if shard_total as usize >= k {
            shard_total as usize - k
        } else {
            DEFAULT_M
        };
        let asm = self
            .fec_assemblers
            .entry(group_id)
            .or_insert_with(|| FecGroupAssembler::new(k, m));
        let _ = asm.insert_shard(shard_index as usize, data.to_vec());
        if asm.ready_to_decode() {
            if let Ok(Some(recovered)) = asm.try_reconstruct() {
                tracing::debug!(group_id, bytes = recovered.len(), "FEC block recovered");
                self.fec_recovered.push(recovered);
            }
        }
    }

    /// Number of sent datagrams still awaiting ACK.
    pub fn unacked_packet_count(&self) -> usize {
        self.reliability.unacked_count()
    }

    /// Payloads recovered from inbound FEC shards (stream 2 semantics).
    pub fn drain_fec_recovered(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.fec_recovered)
    }

    pub fn encode_stream(stream_id: u64, offset: u64, fin: bool, payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(payload.len() + 16);
        frame::encode_stream(&mut buf, stream_id, offset, fin, payload);
        buf
    }

    pub async fn pace(&self, bytes: usize) {
        self.gate.acquire(bytes).await;
    }

    pub fn delay(&mut self) -> std::time::Duration {
        if self.perf_mode {
            std::time::Duration::ZERO
        } else {
            self.send_morph.delay()
        }
    }

    pub fn side(&self) -> Side {
        self.side
    }

    pub fn streams_mut(&mut self) -> &mut StreamMap {
        &mut self.streams
    }

    pub fn read_stream(&mut self, stream_id: u64, out: &mut [u8]) -> Result<(usize, bool)> {
        self.streams.read_stream(stream_id, out)
    }

    pub fn readable_stream_ids(&self) -> Vec<u64> {
        self.streams.readable_ids()
    }
}

/// Legacy alias.
pub type Connection = ConnectionState;

pub fn looks_like_data(datagram: &[u8]) -> bool {
    wire::is_short(datagram) && datagram.len() > SHORT_HEADER_LEN + TAG_LEN
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SessionKeys;
    use prism_core::config::FecMode;
    use prism_core::crypto::X25519Secret;

    fn pair() -> (ConnectionState, ConnectionState) {
        let server_sk = X25519Secret::generate();
        let client_sk = X25519Secret::generate();
        let c_shared = client_sk.diffie_hellman(&server_sk.public());
        let s_shared = server_sk.diffie_hellman(&client_sk.public());
        let ck = SessionKeys::derive(&c_shared, true).unwrap();
        let sk = SessionKeys::derive(&s_shared, false).unwrap();
        let prof = CdnProfile::synthetic_chrome();
        (
            ConnectionState::new(ck, Side::Client, prof.clone(), 0.1, 1400).unwrap(),
            ConnectionState::new(sk, Side::Server, prof, 0.1, 1400).unwrap(),
        )
    }

    #[tokio::test]
    async fn datagram_round_trips_over_aead() {
        let (mut client, mut server) = pair();
        let frames = ConnectionState::encode_stream(4, 0, true, b"hello over real wire");
        let dgram = client.seal_datagram(frames).unwrap();
        assert!(looks_like_data(&dgram));

        let chunks = server.open_datagram(&dgram).await.unwrap();
        assert!(!chunks.is_empty());
        assert_eq!(chunks[0].stream_id, 4);
        assert_eq!(&chunks[0].data[..], b"hello over real wire");
    }

    #[test]
    fn datagram_is_morph_padded_in_stealth() {
        let (mut client, _server) = pair();
        let frames = ConnectionState::encode_stream(0, 0, false, b"x");
        let dgram = client.seal_datagram(frames).unwrap();
        assert!(dgram.len() >= 200, "expected morph padding, got {}", dgram.len());
    }

    fn pair_fec_on() -> (ConnectionState, ConnectionState) {
        let server_sk = X25519Secret::generate();
        let client_sk = X25519Secret::generate();
        let c_shared = client_sk.diffie_hellman(&server_sk.public());
        let s_shared = server_sk.diffie_hellman(&client_sk.public());
        let ck = SessionKeys::derive(&c_shared, true).unwrap();
        let sk = SessionKeys::derive(&s_shared, false).unwrap();
        let prof = CdnProfile::synthetic_chrome();
        (
            ConnectionState::with_options(ck, Side::Client, prof.clone(), 0.1, 1400, true, FecMode::On).unwrap(),
            ConnectionState::with_options(sk, Side::Server, prof, 0.1, 1400, true, FecMode::On).unwrap(),
        )
    }

    #[tokio::test]
    async fn ack_clears_unacked_sender_state() {
        let (mut client, mut server) = pair();
        let frames = ConnectionState::encode_stream(0, 0, true, b"ack-me");
        let dgram = client.seal_datagram(frames).unwrap();
        assert_eq!(client.unacked_packet_count(), 1);

        server.open_datagram(&dgram).await.unwrap();
        let ack = server.build_datagram().unwrap().expect("ACK datagram");
        client.open_datagram(&ack).await.unwrap();
        assert_eq!(client.unacked_packet_count(), 0);
    }

    #[tokio::test]
    async fn rto_retransmits_original_wire() {
        let (mut client, _server) = pair();
        let frames = ConnectionState::encode_stream(0, 0, false, b"retry-me");
        let original = client.seal_datagram(frames).unwrap();
        assert_eq!(client.unacked_packet_count(), 1);

        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        let retrans = client.build_datagram().unwrap().expect("RTO retransmit");
        assert_eq!(retrans, original);
    }

    #[tokio::test]
    async fn fec_recovers_after_two_data_shard_losses() {
        let (mut sender, mut receiver) = pair_fec_on();
        let mut payload = vec![0u8; 640];
        payload[..8].copy_from_slice(b"fecdata!");

        let fec_frames = sender.maybe_emit_fec(&payload).unwrap();
        assert_eq!(fec_frames.len(), 12);

        for (i, ff) in fec_frames.iter().enumerate() {
            if i == 0 || i == 1 {
                continue;
            }
            let dgram = sender.seal_datagram(ff.clone()).unwrap();
            receiver.open_datagram(&dgram).await.unwrap();
        }

        let recovered = receiver.drain_fec_recovered();
        assert_eq!(recovered.len(), 1);
        assert_eq!(&recovered[0][..8], b"fecdata!");
    }
}
