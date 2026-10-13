//! Per-stream reassembly and send-side queues.

use std::collections::{BTreeMap, HashMap, VecDeque};

use bytes::Bytes;

use crate::error::{Result, TransportError};

/// Out-of-order receive buffer keyed by stream offset.
#[derive(Default, Debug)]
pub struct RecvReassembly {
    next_offset: u64,
    gaps: BTreeMap<u64, Bytes>,
    fin_offset: Option<u64>,
}

impl RecvReassembly {
    pub fn push(&mut self, offset: u64, data: Bytes, fin: bool) -> Vec<Bytes> {
        if data.is_empty() && !fin {
            return Vec::new();
        }
        if offset + data.len() as u64 <= self.next_offset {
            // Duplicate or stale.
            if fin {
                self.fin_offset.get_or_insert(offset);
            }
            return Vec::new();
        }
        self.gaps.insert(offset, data);
        if fin {
            self.fin_offset.get_or_insert(offset);
        }
        self.drain_in_order()
    }

    fn drain_in_order(&mut self) -> Vec<Bytes> {
        let mut out = Vec::new();
        loop {
            let Some(data) = self.gaps.remove(&self.next_offset) else {
                break;
            };
            let len = data.len() as u64;
            self.next_offset += len;
            out.push(data);
        }
        out
    }

    pub fn is_fin(&self) -> bool {
        self.fin_offset.map(|o| o <= self.next_offset).unwrap_or(false)
    }

    pub fn next_offset(&self) -> u64 {
        self.next_offset
    }
}

#[derive(Debug)]
pub struct SendChunk {
    pub offset: u64,
    pub fin: bool,
    pub data: Bytes,
}

#[derive(Debug)]
pub struct StreamState {
    pub id: u64,
    send_offset: u64,
    recv: RecvReassembly,
    send_queue: VecDeque<SendChunk>,
    read_queue: VecDeque<Bytes>,
    fin_sent: bool,
    priority: u32,
}

impl StreamState {
    pub fn new(id: u64, priority: u32) -> Self {
        Self {
            id,
            send_offset: 0,
            recv: RecvReassembly::default(),
            send_queue: VecDeque::new(),
            read_queue: VecDeque::new(),
            fin_sent: false,
            priority,
        }
    }

    pub fn queue_send(&mut self, data: Bytes, fin: bool) -> Result<u64> {
        if self.fin_sent {
            return Err(TransportError::Closed);
        }
        let offset = self.send_offset;
        self.send_offset += data.len() as u64;
        if fin {
            self.fin_sent = true;
        }
        self.send_queue.push_back(SendChunk { offset, fin, data });
        Ok(offset)
    }

    pub fn pop_send(&mut self) -> Option<SendChunk> {
        self.send_queue.pop_front()
    }

    pub fn has_pending_send(&self) -> bool {
        !self.send_queue.is_empty()
    }

    pub fn recv_push(&mut self, offset: u64, data: Bytes, fin: bool) -> Vec<Bytes> {
        let parts = self.recv.push(offset, data, fin);
        for p in &parts {
            self.read_queue.push_back(p.clone());
        }
        parts
    }

    pub fn read(&mut self, out: &mut [u8]) -> (usize, bool) {
        let Some(front) = self.read_queue.front() else {
            return (0, self.recv_fin());
        };
        let n = front.len().min(out.len());
        out[..n].copy_from_slice(&front[..n]);
        if n == front.len() {
            self.read_queue.pop_front();
        } else {
            let remainder = front.slice(n..);
            self.read_queue[0] = remainder;
        }
        (n, self.recv_fin() && self.read_queue.is_empty())
    }

    pub fn has_readable(&self) -> bool {
        !self.read_queue.is_empty()
    }

    pub fn recv_fin(&self) -> bool {
        self.recv.is_fin()
    }

    pub fn recv_next_offset(&self) -> u64 {
        self.recv.next_offset()
    }

    pub fn priority(&self) -> u32 {
        self.priority
    }
}

/// All streams on one connection.
#[derive(Debug)]
pub struct StreamMap {
    streams: HashMap<u64, StreamState>,
    max_streams: u64,
    default_priority: u32,
}

impl StreamMap {
    pub fn new(max_streams: u64) -> Self {
        Self {
            streams: HashMap::new(),
            max_streams,
            default_priority: 1,
        }
    }

    pub fn open(&mut self, id: u64) -> Result<&mut StreamState> {
        if self.streams.len() as u64 >= self.max_streams && !self.streams.contains_key(&id) {
            return Err(TransportError::Malformed("max streams exceeded".into()));
        }
        Ok(self.streams.entry(id).or_insert_with(|| StreamState::new(id, self.default_priority)))
    }

    pub fn get_mut(&mut self, id: u64) -> Option<&mut StreamState> {
        self.streams.get_mut(&id)
    }

    pub fn get_or_open(&mut self, id: u64) -> Result<&mut StreamState> {
        self.open(id)
    }

    pub fn ids_with_pending_send(&self) -> Vec<u64> {
        self.streams
            .iter()
            .filter(|(_, s)| s.has_pending_send())
            .map(|(id, _)| *id)
            .collect()
    }

    pub fn readable_ids(&self) -> Vec<u64> {
        self.streams
            .iter()
            .filter(|(_, s)| s.has_readable())
            .map(|(id, _)| *id)
            .collect()
    }

    pub fn read_stream(&mut self, id: u64, out: &mut [u8]) -> Result<(usize, bool)> {
        let st = self.streams.get_mut(&id).ok_or_else(|| {
            crate::error::TransportError::Malformed(format!("unknown stream {id}"))
        })?;
        Ok(st.read(out))
    }

    pub fn set_priority(&mut self, id: u64, priority: u32) -> Result<()> {
        let st = self.open(id)?;
        st.priority = priority;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reassembly_in_order() {
        let mut r = RecvReassembly::default();
        let a = r.push(0, Bytes::from_static(b"hel"), false);
        assert_eq!(a.len(), 1);
        assert_eq!(&a[0][..], b"hel");
        let b = r.push(3, Bytes::from_static(b"lo"), true);
        assert_eq!(b.len(), 1);
        assert!(r.is_fin());
    }

    #[test]
    fn reassembly_out_of_order() {
        let mut r = RecvReassembly::default();
        assert!(r.push(3, Bytes::from_static(b"lo"), false).is_empty());
        let a = r.push(0, Bytes::from_static(b"hel"), true);
        assert_eq!(a.len(), 2);
    }
}
