//! QUIC-like frames carried inside the AEAD plaintext.
//!
//! PRISM keeps the same zero-overhead semantics as the quiche path: a VPN packet
//! is the body of a STREAM frame; there is no separate VPN header. PADDING and
//! PING frames are used for morph padding and entropy regularization.

use bytes::{Bytes, BytesMut};

use crate::error::{Result, TransportError};
use crate::varint;

pub const FRAME_PADDING: u8 = 0x00;
pub const FRAME_PING: u8 = 0x01;
pub const FRAME_ACK: u8 = 0x02;
pub const FRAME_STREAM: u8 = 0x08;
pub const FRAME_FEC: u8 = 0x10;
/// Fixed-width STREAM header (PRISM_PERF); distinct type byte.
pub const FRAME_STREAM_MICRO: u8 = 0x09;

/// A decoded frame (zero-copy payload when backed by `Bytes`).
#[derive(Debug, PartialEq, Eq)]
pub enum Frame {
    Padding(usize),
    Ping,
    Ack {
        largest: u64,
        first_range: u64,
        delay_us: u64,
    },
    Stream {
        id: u64,
        offset: u64,
        fin: bool,
        data: Bytes,
    },
    Fec {
        group_id: u64,
        shard_index: u64,
        shard_total: u64,
        data: Bytes,
    },
}

/// Borrowing view for legacy iterator API.
#[derive(Debug, PartialEq, Eq)]
pub enum FrameRef<'a> {
    Padding(usize),
    Ping,
    Ack {
        largest: u64,
        first_range: u64,
        delay_us: u64,
    },
    Stream {
        id: u64,
        offset: u64,
        fin: bool,
        data: &'a [u8],
    },
    Fec {
        group_id: u64,
        shard_index: u64,
        shard_total: u64,
        data: &'a [u8],
    },
}

pub fn encode_stream(out: &mut Vec<u8>, id: u64, offset: u64, fin: bool, data: &[u8]) {
    encode_stream_with_mode(out, id, offset, fin, data, false);
}

/// STREAM frame; `micro` uses fixed 6-byte header when values fit.
pub fn encode_stream_with_mode(out: &mut Vec<u8>, id: u64, offset: u64, fin: bool, data: &[u8], micro: bool) {
    if micro && id < 256 && offset < 65536 && data.len() < 65536 {
        out.push(FRAME_STREAM_MICRO | if fin { 0x01 } else { 0x00 });
        out.push(id as u8);
        out.extend_from_slice(&(offset as u16).to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
        return;
    }
    let mut ty = FRAME_STREAM | 0b010 | 0b100;
    if fin {
        ty |= 0b001;
    }
    out.push(ty);
    varint::encode(id, out);
    varint::encode(offset, out);
    varint::encode(data.len() as u64, out);
    out.extend_from_slice(data);
}

pub fn encode_ack(out: &mut Vec<u8>, largest: u64, first_range: u64, delay_us: u64) {
    out.push(FRAME_ACK);
    varint::encode(largest, out);
    varint::encode(delay_us, out);
    varint::encode(first_range, out);
}

pub fn encode_fec(out: &mut Vec<u8>, group_id: u64, shard_index: u64, shard_total: u64, data: &[u8]) {
    out.push(FRAME_FEC);
    varint::encode(group_id, out);
    varint::encode(shard_index, out);
    varint::encode(shard_total, out);
    varint::encode(data.len() as u64, out);
    out.extend_from_slice(data);
}

pub fn encode_ping(out: &mut Vec<u8>) {
    out.push(FRAME_PING);
}

pub fn encode_padding(out: &mut Vec<u8>, n: usize) {
    out.extend(std::iter::repeat(FRAME_PADDING).take(n));
}

/// Incremental frame decoder over `BytesMut` (zero-copy via `Bytes::slice`).
pub struct FrameDecoder {
    buf: BytesMut,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self { buf: BytesMut::new() }
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: BytesMut::with_capacity(cap),
        }
    }

    pub fn feed(&mut self, chunk: Bytes) {
        self.buf.extend_from_slice(&chunk);
    }

    pub fn feed_slice(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
    }

    pub fn decode_frame(&mut self) -> Result<Option<Frame>> {
        if self.buf.is_empty() {
            return Ok(None);
        }
        let total = frame_wire_len(&self.buf)?;
        let Some(total) = total else {
            return Ok(None);
        };
        let frame_bytes = self.buf.split_to(total).freeze();
        Ok(Some(parse_frame_bytes(frame_bytes)?))
    }

    pub fn remaining(&self) -> usize {
        self.buf.len()
    }
}

impl Default for FrameDecoder {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_frame_bytes(buf: Bytes) -> Result<Frame> {
    if buf.is_empty() {
        return Err(TransportError::Malformed("empty frame".into()));
    }
    let ty = buf[0];
    if ty == FRAME_PADDING {
        let n = buf.iter().take_while(|&&b| b == FRAME_PADDING).count();
        return Ok(Frame::Padding(n));
    }
    if ty == FRAME_PING {
        return Ok(Frame::Ping);
    }
    if ty == FRAME_ACK {
        return decode_ack_bytes(buf);
    }
    if ty == FRAME_FEC {
        return decode_fec_bytes(buf);
    }
    if ty == FRAME_STREAM_MICRO || (ty & 0xFE) == FRAME_STREAM_MICRO {
        return decode_micro_stream_bytes(buf, ty);
    }
    if (FRAME_STREAM..=FRAME_STREAM | 0x07).contains(&ty) {
        return decode_stream_bytes(buf, ty);
    }
    Err(TransportError::Malformed(format!("unknown frame type 0x{ty:02x}")))
}

fn decode_ack_bytes(buf: Bytes) -> Result<Frame> {
    let mut p = 1usize;
    let (largest, n) = varint::decode(&buf[p..])?;
    p += n;
    let (delay_us, n) = varint::decode(&buf[p..])?;
    p += n;
    let (first_range, n) = varint::decode(&buf[p..])?;
    p += n;
    if p != buf.len() {
        return Err(TransportError::Malformed("ack frame trailing bytes".into()));
    }
    Ok(Frame::Ack {
        largest,
        first_range,
        delay_us,
    })
}

fn decode_fec_bytes(buf: Bytes) -> Result<Frame> {
    let mut p = 1usize;
    let (group_id, n) = varint::decode(&buf[p..])?;
    p += n;
    let (shard_index, n) = varint::decode(&buf[p..])?;
    p += n;
    let (shard_total, n) = varint::decode(&buf[p..])?;
    p += n;
    let (len, n) = varint::decode(&buf[p..])?;
    p += n;
    let len = len as usize;
    if p + len > buf.len() {
        return Err(TransportError::Malformed("fec frame length exceeds buffer".into()));
    }
    let data = buf.slice(p..p + len);
    Ok(Frame::Fec {
        group_id,
        shard_index,
        shard_total,
        data,
    })
}

fn decode_micro_stream_bytes(buf: Bytes, ty: u8) -> Result<Frame> {
    if buf.len() < 6 {
        return Err(TransportError::Malformed("micro stream truncated".into()));
    }
    let fin = ty & 0x01 != 0;
    let id = buf[1] as u64;
    let offset = u16::from_be_bytes([buf[2], buf[3]]) as u64;
    let length = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    if 6 + length > buf.len() {
        return Err(TransportError::Malformed("micro stream length".into()));
    }
    let data = buf.slice(6..6 + length);
    Ok(Frame::Stream { id, offset, fin, data })
}

fn decode_stream_bytes(buf: Bytes, ty: u8) -> Result<Frame> {
    let fin = ty & 0b001 != 0;
    let has_len = ty & 0b010 != 0;
    let has_off = ty & 0b100 != 0;
    let mut p = 1usize;
    let (id, n) = varint::decode(&buf[p..])?;
    p += n;
    let offset = if has_off {
        let (o, n) = varint::decode(&buf[p..])?;
        p += n;
        o
    } else {
        0
    };
    let length = if has_len {
        let (l, n) = varint::decode(&buf[p..])?;
        p += n;
        l as usize
    } else {
        buf.len() - p
    };
    if p + length > buf.len() {
        return Err(TransportError::Malformed("stream frame length exceeds buffer".into()));
    }
    let data = buf.slice(p..p + length);
    Ok(Frame::Stream { id, offset, fin, data })
}

/// Returns total wire length if the buffer contains a complete frame.
fn frame_wire_len(buf: &[u8]) -> Result<Option<usize>> {
    if buf.is_empty() {
        return Ok(None);
    }
    let ty = buf[0];
    if ty == FRAME_PADDING {
        let n = buf.iter().take_while(|&&b| b == FRAME_PADDING).count();
        return Ok(Some(n));
    }
    if ty == FRAME_PING {
        return Ok(Some(1));
    }
    if ty == FRAME_ACK {
        return ack_wire_len(buf);
    }
    if ty == FRAME_FEC {
        return fec_wire_len(buf);
    }
    if ty == FRAME_STREAM_MICRO || (ty & 0xFE) == FRAME_STREAM_MICRO {
        return micro_stream_wire_len(buf, ty);
    }
    if (FRAME_STREAM..=FRAME_STREAM | 0x07).contains(&ty) {
        return stream_wire_len(buf, ty);
    }
    Err(TransportError::Malformed(format!("unknown frame type 0x{ty:02x}")))
}

fn ack_wire_len(buf: &[u8]) -> Result<Option<usize>> {
    let mut p = 1usize;
    let (_, n) = varint::decode(&buf[p..])?;
    p += n;
    let (_, n) = varint::decode(&buf[p..])?;
    p += n;
    let (_, n) = varint::decode(&buf[p..])?;
    p += n;
    Ok(Some(p))
}

fn fec_wire_len(buf: &[u8]) -> Result<Option<usize>> {
    let mut p = 1usize;
    for _ in 0..3 {
        let (_, n) = varint::decode(&buf[p..])?;
        p += n;
    }
    let (len, n) = varint::decode(&buf[p..])?;
    p += n;
    let total = p + len as usize;
    if buf.len() < total {
        return Ok(None);
    }
    Ok(Some(total))
}

fn micro_stream_wire_len(buf: &[u8], _ty: u8) -> Result<Option<usize>> {
    if buf.len() < 6 {
        return Ok(None);
    }
    let length = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let total = 6 + length;
    if buf.len() < total {
        return Ok(None);
    }
    Ok(Some(total))
}

fn stream_wire_len(buf: &[u8], ty: u8) -> Result<Option<usize>> {
    if ty == FRAME_STREAM_MICRO || (ty & 0xFE) == FRAME_STREAM_MICRO {
        return micro_stream_wire_len(buf, ty);
    }
    let fin_ty = ty;
    let _ = fin_ty;
    let has_len = ty & 0b010 != 0;
    let has_off = ty & 0b100 != 0;
    let mut p = 1usize;
    let (_, n) = varint::decode(&buf[p..])?;
    p += n;
    if has_off {
        let (_, n) = varint::decode(&buf[p..])?;
        p += n;
    }
    let length = if has_len {
        let (l, n) = varint::decode(&buf[p..])?;
        p += n;
        l as usize
    } else {
        return Ok(Some(buf.len()));
    };
    let total = p + length;
    if buf.len() < total {
        return Ok(None);
    }
    Ok(Some(total))
}

/// Legacy slice iterator (borrowed payloads).
pub struct FrameReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> FrameReader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
}

impl<'a> Iterator for FrameReader<'a> {
    type Item = Result<FrameRef<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.buf.len() {
            return None;
        }
        let slice = &self.buf[self.pos..];
        let total = match frame_wire_len(slice) {
            Ok(Some(n)) => n,
            Ok(None) => return None,
            Err(e) => return Some(Err(e)),
        };
        let frame_slice = &slice[..total];
        self.pos += total;
        Some(decode_frame_ref(frame_slice))
    }
}

fn decode_frame_ref(buf: &[u8]) -> Result<FrameRef<'_>> {
    if buf.is_empty() {
        return Err(TransportError::Malformed("empty frame".into()));
    }
    let ty = buf[0];
    if ty == FRAME_PADDING {
        let n = buf.iter().take_while(|&&b| b == FRAME_PADDING).count();
        return Ok(FrameRef::Padding(n));
    }
    if ty == FRAME_PING {
        return Ok(FrameRef::Ping);
    }
    if ty == FRAME_ACK {
        let mut p = 1usize;
        let (largest, n) = varint::decode(&buf[p..])?;
        p += n;
        let (delay_us, n) = varint::decode(&buf[p..])?;
        p += n;
        let (first_range, n) = varint::decode(&buf[p..])?;
        p += n;
        if p != buf.len() {
            return Err(TransportError::Malformed("ack frame trailing bytes".into()));
        }
        return Ok(FrameRef::Ack {
            largest,
            first_range,
            delay_us,
        });
    }
    if ty == FRAME_FEC {
        let mut p = 1usize;
        let (group_id, n) = varint::decode(&buf[p..])?;
        p += n;
        let (shard_index, n) = varint::decode(&buf[p..])?;
        p += n;
        let (shard_total, n) = varint::decode(&buf[p..])?;
        p += n;
        let (len, n) = varint::decode(&buf[p..])?;
        p += n;
        let len = len as usize;
        if p + len > buf.len() {
            return Err(TransportError::Malformed("fec frame length exceeds buffer".into()));
        }
        return Ok(FrameRef::Fec {
            group_id,
            shard_index,
            shard_total,
            data: &buf[p..p + len],
        });
    }
    if ty == FRAME_STREAM_MICRO || (ty & 0xFE) == FRAME_STREAM_MICRO {
        if buf.len() < 6 {
            return Err(TransportError::Malformed("micro stream truncated".into()));
        }
        let fin = ty & 0x01 != 0;
        let id = buf[1] as u64;
        let offset = u16::from_be_bytes([buf[2], buf[3]]) as u64;
        let length = u16::from_be_bytes([buf[4], buf[5]]) as usize;
        if 6 + length > buf.len() {
            return Err(TransportError::Malformed("micro stream length".into()));
        }
        return Ok(FrameRef::Stream {
            id,
            offset,
            fin,
            data: &buf[6..6 + length],
        });
    }
    if (FRAME_STREAM..=FRAME_STREAM | 0x07).contains(&ty) {
        let fin = ty & 0b001 != 0;
        let has_len = ty & 0b010 != 0;
        let has_off = ty & 0b100 != 0;
        let mut p = 1usize;
        let (id, n) = varint::decode(&buf[p..])?;
        p += n;
        let offset = if has_off {
            let (o, n) = varint::decode(&buf[p..])?;
            p += n;
            o
        } else {
            0
        };
        let length = if has_len {
            let (l, n) = varint::decode(&buf[p..])?;
            p += n;
            l as usize
        } else {
            buf.len() - p
        };
        if p + length > buf.len() {
            return Err(TransportError::Malformed("stream frame length exceeds buffer".into()));
        }
        return Ok(FrameRef::Stream {
            id,
            offset,
            fin,
            data: &buf[p..p + length],
        });
    }
    Err(TransportError::Malformed(format!("unknown frame type 0x{ty:02x}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_round_trip() {
        let mut buf = Vec::new();
        encode_stream(&mut buf, 4, 0, false, b"hello vpn packet");
        encode_ping(&mut buf);
        encode_padding(&mut buf, 10);

        let mut dec = FrameDecoder::new();
        dec.feed_slice(&buf);
        match dec.decode_frame().unwrap().unwrap() {
            Frame::Stream { id, offset, fin, data } => {
                assert_eq!(id, 4);
                assert_eq!(offset, 0);
                assert!(!fin);
                assert_eq!(&data[..], b"hello vpn packet");
            }
            other => panic!("expected stream, got {other:?}"),
        }
        assert!(matches!(dec.decode_frame().unwrap().unwrap(), Frame::Ping));
        assert!(matches!(dec.decode_frame().unwrap().unwrap(), Frame::Padding(10)));
        assert!(dec.decode_frame().unwrap().is_none());
    }

    #[test]
    fn ack_round_trip() {
        let mut buf = Vec::new();
        encode_ack(&mut buf, 42, 5, 1000);
        let mut dec = FrameDecoder::new();
        dec.feed_slice(&buf);
        match dec.decode_frame().unwrap().unwrap() {
            Frame::Ack { largest, first_range, delay_us } => {
                assert_eq!(largest, 42);
                assert_eq!(first_range, 5);
                assert_eq!(delay_us, 1000);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn micro_header_round_trip() {
        let mut buf = Vec::new();
        encode_stream_with_mode(&mut buf, 3, 100, true, b"perf", true);
        let mut dec = FrameDecoder::new();
        dec.feed_slice(&buf);
        match dec.decode_frame().unwrap().unwrap() {
            Frame::Stream { id, offset, fin, data } => {
                assert_eq!(id, 3);
                assert_eq!(offset, 100);
                assert!(fin);
                assert_eq!(&data[..], b"perf");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn fec_round_trip() {
        let mut buf = Vec::new();
        encode_fec(&mut buf, 1, 0, 12, b"shard-data");
        let mut dec = FrameDecoder::new();
        dec.feed_slice(&buf);
        match dec.decode_frame().unwrap().unwrap() {
            Frame::Fec { group_id, shard_index, data, .. } => {
                assert_eq!(group_id, 1);
                assert_eq!(shard_index, 0);
                assert_eq!(&data[..], b"shard-data");
            }
            other => panic!("{other:?}"),
        }
    }
}
