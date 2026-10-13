//! Mirror-Cell Carrying (MCC) encoder/decoder — zero VPN-header overhead.
//!
//! A VPN packet (e.g. an IP datagram from the TUN device) is carried *directly*
//! as the body of a QUIC STREAM frame. The VPN metadata is encoded entirely in
//! QUIC fields: `stream_id`, `offset`, `length`, `fin`. There is no `vpn_type`,
//! `vpn_length` or `vpn_checksum` — see spec §5.1.

use crate::backend::QuicBackend;
use crate::error::{QuicError, Result};

/// A single mirror cell: a slice of VPN payload bound to a stream position.
///
/// `payload` borrows directly from the TUN read buffer (zero-copy).
#[derive(Debug)]
pub struct Cell<'a> {
    pub stream_id: u64,
    pub payload: &'a [u8],
    pub fin: bool,
}

impl<'a> Cell<'a> {
    pub fn new(stream_id: u64, payload: &'a [u8], fin: bool) -> Self {
        Self {
            stream_id,
            payload,
            fin,
        }
    }
}

/// Writes mirror cells into a QUIC backend as STREAM frames.
pub struct MccEncoder<'b, B: QuicBackend + ?Sized> {
    backend: &'b mut B,
}

impl<'b, B: QuicBackend + ?Sized> MccEncoder<'b, B> {
    pub fn new(backend: &'b mut B) -> Self {
        Self { backend }
    }

    /// Encode one cell. Returns the number of payload bytes accepted (may be
    /// less than `cell.payload.len()` if the stream is flow-control blocked, in
    /// which case the caller must retry the remainder at the new offset).
    pub fn write_cell(&mut self, cell: &Cell<'_>) -> Result<usize> {
        match self
            .backend
            .stream_send(cell.stream_id, cell.payload, cell.fin)
        {
            Ok(n) => Ok(n),
            Err(QuicError::StreamBlocked(_)) => Ok(0),
            Err(e) => Err(e),
        }
    }

    /// Encode an IP packet on its mapped stream, looping until the whole packet
    /// is accepted or the stream blocks. Returns total bytes written.
    pub fn write_ip_packet(&mut self, stream_id: u64, mut packet: &[u8]) -> Result<usize> {
        let mut total = 0;
        while !packet.is_empty() {
            let n = self.write_cell(&Cell::new(stream_id, packet, false))?;
            if n == 0 {
                break; // flow-control blocked; remainder retried later
            }
            total += n;
            packet = &packet[n..];
        }
        Ok(total)
    }
}

/// Reads STREAM frame bodies back into VPN packets.
pub struct MccDecoder<'b, B: QuicBackend + ?Sized> {
    backend: &'b mut B,
}

impl<'b, B: QuicBackend + ?Sized> MccDecoder<'b, B> {
    pub fn new(backend: &'b mut B) -> Self {
        Self { backend }
    }

    /// Drain every readable stream, invoking `sink(stream_id, bytes, fin)` for
    /// each chunk. The slice handed to `sink` borrows `scratch` (zero-copy into
    /// the caller's TUN write path).
    pub fn drain<F>(&mut self, scratch: &mut [u8], mut sink: F) -> Result<()>
    where
        F: FnMut(u64, &[u8], bool),
    {
        for sid in self.backend.readable() {
            loop {
                match self.backend.stream_recv(sid, scratch) {
                    Ok((0, fin)) => {
                        if fin {
                            sink(sid, &[], true);
                        }
                        break;
                    }
                    Ok((n, fin)) => {
                        sink(sid, &scratch[..n], fin);
                        if fin {
                            break;
                        }
                    }
                    Err(QuicError::Done) => break,
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::LoopbackBackend;

    #[test]
    fn round_trips_ip_packet_without_overhead() {
        let mut back = LoopbackBackend::new();
        let ip = b"\x45\x00\x00\x28 simulated IP packet payload";

        {
            let mut enc = MccEncoder::new(&mut back);
            let n = enc.write_ip_packet(4, ip).unwrap();
            assert_eq!(n, ip.len());
        }

        // The loopback moves stream data from the send side to the recv side.
        back.flush_streams();

        let mut scratch = [0u8; 2048];
        let mut got = Vec::new();
        {
            let mut dec = MccDecoder::new(&mut back);
            dec.drain(&mut scratch, |sid, bytes, _fin| {
                assert_eq!(sid, 4);
                got.extend_from_slice(bytes);
            })
            .unwrap();
        }
        assert_eq!(got, ip);
    }
}
