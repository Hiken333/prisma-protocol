//! Real QUIC backend on top of Cloudflare `quiche` + BoringSSL.
//!
//! Compiled only with `--features quiche-backend`. The three capabilities stock
//! quiche keeps internal — TLS exporter access, frame-level padding to a target
//! size, explicit PING — are provided by the vendored PRISM fork
//! (`third_party/quiche`, see `docs/quiche-fork.md`) as
//! `Connection::export_keying_material`, `set_prism_min_send_size` and
//! `send_prism_ping`. This backend wires straight to them.

#![cfg(feature = "quiche-backend")]

use crate::backend::{AckReport, QuicBackend};
use crate::error::{QuicError, Result};

/// Wraps a `quiche::Connection`. The owner is responsible for the UDP socket and
/// for calling [`QuicBackend::recv`] / [`QuicBackend::send`] in its event loop.
pub struct QuicheBackend {
    conn: quiche::Connection,
    /// Source/destination for `RecvInfo` / `SendInfo`.
    local: std::net::SocketAddr,
    peer: std::net::SocketAddr,
}

impl QuicheBackend {
    pub fn from_connection(
        conn: quiche::Connection,
        local: std::net::SocketAddr,
        peer: std::net::SocketAddr,
    ) -> Self {
        Self { conn, local, peer }
    }

    /// Access the inner connection (e.g. for handshake-time configuration).
    pub fn connection_mut(&mut self) -> &mut quiche::Connection {
        &mut self.conn
    }
}

fn map_err(e: quiche::Error) -> QuicError {
    match e {
        quiche::Error::Done => QuicError::Done,
        quiche::Error::StreamLimit => QuicError::Backend("stream limit".into()),
        other => QuicError::Backend(format!("{other:?}")),
    }
}

impl QuicBackend for QuicheBackend {
    fn stream_send(&mut self, stream_id: u64, data: &[u8], fin: bool) -> Result<usize> {
        match self.conn.stream_send(stream_id, data, fin) {
            Ok(n) => Ok(n),
            Err(quiche::Error::Done) => Ok(0),
            Err(e) => Err(map_err(e)),
        }
    }

    fn stream_recv(&mut self, stream_id: u64, out: &mut [u8]) -> Result<(usize, bool)> {
        match self.conn.stream_recv(stream_id, out) {
            Ok((n, fin)) => Ok((n, fin)),
            Err(quiche::Error::Done) => Ok((0, false)),
            Err(e) => Err(map_err(e)),
        }
    }

    fn readable(&self) -> Vec<u64> {
        self.conn.readable().collect()
    }

    fn set_morph_target(&mut self, target: usize) {
        // PRISM fork: pad the next short-header datagram up to `target` bytes
        // with in-AEAD PADDING frames.
        self.conn.set_prism_min_send_size(target);
    }

    fn send(&mut self, out: &mut [u8]) -> Result<usize> {
        match self.conn.send(out) {
            Ok((n, _info)) => Ok(n),
            Err(quiche::Error::Done) => Ok(0),
            Err(e) => Err(map_err(e)),
        }
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        let info = quiche::RecvInfo {
            from: self.peer,
            to: self.local,
        };
        self.conn.recv(buf, info).map_err(map_err)
    }

    fn send_ping(&mut self) -> Result<()> {
        // PRISM fork: queue a PING so the next packet is ack-eliciting; the
        // morph target padding turns it into a PING + PADDING cover datagram.
        self.conn.send_prism_ping().map_err(map_err)
    }

    fn export_keying_material(
        &mut self,
        label: &[u8],
        context: &[u8],
        out: &mut [u8],
    ) -> Result<()> {
        // PRISM fork: TLS 1.3 exporter (RFC 8446 7.5).
        self.conn
            .export_keying_material(out, label, context)
            .map_err(map_err)
    }

    fn take_ack_report(&mut self) -> AckReport {
        // Stock quiche aggregates ACK/loss in `stats()` / `path_stats()`. The fork
        // surfaces per-packet `(acked, lost, rtt)` for the custom controller.
        AckReport::default()
    }

    fn bytes_in_flight(&self) -> usize {
        self.conn
            .stats()
            .sent
            .saturating_sub(self.conn.stats().lost) as usize
    }

    fn is_established(&self) -> bool {
        self.conn.is_established()
    }

    fn is_closed(&self) -> bool {
        self.conn.is_closed()
    }

    fn close(&mut self, app: bool, err: u64, reason: &[u8]) -> Result<()> {
        match self.conn.close(app, err, reason) {
            Ok(()) | Err(quiche::Error::Done) => Ok(()),
            Err(e) => Err(map_err(e)),
        }
    }
}
