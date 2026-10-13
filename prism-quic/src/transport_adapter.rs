//! Adapter: implement [`prism_transport::TransportBackend`] for [`QuicBackend`](crate::backend::QuicBackend).

use prism_transport::{TransportBackend, TransportError};

use crate::backend::QuicBackend;
use crate::error::QuicError;

/// QUIC stack wrapper implementing the shared transport trait.
pub struct QuicTransportAdapter<B: QuicBackend> {
    inner: B,
}

impl<B: QuicBackend> QuicTransportAdapter<B> {
    pub fn new(inner: B) -> Self {
        Self { inner }
    }

    pub fn inner(&self) -> &B {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut B {
        &mut self.inner
    }
}

fn map_err(e: QuicError) -> TransportError {
    TransportError::Malformed(e.to_string())
}

impl<B: QuicBackend> TransportBackend for QuicTransportAdapter<B> {
    fn stream_send(&mut self, stream_id: u64, data: &[u8], fin: bool) -> Result<usize, TransportError> {
        self.inner.stream_send(stream_id, data, fin).map_err(map_err)
    }

    fn stream_recv(&mut self, stream_id: u64, out: &mut [u8]) -> Result<(usize, bool), TransportError> {
        self.inner.stream_recv(stream_id, out).map_err(map_err)
    }

    fn readable(&self) -> Vec<u64> {
        self.inner.readable()
    }

    fn is_established(&self) -> bool {
        self.inner.is_established()
    }

    fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::LoopbackBackend;

    #[test]
    fn adapter_delegates_stream_io() {
        let back = LoopbackBackend::new();
        let mut adapter = QuicTransportAdapter::new(back);
        adapter.stream_send(4, b"vpn", false).unwrap();
        adapter.inner_mut().flush_streams();
        let mut buf = [0u8; 64];
        let (n, _) = adapter.stream_recv(4, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"vpn");
    }
}
