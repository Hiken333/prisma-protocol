//! Unified transport backend trait for native UDP and quiche paths.

use crate::conn::ConnectionState;
use crate::error::Result;

/// Minimal stream-multiplexed transport surface shared by native and QUIC backends.
pub trait TransportBackend: Send {
    fn stream_send(&mut self, stream_id: u64, data: &[u8], fin: bool) -> Result<usize>;
    fn stream_recv(&mut self, stream_id: u64, out: &mut [u8]) -> Result<(usize, bool)>;
    fn readable(&self) -> Vec<u64>;
    fn is_established(&self) -> bool;
    fn is_closed(&self) -> bool;
}

impl TransportBackend for ConnectionState {
    fn stream_send(&mut self, stream_id: u64, data: &[u8], fin: bool) -> Result<usize> {
        self.queue_send(stream_id, bytes::Bytes::copy_from_slice(data), fin)?;
        Ok(data.len())
    }

    fn stream_recv(&mut self, stream_id: u64, out: &mut [u8]) -> Result<(usize, bool)> {
        self.read_stream(stream_id, out)
    }

    fn readable(&self) -> Vec<u64> {
        self.readable_stream_ids()
    }

    fn is_established(&self) -> bool {
        true
    }

    fn is_closed(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::{ConnectionState, Side};
    use crate::crypto::SessionKeys;
    use prism_core::crypto::X25519Secret;
    use prism_morph::CdnProfile;

    fn pair() -> (ConnectionState, ConnectionState) {
        let server_sk = X25519Secret::generate();
        let client_sk = X25519Secret::generate();
        let c_shared = client_sk.diffie_hellman(&server_sk.public());
        let s_shared = server_sk.diffie_hellman(&client_sk.public());
        let ck = SessionKeys::derive(&c_shared, true).unwrap();
        let sk = SessionKeys::derive(&s_shared, false).unwrap();
        let prof = CdnProfile::synthetic_chrome();
        (
            ConnectionState::new(ck, Side::Client, prof.clone(), 0.0, 1400).unwrap(),
            ConnectionState::new(sk, Side::Server, prof, 0.0, 1400).unwrap(),
        )
    }

    #[test]
    fn native_backend_is_established() {
        let (client, _) = pair();
        assert!(TransportBackend::is_established(&client));
        assert!(!TransportBackend::is_closed(&client));
    }
}
