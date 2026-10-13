//! Parallel UDP lanes on `base_port + 1 .. +N`.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use tokio::net::UdpSocket;
use tracing::info;

use crate::pacer::bolt_lanes_from_env;

pub struct BoltLanes {
    pub sockets: Vec<Arc<UdpSocket>>,
    peer: Vec<Arc<RwLock<Option<SocketAddr>>>>,
    next_lane: AtomicUsize,
    lane_count: usize,
}

impl BoltLanes {
    pub fn lane_count(&self) -> usize {
        self.lane_count
    }

    pub fn lane_addrs(base: SocketAddr, count: usize) -> Vec<SocketAddr> {
        let ip = base.ip();
        let p = base.port();
        (1..=count)
            .map(|i| SocketAddr::new(ip, p.saturating_add(i as u16)))
            .collect()
    }

    pub fn lane_addrs_default(base: SocketAddr) -> Vec<SocketAddr> {
        Self::lane_addrs(base, bolt_lanes_from_env())
    }

    pub async fn bind_server(base: SocketAddr) -> Result<Self, std::io::Error> {
        let count = bolt_lanes_from_env();
        let addrs = Self::lane_addrs(base, count);
        let mut sockets = Vec::with_capacity(count);
        for addr in &addrs {
            let s = Arc::new(UdpSocket::bind(*addr).await?);
            tune_lane_socket(&s);
            sockets.push(s);
        }
        info!(?addrs, count, "BOLT lanes listening (server)");
        Ok(Self::new(sockets, vec![None; count], count))
    }

    pub async fn bind_client(peer: SocketAddr) -> Result<Self, std::io::Error> {
        let count = bolt_lanes_from_env();
        let peer_lanes = Self::lane_addrs(peer, count);
        let bind_addr = if peer.is_ipv4() {
            SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0))
        } else {
            SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0))
        };
        let mut sockets = Vec::with_capacity(count);
        for _ in 0..count {
            let s = Arc::new(UdpSocket::bind(bind_addr).await?);
            tune_lane_socket(&s);
            sockets.push(s);
        }
        let peer_set: Vec<Option<SocketAddr>> = peer_lanes.into_iter().map(Some).collect();
        info!(?peer_set, ?bind_addr, count, "BOLT lanes ready (client)");
        Ok(Self::new(sockets, peer_set, count))
    }

    fn new(sockets: Vec<Arc<UdpSocket>>, peer: Vec<Option<SocketAddr>>, lane_count: usize) -> Self {
        Self {
            sockets,
            peer: peer.into_iter().map(|p| Arc::new(RwLock::new(p))).collect(),
            next_lane: AtomicUsize::new(0),
            lane_count,
        }
    }

    pub fn peer_handle(&self, lane: usize) -> Arc<RwLock<Option<SocketAddr>>> {
        Arc::clone(&self.peer[lane])
    }

    pub fn learn_peer(&self, lane: usize, from: SocketAddr) -> bool {
        let mut slot = self.peer[lane].write().expect("peer lock");
        if *slot == Some(from) {
            return false;
        }
        *slot = Some(from);
        info!(lane, %from, "BOLT peer learned");
        true
    }

    pub fn socket(&self, lane: usize) -> Arc<UdpSocket> {
        Arc::clone(&self.sockets[lane])
    }

    pub fn pick_lane(&self) -> usize {
        self.next_lane.fetch_add(1, Ordering::Relaxed) % self.lane_count
    }

    pub async fn send_wire(&self, lane: usize, wire: &[u8]) -> Result<usize, std::io::Error> {
        let peer = *self.peer[lane].read().expect("peer lock");
        let Some(peer) = peer else {
            return Ok(0);
        };
        self.sockets[lane].send_to(wire, peer).await
    }
}

fn tune_lane_socket(sock: &UdpSocket) {
    const BUF: usize = 16 * 1024 * 1024;
    let s = socket2::SockRef::from(sock);
    let _ = s.set_recv_buffer_size(BUF);
    let _ = s.set_send_buffer_size(BUF);
}
