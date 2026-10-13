//! Windows TUN backend (wintun.dll).

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use wintun::{Adapter, Session, MAX_RING_CAPACITY};

use crate::TunError;
use super::{parse_cidr, prefix_to_netmask};

const WINTUN_POOL: &str = "Anarac";

pub struct WintunTun {
    session: Arc<Session>,
    _adapter: Arc<Adapter>,
    if_index: u32,
    interface_alias: String,
}

impl WintunTun {
    pub async fn open(name: &str, mtu: usize, cidr: &str) -> Result<Self, TunError> {
        let (addr, prefix) = parse_cidr(cidr)?;
        let mask = prefix_to_netmask(prefix);

        let dll = unsafe { wintun::load() }.map_err(|e| {
            TunError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("wintun.dll: {e}"),
            ))
        })?;

        let adapter = match Adapter::open(&dll, name) {
            Ok(adapter) => {
                tracing::info!(%name, "reusing existing wintun adapter");
                adapter
            }
            Err(_) => Adapter::create(&dll, WINTUN_POOL, name, None).map_err(|e| {
                TunError::Io(std::io::Error::other(format!("wintun adapter: {e}")))
            })?,
        };

        let session = Arc::new(
            adapter
                .start_session(MAX_RING_CAPACITY)
                .map_err(|e| TunError::Io(std::io::Error::other(format!("wintun session: {e}"))))?,
        );

        set_interface_ip(&adapter, addr, mask)?;

        let if_index = adapter
            .get_adapter_index()
            .map_err(|e| TunError::Io(std::io::Error::other(format!("wintun ifIndex: {e}"))))?;
        let interface_alias = adapter
            .get_name()
            .unwrap_or_else(|_| name.to_string());

        // Set the adapter MTU. Without this the adapter keeps its huge default
        // MTU, so Windows advertises a bogus TCP MSS (e.g. 65495) and emits
        // oversized IP packets that fragment/stall over the 1280-byte tunnel.
        set_interface_mtu(if_index, mtu);

        tracing::info!(%name, %interface_alias, if_index, %cidr, mtu, "wintun TUN ready");
        Ok(Self {
            session,
            _adapter: adapter,
            if_index,
            interface_alias,
        })
    }

    pub fn route_target(&self) -> (u32, &str) {
        (self.if_index, &self.interface_alias)
    }

    pub async fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize, TunError> {
        match self.session.try_receive() {
            Ok(Some(packet)) => {
                let bytes = packet.bytes();
                let n = bytes.len().min(buf.len());
                buf[..n].copy_from_slice(&bytes[..n]);
                drop(packet);
                Ok(n)
            }
            Ok(None) => Ok(0),
            Err(e) => Err(TunError::Io(std::io::Error::other(format!("wintun recv: {e}")))),
        }
    }

    pub async fn write_packet(&mut self, packet: &[u8]) -> Result<(), TunError> {
        let mut p = self
            .session
            .allocate_send_packet(packet.len().min(u16::MAX as usize) as u16)
            .map_err(|e| TunError::Io(std::io::Error::other(format!("wintun alloc: {e}"))))?;
        let n = p.bytes_mut().len().min(packet.len());
        p.bytes_mut()[..n].copy_from_slice(&packet[..n]);
        self.session.send_packet(p);
        Ok(())
    }
}

fn set_interface_mtu(if_index: u32, mtu: usize) {
    // netsh is the most reliable way to set the IPv4 MTU on a wintun subinterface.
    let res = std::process::Command::new("netsh")
        .args([
            "interface",
            "ipv4",
            "set",
            "subinterface",
            &if_index.to_string(),
            &format!("mtu={mtu}"),
            "store=active",
        ])
        .output();
    match res {
        Ok(o) if o.status.success() => {}
        Ok(o) => tracing::warn!(
            if_index,
            mtu,
            stderr = %String::from_utf8_lossy(&o.stderr),
            "netsh set MTU failed (continuing)"
        ),
        Err(e) => tracing::warn!(if_index, mtu, error = %e, "netsh set MTU spawn failed"),
    }
}

fn set_interface_ip(adapter: &Adapter, addr: [u8; 4], mask: [u8; 4]) -> Result<(), TunError> {
    let ip = Ipv4Addr::from(addr);
    let netmask = Ipv4Addr::from(mask);
    let mut last_err = String::new();

    // NDIS may not register the adapter immediately after create (Element not found).
    for attempt in 1..=8 {
        if attempt > 1 {
            std::thread::sleep(Duration::from_millis(250 * attempt as u64));
        }
        match adapter.set_network_addresses_tuple(IpAddr::V4(ip), IpAddr::V4(netmask), None) {
            Ok(()) => return Ok(()),
            Err(e) => {
                last_err = e.to_string();
                tracing::warn!(attempt, error = %last_err, "set TUN address retry");
            }
        }
    }

    Err(TunError::Io(std::io::Error::other(format!(
        "failed to set TUN IP (run as Administrator): {last_err}"
    ))))
}
