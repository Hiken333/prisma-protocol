//! Linux TUN backend (`tun` crate, async).

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

use crate::TunError;
use super::{parse_cidr, prefix_to_netmask};

pub struct LinuxTun {
    dev: Arc<Mutex<tun::AsyncDevice>>,
}

impl LinuxTun {
    pub async fn open(name: &str, mtu: usize, cidr: &str) -> Result<Self, TunError> {
        let (addr, prefix) = parse_cidr(cidr)?;
        let mask = prefix_to_netmask(prefix);

        let mut config = tun::Configuration::default();
        config
            .name(name)
            .address((addr[0], addr[1], addr[2], addr[3]))
            .netmask((mask[0], mask[1], mask[2], mask[3]))
            .mtu(mtu as i32)
            .up();

        let dev = tun::create_as_async(&config).map_err(|e| {
            TunError::Io(std::io::Error::other(format!("tun open: {e}")))
        })?;
        tracing::info!(%name, %cidr, mtu, "linux TUN ready");
        Ok(Self {
            dev: Arc::new(Mutex::new(dev)),
        })
    }

    pub async fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize, TunError> {
        let mut dev = self.dev.lock().await;
        let n = dev.read(buf).await.map_err(TunError::Io)?;
        Ok(n)
    }

    pub async fn write_packet(&mut self, packet: &[u8]) -> Result<(), TunError> {
        let mut dev = self.dev.lock().await;
        dev.write_all(packet).await.map_err(TunError::Io)?;
        Ok(())
    }
}
