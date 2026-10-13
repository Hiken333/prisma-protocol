//! Platform TUN backends (optional features).

#[cfg(all(feature = "device-linux", target_os = "linux"))]
mod linux;

#[cfg(all(feature = "device-wintun", target_os = "windows"))]
mod wintun;

use crate::TunError;

/// Cross-platform TUN handle used by PRISM tunnel binaries.
pub struct PlatformTun {
    #[cfg(all(feature = "device-linux", target_os = "linux"))]
    inner: linux::LinuxTun,
    #[cfg(all(feature = "device-wintun", target_os = "windows"))]
    inner: wintun::WintunTun,
    mtu: usize,
}

impl PlatformTun {
    /// Open a TUN device with the given name, MTU, and IPv4 CIDR (e.g. `172.19.0.2/30`).
    pub async fn open(name: &str, mtu: usize, cidr: &str) -> Result<Self, TunError> {
        #[cfg(all(feature = "device-linux", target_os = "linux"))]
        {
            let inner = linux::LinuxTun::open(name, mtu, cidr).await?;
            return Ok(Self { inner, mtu });
        }
        #[cfg(all(feature = "device-wintun", target_os = "windows"))]
        {
            let inner = wintun::WintunTun::open(name, mtu, cidr).await?;
            return Ok(Self { inner, mtu });
        }
        #[cfg(not(any(
            all(feature = "device-linux", target_os = "linux"),
            all(feature = "device-wintun", target_os = "windows")
        )))]
        {
            let _ = (name, mtu, cidr);
            Err(TunError::Unavailable)
        }
    }

    pub fn mtu(&self) -> usize {
        self.mtu
    }

    /// Windows wintun interface index + alias for route/DNS setup.
    #[cfg(all(feature = "device-wintun", target_os = "windows"))]
    pub fn windows_route_target(&self) -> (u32, String) {
        let (idx, alias) = self.inner.route_target();
        (idx, alias.to_string())
    }

    pub async fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize, TunError> {
        #[cfg(all(feature = "device-linux", target_os = "linux"))]
        {
            return self.inner.read_packet(buf).await;
        }
        #[cfg(all(feature = "device-wintun", target_os = "windows"))]
        {
            return self.inner.read_packet(buf).await;
        }
        #[cfg(not(any(
            all(feature = "device-linux", target_os = "linux"),
            all(feature = "device-wintun", target_os = "windows")
        )))]
        {
            let _ = buf;
            Err(TunError::Unavailable)
        }
    }

    pub async fn write_packet(&mut self, packet: &[u8]) -> Result<(), TunError> {
        #[cfg(all(feature = "device-linux", target_os = "linux"))]
        {
            return self.inner.write_packet(packet).await;
        }
        #[cfg(all(feature = "device-wintun", target_os = "windows"))]
        {
            return self.inner.write_packet(packet).await;
        }
        #[cfg(not(any(
            all(feature = "device-linux", target_os = "linux"),
            all(feature = "device-wintun", target_os = "windows")
        )))]
        {
            let _ = packet;
            Err(TunError::Unavailable)
        }
    }
}

/// Parse `a.b.c.d/prefix` into address + prefix length.
pub(crate) fn parse_cidr(cidr: &str) -> Result<([u8; 4], u8), TunError> {
    let (addr, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| TunError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "cidr must be a.b.c.d/prefix",
        )))?;
    let mut octets = [0u8; 4];
    for (i, part) in addr.split('.').enumerate() {
        if i >= 4 {
            return Err(TunError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid ipv4",
            )));
        }
        octets[i] = part.parse().map_err(|_| {
            TunError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid ipv4 octet",
            ))
        })?;
    }
    let prefix: u8 = prefix.parse().map_err(|_| {
        TunError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid prefix",
        ))
    })?;
    Ok((octets, prefix))
}

/// Netmask from prefix length (IPv4).
pub(crate) fn prefix_to_netmask(prefix: u8) -> [u8; 4] {
    let bits = prefix.min(32);
    let mask = if bits == 0 {
        0u32
    } else {
        !0u32 << (32 - bits)
    };
    mask.to_be_bytes()
}
