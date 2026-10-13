//! `prism-tun` — TUN device abstraction and VPN-packet to QUIC-stream mapping.
//!
//! The actual device backend (`tun` on Linux/macOS, `wintun` on Windows) is
//! gated behind the `device` feature; the trait and the flow-to-stream mapping
//! that PRISM relies on build without a device so they can be unit tested.

pub mod error;
pub mod mapper;

#[cfg(any(feature = "device-wintun", feature = "device-linux"))]
pub mod device;

#[cfg(all(target_os = "windows", feature = "device-wintun"))]
mod routes_windows;

#[cfg(all(target_os = "windows", feature = "device-wintun"))]
pub use routes_windows::RouteGuard;

use std::future::Future;

pub use error::TunError;
pub use mapper::{parse_flow, pool_stream_id, FlowKey, StreamMapper};

#[cfg(any(feature = "device-wintun", feature = "device-linux"))]
pub use device::PlatformTun;

/// An async TUN device: reads/writes raw IP packets.
pub trait TunDevice: Send {
    /// Read one IP packet into `buf`, returning its length.
    fn read_packet<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> impl Future<Output = Result<usize, TunError>> + Send + 'a;

    /// Write one IP packet.
    fn write_packet<'a>(
        &'a mut self,
        packet: &'a [u8],
    ) -> impl Future<Output = Result<(), TunError>> + Send + 'a;

    /// Path MTU of the device.
    fn mtu(&self) -> usize;
}
