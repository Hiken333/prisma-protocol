//! Deployment configuration mirroring the `prism:` YAML block in the spec (§7).

use serde::{Deserialize, Serialize};

/// Top-level node configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrismConfig {
    pub listen: String,
    pub decoy: DecoyConfig,
    pub shadow_key: ShadowKeyConfig,
    pub transport: TransportConfig,
    pub morph: MorphConfig,
    pub tls: TlsConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecoyConfig {
    pub origin: String,
    /// Refresh interval for the captured CDN profile, in seconds.
    #[serde(default = "default_profile_refresh")]
    pub profile_refresh_secs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShadowKeyConfig {
    /// X25519 private key (server only), hex-encoded. Rotated every 30 days.
    pub private: Option<String>,
    /// X25519 public key, hex-encoded. Shipped in the client subscription.
    pub public: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransportConfig {
    #[serde(default = "default_max_streams")]
    pub max_streams: u64,
    #[serde(default = "default_cwnd_gain")]
    pub initial_cwnd_gain: f64,
    #[serde(default = "default_brutal_threshold")]
    pub brutal_loss_threshold: f64,
    /// `auto` enables Reed-Solomon FEC when loss > 5%.
    #[serde(default)]
    pub fec: FecMode,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FecMode {
    Off,
    On,
    #[default]
    Auto,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MorphConfig {
    #[serde(default = "default_engine")]
    pub engine: String,
    #[serde(default = "default_profile_source")]
    pub profile_source: String,
    #[serde(default = "default_jitter")]
    pub jitter_pct: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TlsConfig {
    #[serde(default = "default_ech")]
    pub ech: String,
    #[serde(default = "default_fingerprint")]
    pub fingerprint: String,
    #[serde(default = "default_max_early_data")]
    pub max_early_data: u32,
}

fn default_profile_refresh() -> u64 {
    24 * 3600
}
fn default_max_streams() -> u64 {
    256
}
fn default_cwnd_gain() -> f64 {
    2.0
}
fn default_brutal_threshold() -> f64 {
    0.02
}
fn default_engine() -> String {
    "cpr".to_string()
}
fn default_profile_source() -> String {
    "decoy_capture".to_string()
}
fn default_jitter() -> f64 {
    0.10
}
fn default_ech() -> String {
    "required".to_string()
}
fn default_fingerprint() -> String {
    "chrome_124".to_string()
}
fn default_max_early_data() -> u32 {
    16384
}
