//! Capture summary model: histogrammed sizes / inter-arrival times produced by
//! the capture preprocessing step (e.g. a tshark/pyshark exporter).

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FlowDirection {
    Up,
    Down,
}

/// A histogrammed summary of one capture (Chrome baseline or PRISM session).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CaptureSummary {
    /// Datagram-size histogram (matching bucket layout across compared captures).
    pub size_hist: Vec<u64>,
    /// Inter-arrival-time histogram.
    pub iat_hist: Vec<u64>,
    /// A representative payload sample for entropy estimation.
    #[serde(default, with = "serde_bytes_vec")]
    pub payload_sample: Vec<u8>,
    pub direction: FlowDirection,
}

impl CaptureSummary {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let bytes = std::fs::read(path)?;
        Ok(serde_json::from_slice(&bytes)?)
    }
}

/// Hex (de)serialization for the payload sample so summaries stay human-diffable.
mod serde_bytes_vec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        s.serialize_str(&hex)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(serde::de::Error::custom))
            .collect()
    }
}
