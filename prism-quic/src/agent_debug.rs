//! Agent debug NDJSON logger (session e61415).
//! Active when `PRISM_AGENT_DEBUG=1` or `PRISM_PERF=1` / `--perf`.
#![cfg(feature = "quiche-backend")]

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static SEQ: AtomicU64 = AtomicU64::new(0);
static RESOLVED_LOG: OnceLock<PathBuf> = OnceLock::new();

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

pub fn enabled() -> bool {
    env_flag("PRISM_AGENT_DEBUG") || env_flag("PRISM_PERF") || env_flag("PRISM_SESSION_DEBUG")
}

fn resolve_log_path() -> PathBuf {
    if let Ok(p) = std::env::var("PRISM_AGENT_DEBUG_LOG") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("debug-e61415.log"));
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join("debug-e61415.log"));
    }
    candidates.push(std::env::temp_dir().join("debug-e61415.log"));
    candidates.push(PathBuf::from("debug-e61415.log"));
    for c in &candidates {
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(c) {
            let _ = writeln!(f, r#"{{"sessionId":"e61415","message":"log_path_probe","data":{{"path":"{}"}}}}"#, c.display());
            return c.clone();
        }
    }
    std::env::temp_dir().join("debug-e61415.log")
}

fn log_path() -> &'static PathBuf {
    RESOLVED_LOG.get_or_init(resolve_log_path)
}

/// Call once at process start so the chosen path appears in stderr/docker logs.
pub fn announce() {
    if !enabled() {
        return;
    }
    let path = log_path();
    tracing::info!(
        target: "agent_debug",
        path = %path.display(),
        "PRISM agent debug enabled"
    );
    log(
        "H0",
        "agent_debug.rs:announce",
        "debug session started",
        &format!(r#"{{"log_path":"{}"}}"#, path.display()),
    );
}

pub fn log(hypothesis_id: &str, location: &str, message: &str, data_json: &str) {
    if !enabled() {
        return;
    }
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let id = SEQ.fetch_add(1, Ordering::Relaxed);
    let line = format!(
        r#"{{"sessionId":"e61415","id":"log_{ts}_{id}","timestamp":{ts},"hypothesisId":"{hypothesis_id}","location":"{location}","message":"{message}","data":{data_json}}}"#
    );
    tracing::info!(target: "agent_debug", %hypothesis_id, %location, %message, raw = %data_json);
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(log_path()) {
        let _ = writeln!(f, "{line}");
    }
}

/// Periodic tunnel throughput snapshot (client or server).
pub struct TunnelTickStats {
    pub role: &'static str,
    pub fast: bool,
    pub loop_iters: u64,
    pub tun_pkts_in: u64,
    pub tun_bytes_in: u64,
    pub tun_pkts_out: u64,
    pub tun_bytes_out: u64,
    pub udp_pkts_sent: u64,
    pub udp_bytes_sent: u64,
    pub udp_pkts_recv: u64,
    pub udp_bytes_recv: u64,
    pub keepalives: u64,
    pub peer_idle_ms: u64,
    pub loop_us_max: u64,
    pub loop_us_avg: u64,
    pub phase_tun_us: u64,
    pub phase_recv_us: u64,
    pub phase_flush_us: u64,
    pub phase_drain_us: u64,
}

impl TunnelTickStats {
    pub fn emit(&self, hypothesis_id: &str) {
        log(
            hypothesis_id,
            "tunnel_tick",
            "tunnel throughput snapshot",
            &format!(
                r#"{{"role":"{}","fast":{},"loop_iters":{},"tun_pkts_in":{},"tun_bytes_in":{},"tun_pkts_out":{},"tun_bytes_out":{},"udp_pkts_sent":{},"udp_bytes_sent":{},"udp_pkts_recv":{},"udp_bytes_recv":{},"keepalives":{},"peer_idle_ms":{},"loop_us_max":{},"loop_us_avg":{},"phase_tun_us":{},"phase_recv_us":{},"phase_flush_us":{},"phase_drain_us":{}}}"#,
                self.role,
                self.fast,
                self.loop_iters,
                self.tun_pkts_in,
                self.tun_bytes_in,
                self.tun_pkts_out,
                self.tun_bytes_out,
                self.udp_pkts_sent,
                self.udp_bytes_sent,
                self.udp_pkts_recv,
                self.udp_bytes_recv,
                self.keepalives,
                self.peer_idle_ms,
                self.loop_us_max,
                self.loop_us_avg,
                self.phase_tun_us,
                self.phase_recv_us,
                self.phase_flush_us,
                self.phase_drain_us,
            ),
        );
    }
}
