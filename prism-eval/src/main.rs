//! `prism-eval` CLI: compare a PRISM capture summary against a Chrome baseline
//! and exit non-zero if it fails the indistinguishability thresholds (CI gate).
//!
//! Usage:
//!   prism-eval [--strict|--live] <chrome_baseline.json> <prism_capture.json>
//!
//! Modes:
//!   --strict (default): size_kl, iat_kl and entropy are all hard gates. Use
//!       with profile-sampled or large captures (the morph algorithm itself is
//!       proven within 0.05 by prism-morph's deterministic morph_fidelity test).
//!   --live: for a real packet capture. Entropy and size_kl are hard gates;
//!       iat_kl is reported but informational, because on Windows the system
//!       timer resolution (~15.6 ms) cannot realize the profile's sub-2 ms
//!       inter-arrival mass via real sleeps. The deterministic morph_fidelity
//!       test is the authoritative IAT gate; here we still surface the number.

use anyhow::{Context, Result};
use prism_eval::{
    kl_divergence, normalize_smoothed, shannon_entropy, CaptureSummary, Thresholds,
};

fn main() -> Result<()> {
    let mut live = false;
    let mut positional: Vec<String> = Vec::new();
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--live" => live = true,
            "--strict" => live = false,
            other => positional.push(other.to_string()),
        }
    }
    let baseline_path = positional.first().context("missing <chrome_baseline.json>")?;
    let capture_path = positional.get(1).context("missing <prism_capture.json>")?;

    let baseline = CaptureSummary::load(baseline_path)
        .with_context(|| format!("loading baseline {baseline_path}"))?;
    let capture = CaptureSummary::load(capture_path)
        .with_context(|| format!("loading capture {capture_path}"))?;

    let size_kl = kl_divergence(
        &normalize_smoothed(&capture.size_hist),
        &normalize_smoothed(&baseline.size_hist),
    );
    let iat_kl = kl_divergence(
        &normalize_smoothed(&capture.iat_hist),
        &normalize_smoothed(&baseline.iat_hist),
    );
    let entropy = shannon_entropy(&capture.payload_sample);

    let t = Thresholds::default();
    // In live mode, size_kl is held to a looser bound that absorbs packet-capture
    // discretization (UDP-header offset, framing, bucket edges); iat is advisory.
    let max_size_kl = if live { 0.10 } else { t.max_size_kl };

    let size_ok = size_kl <= max_size_kl;
    let iat_ok = live || iat_kl <= t.max_iat_kl;
    let entropy_ok = entropy >= t.min_entropy && entropy <= t.max_entropy;
    let passed = size_ok && iat_ok && entropy_ok;

    println!("mode     = {}", if live { "live" } else { "strict" });
    println!(
        "size  KL = {size_kl:.4} (max {max_size_kl:.4}) {}",
        if size_ok { "OK" } else { "FAIL" }
    );
    if live {
        println!("iat   KL = {iat_kl:.4} (informational; OS timer-bound)");
    } else {
        println!(
            "iat   KL = {iat_kl:.4} (max {:.4}) {}",
            t.max_iat_kl,
            if iat_kl <= t.max_iat_kl { "OK" } else { "FAIL" }
        );
    }
    println!(
        "entropy  = {entropy:.4} bits/byte (target {:.2}..{:.2}) {}",
        t.min_entropy,
        t.max_entropy,
        if entropy_ok { "OK" } else { "FAIL" }
    );
    println!("result   = {}", if passed { "PASS" } else { "FAIL" });

    if passed {
        Ok(())
    } else {
        std::process::exit(1);
    }
}
