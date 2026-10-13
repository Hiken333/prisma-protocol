//! Windows route helpers for PRISM TUN (bypass server IP, default via tunnel GW).

use anyhow::{Context, Result};
use std::process::Output;

const TUN_GW: &str = "172.19.0.1";
const TUN_ROUTE_METRIC: u32 = 1;
const PHYSICAL_ROUTE_METRIC_BUMPED: u32 = 50;
const DNS_PRIMARY: &str = "1.1.1.1";
const DNS_SECONDARY: &str = "8.8.8.8";

pub struct RouteGuard {
    server_ip: String,
    default_gw: String,
    tun_name: String,
    tun_if_index: u32,
    physical_if_index: u32,
    saved_physical_metric: u32,
    ipv6_disabled_aliases: Vec<String>,
}

impl RouteGuard {
    /// `tun_if_index` / `tun_alias` come from the open wintun adapter (not a name lookup).
    pub fn install(server_ip: &str, tun_if_index: u32, tun_alias: &str) -> Result<Self> {
        let physical = physical_default_route()?;

        tracing::info!(
            %server_ip,
            tun_alias,
            tun_if_index,
            physical_gw = %physical.gateway,
            physical_if_index = physical.if_index,
            tun_gw = TUN_GW,
            "installing PRISM routes"
        );

        set_interface_metric(physical.if_index, PHYSICAL_ROUTE_METRIC_BUMPED)?;
        set_interface_metric(tun_if_index, TUN_ROUTE_METRIC)?;

        bump_physical_default_metric(physical.if_index, PHYSICAL_ROUTE_METRIC_BUMPED)?;

        add_host_bypass(server_ip, &physical.gateway, physical.if_index)?;

        add_tunnel_default(tun_if_index)?;

        verify_tunnel_default(tun_if_index)?;
        tracing::info!(tun_if_index, "PRISM routes verified");

        set_tun_dns(tun_alias)?;

        let ipv6_disabled_aliases = disable_physical_ipv6(tun_alias)?;

        Ok(Self {
            server_ip: server_ip.to_string(),
            default_gw: physical.gateway,
            tun_name: tun_alias.to_string(),
            tun_if_index,
            physical_if_index: physical.if_index,
            saved_physical_metric: physical.metric,
            ipv6_disabled_aliases,
        })
    }
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        uninstall(
            &self.server_ip,
            &self.default_gw,
            self.tun_if_index,
            self.physical_if_index,
            self.saved_physical_metric,
            &self.tun_name,
            &self.ipv6_disabled_aliases,
        );
    }
}

struct PhysicalDefault {
    gateway: String,
    if_index: u32,
    metric: u32,
}

fn run_powershell(script: &str) -> Result<Output> {
    let out = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .output()
        .context("powershell")?;
    Ok(out)
}

fn ps_ok(out: &Output) -> bool {
    out.status.success()
}

fn physical_default_route() -> Result<PhysicalDefault> {
    let script = r"
$r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 |
  Where-Object {
    $_.InterfaceAlias -notlike '*Wintun*' -and
    $_.InterfaceDescription -notlike '*Wintun*' -and
    $_.NextHop -and $_.NextHop -ne '0.0.0.0' -and $_.NextHop -ne '172.19.0.1'
  } |
  Sort-Object RouteMetric |
  Select-Object -First 1
if (-not $r) { exit 1 }
Write-Output $r.NextHop
Write-Output $r.InterfaceIndex
Write-Output $r.RouteMetric
";
    let out = run_powershell(script)?;
    if !ps_ok(&out) {
        anyhow::bail!("no physical default route found");
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parts: Vec<String> = stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    if parts.len() < 3 {
        anyhow::bail!("unexpected Get-NetRoute output");
    }
    Ok(PhysicalDefault {
        gateway: parts[0].clone(),
        if_index: parts[1].parse().context("physical ifIndex")?,
        metric: parts[2].parse().unwrap_or(1),
    })
}

fn set_interface_metric(if_index: u32, metric: u32) -> Result<()> {
    let script = format!(
        "Set-NetIPInterface -InterfaceIndex {if_index} -InterfaceMetric {metric} -ErrorAction Stop"
    );
    let out = run_powershell(&script)?;
    if !ps_ok(&out) {
        tracing::warn!(
            if_index,
            stderr = %String::from_utf8_lossy(&out.stderr),
            "Set-NetIPInterface metric failed (continuing)"
        );
    }
    Ok(())
}

fn bump_physical_default_metric(if_index: u32, metric: u32) -> Result<()> {
    let script = format!(
        "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -InterfaceIndex {if_index} -ErrorAction SilentlyContinue | Set-NetRoute -RouteMetric {metric} -ErrorAction Stop"
    );
    let out = run_powershell(&script)?;
    if !ps_ok(&out) {
        tracing::warn!(
            stderr = %String::from_utf8_lossy(&out.stderr),
            "Set-NetRoute metric on physical interface failed (continuing)"
        );
    }
    Ok(())
}

fn restore_physical_default_metric(if_index: u32, metric: u32) {
    let script = format!(
        "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -InterfaceIndex {if_index} -ErrorAction SilentlyContinue | Set-NetRoute -RouteMetric {metric} -ErrorAction SilentlyContinue"
    );
    let _ = run_powershell(&script);
}

fn add_host_bypass(server_ip: &str, gw: &str, if_index: u32) -> Result<()> {
    let script = format!(
        "New-NetRoute -DestinationPrefix '{server_ip}/32' -NextHop '{gw}' -InterfaceIndex {if_index} -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction SilentlyContinue"
    );
    let out = run_powershell(&script)?;
    if !ps_ok(&out) {
        tracing::warn!(%server_ip, "host bypass route may already exist");
    }
    Ok(())
}

fn verify_tunnel_default(tun_if_index: u32) -> Result<()> {
    let script = format!(
        r"$r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -InterfaceIndex {tun_if_index} |
  Sort-Object RouteMetric |
  Select-Object -First 1
if (-not $r) {{ exit 2 }}
if ($r.RouteMetric -gt 5) {{ exit 3 }}
exit 0"
    );
    let out = run_powershell(&script)?;
    if ps_ok(&out) {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    anyhow::bail!("routes verification failed: {stderr}");
}

fn add_tunnel_default(tun_if_index: u32) -> Result<()> {
    // On-link default via wintun (WireGuard/sing-box style). Using NextHop 172.19.0.1
    // does not inject packets into the TUN device on Windows.
    let script = format!(
        "New-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceIndex {tun_if_index} -RouteMetric {TUN_ROUTE_METRIC} -PolicyStore ActiveStore -ErrorAction Stop"
    );
    let out = run_powershell(&script)?;
    if !ps_ok(&out) {
        anyhow::bail!(
            "tunnel default route failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // route.exe fallback: on-link default bound to interface index
    let status = std::process::Command::new("route")
        .args([
            "add",
            "0.0.0.0",
            "mask",
            "0.0.0.0",
            "0.0.0.0",
            "metric",
            &TUN_ROUTE_METRIC.to_string(),
            "if",
            &tun_if_index.to_string(),
        ])
        .status()
        .context("route add default via tun if")?;
    if !status.success() {
        tracing::warn!("route.exe default via tun if returned non-zero (may already exist)");
    }
    Ok(())
}

fn remove_tunnel_default(tun_if_index: u32) {
    let script = format!(
        "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -InterfaceIndex {tun_if_index} -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue"
    );
    let _ = run_powershell(&script);
    let _ = std::process::Command::new("route")
        .args([
            "delete",
            "0.0.0.0",
            "mask",
            "0.0.0.0",
            "0.0.0.0",
            "if",
            &tun_if_index.to_string(),
        ])
        .status();
}

fn remove_host_bypass(server_ip: &str) {
    let script = format!(
        "Get-NetRoute -DestinationPrefix '{server_ip}/32' -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue"
    );
    let _ = run_powershell(&script);
}

fn set_tun_dns(tun_name: &str) -> Result<()> {
    let q = tun_name.replace('\'', "''");
    let script = format!(
        "Set-DnsClientServerAddress -InterfaceAlias '{q}' -ServerAddresses @('{DNS_PRIMARY}','{DNS_SECONDARY}') -ErrorAction Stop"
    );
    let out = run_powershell(&script)?;
    if !ps_ok(&out) {
        anyhow::bail!(
            "set TUN DNS failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

fn restore_tun_dns(tun_name: &str) {
    let q = tun_name.replace('\'', "''");
    let script = format!(
        "Set-DnsClientServerAddress -InterfaceAlias '{q}' -ResetServerAddresses -ErrorAction SilentlyContinue"
    );
    let _ = run_powershell(&script);
}

fn disable_physical_ipv6(tun_name: &str) -> Result<Vec<String>> {
    let q = tun_name.replace('\'', "''");
    let script = format!(
        r"$disabled = @()
Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
  Where-Object {{ $_.Status -eq 'Up' -and $_.InterfaceAlias -ne '{q}' }} |
  ForEach-Object {{
    $b = Get-NetAdapterBinding -Name $_.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
    if ($b -and $b.Enabled) {{
      Disable-NetAdapterBinding -Name $_.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
      $disabled += $_.InterfaceAlias
    }}
  }}
$disabled -join ','"
    );
    let out = run_powershell(&script)?;
    if !ps_ok(&out) {
        tracing::warn!("IPv6 disable on physical adapters failed (continuing)");
        return Ok(Vec::new());
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        return Ok(Vec::new());
    }
    Ok(s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect())
}

fn restore_physical_ipv6(aliases: &[String]) {
    for alias in aliases {
        let q = alias.replace('\'', "''");
        let script = format!(
            "Enable-NetAdapterBinding -Name '{q}' -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue"
        );
        let _ = run_powershell(&script);
    }
}

/// Remove PRISM routes and restore interface/DNS/IPv6 state.
pub fn uninstall(
    server_ip: &str,
    default_gw: &str,
    tun_if_index: u32,
    physical_if_index: u32,
    saved_physical_metric: u32,
    tun_name: &str,
    ipv6_disabled_aliases: &[String],
) {
    remove_host_bypass(server_ip);
    remove_tunnel_default(tun_if_index);
    restore_physical_default_metric(physical_if_index, saved_physical_metric);
    restore_tun_dns(tun_name);
    restore_physical_ipv6(ipv6_disabled_aliases);

    if !default_gateway_exists(default_gw) {
        tracing::warn!(%default_gw, "restoring missing default route");
        let script = format!(
            "New-NetRoute -DestinationPrefix '0.0.0.0/0' -NextHop '{default_gw}' -InterfaceIndex {physical_if_index} -RouteMetric {saved_physical_metric} -PolicyStore ActiveStore -ErrorAction SilentlyContinue"
        );
        let _ = run_powershell(&script);
    }
}

fn default_gateway_exists(gw: &str) -> bool {
    let script = format!(
        "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 | Where-Object NextHop -EQ '{gw}').Count -gt 0"
    );
    match run_powershell(&script) {
        Ok(o) if ps_ok(&o) => {
            String::from_utf8_lossy(&o.stdout).trim().eq_ignore_ascii_case("true")
        }
        _ => true,
    }
}
