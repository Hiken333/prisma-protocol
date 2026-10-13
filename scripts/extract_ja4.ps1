<#
.SYNOPSIS
  Extract the QUIC ClientHello JA4 fingerprint from a pcapng using tshark's
  native tls.handshake.ja4 / ja4_r fields (Wireshark >= 4.2).

.DESCRIPTION
  Writes the JA4 string to -Out (one line) and the raw JA4_r form to
  "<Out>.r" for field-by-field diffing. Picks the first ClientHello found.

.EXAMPLE
  .\scripts\extract_ja4.ps1 -Pcap testdata\prism.pcapng -Out testdata\prism.ja4
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Pcap,
    [Parameter(Mandatory = $true)][string]$Out,
    [string]$Tshark = "C:\Program Files\Wireshark\tshark.exe"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $Tshark)) { throw "tshark not found: $Tshark" }
if (-not (Test-Path $Pcap)) { throw "pcap not found: $Pcap" }

# QUIC ClientHello carries the TLS handshake inside CRYPTO frames; tshark's TLS
# dissector emits ja4 with a 'q' transport prefix for QUIC.
$rows = & $Tshark -r $Pcap `
    -Y "quic && tls.handshake.type == 1" `
    -T fields -e tls.handshake.ja4 -e tls.handshake.ja4_r 2>$null |
    Where-Object { $_ -and $_.Trim() -ne "" -and $_ -notmatch "^\s*\t*$" }

if (-not $rows) {
    throw "No QUIC ClientHello with a JA4 field found in $Pcap. (Is it a QUIC capture? Is the TLS/QUIC dissector enabled?)"
}

$first = ($rows | Select-Object -First 1)
$parts = $first -split "`t"
$ja4 = $parts[0].Trim()
$ja4r = if ($parts.Count -gt 1) { $parts[1].Trim() } else { "" }

if (-not $ja4) { throw "Empty JA4 extracted from $Pcap." }

Set-Content -Path $Out -Value $ja4 -NoNewline
Set-Content -Path ($Out + ".r") -Value $ja4r -NoNewline

Write-Host "JA4   : $ja4"
Write-Host "JA4_r : $ja4r"
Write-Host "Wrote : $Out (+ .r)"
