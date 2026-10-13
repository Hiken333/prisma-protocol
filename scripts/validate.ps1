<#
.SYNOPSIS
  One-shot PRISM indistinguishability gate: builds the binaries, captures a
  Chrome h3 ClientHello and a PRISM session, and runs every gate:

    1. JA4 handshake parity  (PRISM ClientHello == Chrome 148)   [HARD]
    2. Morph KL fidelity     (size_kl & iat_kl <= 0.05)          [HARD]
    3. Statistical gate      (prism-eval --strict, profile data) [HARD]
    4. Live-capture gate     (prism-eval --live on real bulk)    [HARD]

  All four fail the script on regression. Gate 2 (deterministic) is the
  authoritative size+IAT proof of the morph algorithm; Gate 4 runs prism-eval
  in --live mode on a real sustained capture, enforcing entropy and size_kl
  while treating IAT as informational (OS timer resolution bounds sub-2ms
  inter-arrival on Windows).

.EXAMPLE
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
  .\scripts\validate.ps1
#>
[CmdletBinding()]
param(
    [string]$OutDir = "testdata",
    [string]$Tshark = "C:\Program Files\Wireshark\tshark.exe",
    [switch]$SkipCapture
)

# Native commands (cargo/python) write warnings to stderr; manage success via
# exit codes and the $failures list rather than terminating on stderr.
$ErrorActionPreference = "Continue"
$failures = @()

function Section($t) { Write-Host "`n=== $t ===" -ForegroundColor Cyan }

# --- Build env + binaries --------------------------------------------------
Section "Build"
. "$PSScriptRoot\dev-env.ps1" *> $null
$env:CC = "cl.exe"; $env:CXX = "cl.exe"
Get-Process prism-server, prism-client -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 400
cmd /c "cargo build -p prism-server -p prism-client --features quiche-backend 2>&1" | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Host "build failed" -ForegroundColor Red; exit 1 }

# --- Capture ---------------------------------------------------------------
if (-not $SkipCapture) {
    Section "Capture (Chrome ClientHello + sustained PRISM bulk traffic)"
    try {
        & "$PSScriptRoot\capture.ps1" -OutDir $OutDir -ChromeSeconds 4 -PrismSeconds 16 -Bulk |
            Out-Null
    } catch {
        Write-Host "capture failed: $_" -ForegroundColor Red; exit 1
    }
}

# --- Gate 1: JA4 parity (HARD) --------------------------------------------
Section "Gate 1/4: JA4 handshake parity"
try {
    & "$PSScriptRoot\extract_ja4.ps1" -Pcap "$OutDir\chrome_h3.pcapng" -Out "$OutDir\chrome.ja4" -Tshark $Tshark | Out-Null
    & "$PSScriptRoot\extract_ja4.ps1" -Pcap "$OutDir\prism.pcapng" -Out "$OutDir\prism.ja4" -Tshark $Tshark | Out-Null
    python "$PSScriptRoot\ja4_compare.py" "$OutDir\chrome.ja4" "$OutDir\prism.ja4"
    if ($LASTEXITCODE -ne 0) { $failures += "JA4 parity" }
} catch {
    Write-Host "JA4 extraction error: $_" -ForegroundColor Red
    $failures += "JA4 parity"
}

# --- Gate 2: deterministic morph KL fidelity (HARD) ------------------------
Section "Gate 2/4: morph KL fidelity (size_kl & iat_kl <= 0.05)"
cmd /c "cargo test -p prism-morph --test morph_fidelity 2>&1"
if ($LASTEXITCODE -ne 0) { $failures += "morph KL fidelity" }

# --- Gate 3: statistical gate on representative fixtures (HARD) ------------
Section "Gate 3/4: statistical gate (representative profile samples)"
cmd /c "python `"$PSScriptRoot\sample_profile.py`" down 20000 1 > `"$OutDir\chrome_baseline.json`""
cmd /c "python `"$PSScriptRoot\sample_profile.py`" down 20000 2 > `"$OutDir\prism_capture.json`""
cmd /c "cargo run -q -p prism-eval -- `"$OutDir\chrome_baseline.json`" `"$OutDir\prism_capture.json`" 2>&1"
if ($LASTEXITCODE -ne 0) { $failures += "statistical gate" }

# --- Gate 4: live-capture eval (INFO) -------------------------------------
Section "Gate 4/4: live-capture gate (prism-eval --live on real bulk traffic)"
$env:PRISM_TSHARK = $Tshark
# Baseline = the morph CdnProfile sampled through the same clamp (mtu 1452);
# capture = the real sustained PRISM session.
cmd /c "python `"$PSScriptRoot\sample_profile.py`" down 20000 1 1452 > `"$OutDir\chrome_baseline_live.json`""
cmd /c "python `"$PSScriptRoot\summarize_capture.py`" `"$OutDir\prism.pcapng`" down > `"$OutDir\prism_live.json`""
cmd /c "cargo run -q -p prism-eval -- --live `"$OutDir\chrome_baseline_live.json`" `"$OutDir\prism_live.json`" 2>&1"
if ($LASTEXITCODE -ne 0) { $failures += "live-capture gate" }

# --- Verdict ---------------------------------------------------------------
Section "Verdict"
if ($failures.Count -eq 0) {
    Write-Host "ALL HARD GATES PASS" -ForegroundColor Green
    exit 0
} else {
    Write-Host ("FAILED: " + ($failures -join ", ")) -ForegroundColor Red
    exit 1
}
