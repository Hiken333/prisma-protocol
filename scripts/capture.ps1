<#
.SYNOPSIS
  Capture a Chrome HTTP/3 (QUIC) session to a decoy origin and a PRISM
  client<->server session on loopback, into two pcapng files for the
  indistinguishability gate (prism-eval) and JA4 extraction.

.DESCRIPTION
  - Chrome -> decoy h3 is captured on the active physical interface.
  - PRISM client<->server is captured on the Npcap loopback adapter.

  Requires Wireshark (tshark/dumpcap), Chrome, and prebuilt PRISM binaries:
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
    . .\scripts\dev-env.ps1
    $env:CC='cl.exe'; $env:CXX='cl.exe'
    cargo build -p prism-server -p prism-client --features quiche-backend

.EXAMPLE
  .\scripts\capture.ps1 -DecoyHost www.google.com -OutDir testdata
#>
[CmdletBinding()]
param(
    [string]$DecoyHost = "www.google.com",
    [string]$OutDir = "testdata",
    [int]$ChromeSeconds = 12,
    [int]$PrismSeconds = 10,
    [int]$Count = 80,
    [int]$ServerPort = 4433,
    [int]$ChromeSinkPort = 8443,
    [string]$ChromeDecoyName = "testdecoy",
    [switch]$Bulk,
    [string]$Tshark = "C:\Program Files\Wireshark\tshark.exe",
    [string]$Dumpcap = "C:\Program Files\Wireshark\dumpcap.exe",
    [string]$Chrome = "C:\Program Files\Google\Chrome\Application\chrome.exe",
    [string]$Cert = "testdata\cert.pem",
    [string]$Key = "testdata\key.pem",
    # Fixed shadow secret so captures are reproducible (any 64 hex chars).
    [string]$ShadowSk = "1111111111111111111111111111111111111111111111111111111111111111"
)

# X25519 public key for the default test ShadowSk above (deterministic; avoids
# parsing tracing output from a redirected, block-buffered server stdout).
$DefaultShadowPk = "7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13"

$ErrorActionPreference = "Stop"

function Require-File($path, $hint) {
    if (-not (Test-Path $path)) { throw "Not found: $path`n  $hint" }
}

# tracing-subscriber may colour structured fields, inserting ANSI escapes
# between "shadow_pk" and "=HEX". Strip them before regex matching.
function Read-ShadowPkFromLog([string]$path) {
    if (-not (Test-Path $path)) { return $null }
    try {
        $fs = [System.IO.File]::Open(
            $path,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::ReadWrite)
        try {
            $sr = New-Object System.IO.StreamReader($fs)
            $raw = $sr.ReadToEnd()
            $sr.Close()
        } finally { $fs.Close() }
    } catch { return $null }
    $plain = $raw -replace '\x1b\[[0-9;]*m', ''
    if ($plain -match 'shadow_pk=([0-9a-f]{64})') { return $matches[1] }
    return $null
}

function Wait-UdpPortBound([int]$port, [int]$seconds) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline) {
        $ep = Get-NetUDPEndpoint -LocalPort $port -ErrorAction SilentlyContinue
        if ($ep) { return $true }
        Start-Sleep -Milliseconds 150
    }
    return $false
}

Require-File $Tshark "Install Wireshark (https://www.wireshark.org)."
Require-File $Dumpcap "Install Wireshark (includes dumpcap)."
Require-File $Chrome "Install Google Chrome or pass -Chrome <path>."
Require-File $Cert "Generate testdata\cert.pem (see README) or pass -Cert <path>."
Require-File $Key "Generate testdata\key.pem (see README) or pass -Key <path>."

$srvExe = "target\debug\prism-server.exe"
$cliExe = "target\debug\prism-client.exe"
Require-File $srvExe "Build first: cargo build -p prism-server --features quiche-backend"
Require-File $cliExe "Build first: cargo build -p prism-client --features quiche-backend"

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$chromePcap = Join-Path $OutDir "chrome_h3.pcapng"
$prismPcap = Join-Path $OutDir "prism.pcapng"

# --- Resolve capture interfaces -------------------------------------------
function Find-LoopbackDevice {
    $lines = & $Tshark -D 2>$null
    foreach ($l in $lines) {
        if ($l -match "NPF_Loopback" -or $l -match "[Ll]oopback") {
            if ($l -match "(\\Device\\NPF_[^\s]+)") { return $matches[1] }
        }
    }
    throw "No loopback capture adapter found. Install Npcap with loopback support."
}

$loopDev = Find-LoopbackDevice
Write-Host "[*] Loopback device : $loopDev" -ForegroundColor Cyan

# --- Capture 1: Chrome HTTP/3 ClientHello on loopback ---------------------
# We force Chrome QUIC at a local UDP sink and capture on the loopback adapter.
# This is deterministic and routing/VPN-independent: the JA4 fingerprint of the
# ClientHello is identical regardless of destination (SNI is always present).
# A tiny UDP sink on $ChromeSinkPort avoids ICMP port-unreachable so Chrome
# emits (and retransmits) its Initial. NOTE: Start-Process (Windows PowerShell
# 5.1) does not auto-quote array elements with spaces, so filters are pre-quoted.
Write-Host "[*] Capturing Chrome h3 ClientHello on loopback udp/$ChromeSinkPort ..." -ForegroundColor Green

$sink = Start-Job -ArgumentList $ChromeSinkPort -ScriptBlock {
    param($port)
    $u = New-Object System.Net.Sockets.UdpClient($port)
    $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt 20) {
        try { if ($u.Available -gt 0) { $null = $u.Receive([ref]$ep) } else { Start-Sleep -Milliseconds 50 } } catch {}
    }
    $u.Close()
}
Start-Sleep -Milliseconds 500

$dump = Start-Process -FilePath $Dumpcap -PassThru -NoNewWindow -ArgumentList @(
    "-i", $loopDev,
    "-f", "`"udp port $ChromeSinkPort`"",
    "-a", "duration:$ChromeSeconds",
    "-w", "`"$chromePcap`""
)
Start-Sleep -Milliseconds 800

$chromeProfile = Join-Path $env:TEMP ("prism-chrome-" + [guid]::NewGuid().ToString("N"))
$chromeArgs = @(
    "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
    "--enable-quic",
    "--host-resolver-rules=`"MAP $ChromeDecoyName 127.0.0.1`"",
    "--origin-to-force-quic-on=$($ChromeDecoyName):$ChromeSinkPort",
    "--ignore-certificate-errors",
    "--user-data-dir=`"$chromeProfile`"",
    "https://$($ChromeDecoyName):$ChromeSinkPort/"
)
$chrome = Start-Process -FilePath $Chrome -PassThru -ArgumentList $chromeArgs -WindowStyle Hidden

$dump.WaitForExit()
try { if ($chrome -and -not $chrome.HasExited) { $chrome.Kill() } } catch {}
Stop-Job $sink -ErrorAction SilentlyContinue; Remove-Job $sink -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 300
Remove-Item -Recurse -Force $chromeProfile -ErrorAction SilentlyContinue
Write-Host "[*] Wrote $chromePcap" -ForegroundColor Green

# --- Capture 2: PRISM client<->server on loopback -------------------------
Get-Process prism-server,prism-client -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 400

Write-Host "[*] Capturing PRISM on loopback udp/$ServerPort for ${PrismSeconds}s ..." -ForegroundColor Green
$dump2 = Start-Process -FilePath $Dumpcap -PassThru -NoNewWindow -ArgumentList @(
    "-i", $loopDev,
    "-f", "`"udp port $ServerPort`"",
    "-a", "duration:$PrismSeconds",
    "-w", "`"$prismPcap`""
)
Start-Sleep -Milliseconds 800

# Start the PRISM server with a fixed shadow key, capture its stdout to read
# back the published shadow_pk for the client.
$srvOut = Join-Path $OutDir "server.log"
$srvErr = Join-Path $OutDir "server.err.log"
Remove-Item $srvOut, $srvErr -ErrorAction SilentlyContinue
# Plain logs: easier to grep and avoids ANSI between field name and value.
$env:NO_COLOR = "1"
$workDir = (Get-Location).Path
$server = Start-Process -FilePath (Join-Path $workDir $srvExe) -PassThru -NoNewWindow `
    -WorkingDirectory $workDir `
    -RedirectStandardOutput $srvOut -RedirectStandardError $srvErr -ArgumentList @(
        "--listen", "127.0.0.1:$ServerPort",
        "--decoy", $DecoyHost,
        "--shadow-sk", $ShadowSk,
        "--cert", (Join-Path $workDir $Cert),
        "--key", (Join-Path $workDir $Key)
    )

# Wait for the server to bind UDP and publish shadow_pk. For the default test
# ShadowSk the public key is precomputed (stdout may be block-buffered when
# redirected). Custom ShadowSk values still fall back to log parsing.
$shadowPk = $null
if ($ShadowSk -eq "1111111111111111111111111111111111111111111111111111111111111111") {
    $shadowPk = $DefaultShadowPk
}
$ready = Wait-UdpPortBound $ServerPort 20
if (-not $ready -or $server.HasExited) {
    try { if (-not $server.HasExited) { $server.Kill() } } catch {}
    throw "PRISM server failed to bind udp/$ServerPort (exited=$($server.HasExited); see $srvOut and $srvErr)"
}
if (-not $shadowPk) {
    $deadline = (Get-Date).AddSeconds(20)
    while ((Get-Date) -lt $deadline -and -not $shadowPk) {
        Start-Sleep -Milliseconds 200
        if ($server.HasExited) { break }
        foreach ($f in @($srvErr, $srvOut)) {
            $shadowPk = Read-ShadowPkFromLog $f
            if ($shadowPk) { break }
        }
    }
}
if (-not $shadowPk) {
    try { if (-not $server.HasExited) { $server.Kill() } } catch {}
    $hint = if ($server.HasExited) { "server exited early; see $srvOut and $srvErr" } else { "see $srvOut and $srvErr" }
    throw "Server did not publish shadow_pk within 20s ($hint)"
}
Write-Host "[*] shadow_pk = $shadowPk" -ForegroundColor Cyan

# Run the client to generate PRISM traffic. In bulk mode the client streams
# morph-shaped datagrams for (PrismSeconds - 1)s so the capture is a
# representative size/IAT sample; otherwise it sends a fixed burst of $Count.
$cliOut = Join-Path $OutDir "client.log"
Remove-Item $cliOut -ErrorAction SilentlyContinue
$cliArgs = @(
    "--server", "127.0.0.1:$ServerPort",
    "--shadow-pk", $shadowPk,
    "--decoy", $DecoyHost
)
if ($Bulk) {
    $bulkSecs = [Math]::Max(2, $PrismSeconds - 1)
    $cliArgs += @("--bulk", $bulkSecs)
} else {
    $cliArgs += @("--count", $Count)
}
$client = Start-Process -FilePath $cliExe -PassThru -NoNewWindow `
    -RedirectStandardOutput $cliOut -RedirectStandardError (Join-Path $OutDir "client.err.log") -ArgumentList $cliArgs
try { $client.WaitForExit(($PrismSeconds + 5) * 1000) | Out-Null } catch {}

$dump2.WaitForExit()
try { if (-not $client.HasExited) { $client.Kill() } } catch {}
try { if (-not $server.HasExited) { $server.Kill() } } catch {}
Write-Host "[*] Wrote $prismPcap" -ForegroundColor Green

Write-Host ""
Write-Host "Done. Next:" -ForegroundColor Green
Write-Host "  .\scripts\extract_ja4.ps1 -Pcap $chromePcap -Out $OutDir\chrome.ja4"
Write-Host "  .\scripts\extract_ja4.ps1 -Pcap $prismPcap  -Out $OutDir\prism.ja4"
Write-Host "  python scripts\summarize_capture.py $chromePcap down > $OutDir\chrome_baseline.json"
Write-Host "  python scripts\summarize_capture.py $prismPcap  down > $OutDir\prism_capture.json"
Write-Host "  cargo run -p prism-eval -- $OutDir\chrome_baseline.json $OutDir\prism_capture.json"
Write-Host "  python scripts\ja4_compare.py $OutDir\chrome.ja4 $OutDir\prism.ja4"
