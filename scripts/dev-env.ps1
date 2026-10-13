# Sets up a build environment for the quiche/BoringSSL (quiche-backend) build on
# Windows. Dot-source this before running `cargo build --features quiche-backend`:
#
#   # If scripts are blocked (ExecutionPolicy), run once per session:
#   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
#   . .\scripts\dev-env.ps1
#   cargo build -p prism-quic --features quiche-backend
#
#
# It imports the MSVC environment (vcvars64) and puts cargo, cmake, nasm, perl
# and go on PATH — everything quiche needs to compile its vendored BoringSSL.

$ErrorActionPreference = 'Stop'

function Import-VcVars {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vswhere)) { throw "vswhere not found; install VS Build Tools" }
    $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $vsPath) {
        # Fall back to the known BuildTools path.
        $vsPath = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"
    }
    $vcvars = Join-Path $vsPath "VC\Auxiliary\Build\vcvars64.bat"
    if (-not (Test-Path $vcvars)) { throw "vcvars64.bat not found at $vcvars" }

    # Capture the environment vcvars64 produces and import it into this session.
    cmd /c "`"$vcvars`" >nul 2>&1 && set" | ForEach-Object {
        if ($_ -match '^([^=]+)=(.*)$') {
            Set-Item -Path "Env:$($matches[1])" -Value $matches[2]
        }
    }
}

function Add-ToolPath {
    # Highest priority first. The dedicated CMake and NASM must win over the
    # copies Strawberry Perl bundles in C:\Strawberry\c\bin (those ship a gcc
    # that can confuse BoringSSL's compiler detection). Strawberry is only used
    # for perl, so it is deliberately omitted from PATH here.
    $tools = @(
        "$env:USERPROFILE\.cargo\bin",
        "C:\Program Files\CMake\bin",
        "$env:LOCALAPPDATA\bin\NASM",
        "C:\Strawberry\perl\bin",
        "C:\Program Files\Go\bin"
    )
    # Build the prefix in priority order, then prepend it once.
    $prefix = @()
    foreach ($t in $tools) {
        if ((Test-Path $t) -and ($env:Path -notlike "*$t*")) { $prefix += $t }
    }
    if ($prefix.Count -gt 0) {
        $env:Path = ($prefix -join ';') + ';' + $env:Path
    }
}

Import-VcVars
Add-ToolPath

Write-Host "PRISM dev-env ready:" -ForegroundColor Green
foreach ($t in @('cl','cmake','nasm','perl','go','cargo','rustc')) {
    $c = Get-Command $t -ErrorAction SilentlyContinue
    if ($c) {
        $src = if ($c.Source) { $c.Source } else { $c.Name }
        Write-Host ("  {0,-6} {1}" -f $t, $src)
    } else {
        Write-Host ("  {0,-6} MISSING" -f $t) -ForegroundColor Yellow
    }
}
