# Reproduces the vendored quiche + BoringSSL fork that PRISM builds against.
#
#   .\scripts\vendor-quiche.ps1
#
# Clones quiche at the pinned tag (recursively, to pull BoringSSL) into
# third_party/quiche, then applies the PRISM fork patches from patches/.
# third_party/ is git-ignored because BoringSSL is too large to commit; the
# patches that turn stock quiche into the PRISM fork are tracked in patches/.

$ErrorActionPreference = 'Stop'

$QuicheTag = '0.22.0'
$Root      = Split-Path -Parent $PSScriptRoot
$Dest      = Join-Path $Root 'third_party\quiche'
$Patches   = Join-Path $Root 'patches'

if (Test-Path $Dest) {
    Write-Host "third_party/quiche already exists; remove it to re-vendor." -ForegroundColor Yellow
    return
}

New-Item -ItemType Directory -Force -Path (Join-Path $Root 'third_party') | Out-Null

Write-Host "Cloning quiche $QuicheTag (recursive, with BoringSSL)..." -ForegroundColor Cyan
git clone --depth 1 --branch $QuicheTag --recursive --shallow-submodules `
    https://github.com/cloudflare/quiche $Dest

# Apply the PRISM fork patches. 0001 patches quiche itself (TLS exporter, frame
# padding to a morph target, explicit PING). 0002 patches the vendored BoringSSL
# submodule (X25519 key_share ephemeral injection for Reality auth).
$bsslDir = Join-Path $Dest 'quiche\deps\boringssl'
$patchMap = @(
    @{ File = '0001-prism-quiche-fork.patch';            Dir = $Dest },
    @{ File = '0002-prism-boringssl-x25519-offer.patch'; Dir = $bsslDir }
)
foreach ($p in $patchMap) {
    $patchPath = Join-Path $Patches $p.File
    if (Test-Path $patchPath) {
        Write-Host "Applying $($p.File) in $($p.Dir)..." -ForegroundColor Cyan
        git -C $p.Dir apply --whitespace=nowarn $patchPath
    }
}

Write-Host "Vendored quiche fork ready at $Dest" -ForegroundColor Green
