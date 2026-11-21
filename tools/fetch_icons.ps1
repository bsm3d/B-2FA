<#
.SYNOPSIS
  Install the 2FAS logo pack for B-2FA (run it once, needs git).

.DESCRIPTION
  Downloads only parsers/src/main/assets of the 2FAS Android repository (about 13 MB of PNG plus
  services.json) into a throw-away temporary folder, then copies services.json and the PNGs to
  %APPDATA%\BSM\B-2FA\icons (or $env:B2FA_HOME\icons). B-2FA itself never uses the network.

  The 2FAS README says their graphics are not under the GPL and have their own terms: keep this
  pack for your own use and do not ship it with B-2FA.

.PARAMETER Source
  A folder that already holds services.json and icons\ (no download).
#>
param([string]$Source)

$ErrorActionPreference = 'Stop'
$repo = 'https://github.com/twofas/2fas-android.git'
$assets = 'parsers/src/main/assets'
$dest = if ($env:B2FA_HOME) { Join-Path $env:B2FA_HOME 'icons' } else { Join-Path $env:APPDATA 'BSM\B-2FA\icons' }

$tmp = $null
try {
    if (-not $Source) {
        if (-not (Get-Command git -ErrorAction SilentlyContinue)) { throw 'git is needed to download the pack.' }
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ('b2fa-icons-' + [guid]::NewGuid().ToString('N'))
        Write-Host 'Downloading the 2FAS asset folder (about 13 MB)...'
        git clone --depth 1 --filter=blob:none --sparse $repo (Join-Path $tmp 'repo') 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'git clone failed.' }
        git -C (Join-Path $tmp 'repo') sparse-checkout set $assets 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'git sparse-checkout failed.' }
        $Source = Join-Path (Join-Path $tmp 'repo') ($assets -replace '/', '\')
    }
    $services = Join-Path $Source 'services.json'
    $pngs = @(Get-ChildItem -LiteralPath (Join-Path $Source 'icons') -Filter '*.png' -ErrorAction SilentlyContinue |
              Where-Object { $_.Name -match '^[0-9a-fA-F-]{36}\.png$' })
    if (-not (Test-Path -LiteralPath $services) -or $pngs.Count -eq 0) { throw 'The source does not look like the 2FAS asset folder.' }
    $list = Get-Content -LiteralPath $services -Raw -Encoding UTF8 | ConvertFrom-Json   # must at least be valid JSON
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    foreach ($p in $pngs) { Copy-Item -LiteralPath $p.FullName -Destination (Join-Path $dest $p.Name) -Force }
    Copy-Item -LiteralPath $services -Destination (Join-Path $dest 'services.json') -Force
    Write-Host ("Installed {0} logos for {1} services into {2}" -f $pngs.Count, @($list).Count, $dest)
}
finally {
    if ($tmp -and (Test-Path -LiteralPath $tmp)) {
        # git marks its objects read-only
        Get-ChildItem -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object { try { $_.Attributes = 'Normal' } catch {} }
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}
