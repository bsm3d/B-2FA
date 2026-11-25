# B-2FA
# © Benoit Saint-Moulin - 2026
# Version du fichier : 1.0.1
# Fonction du fichier : Script that downloads the 2FAS logo pack once from its pinned repository into the B-2FA icons folder.

<#
.SYNOPSIS
  Install the 2FAS logo pack for B-2FA (run it once, needs git).

.DESCRIPTION
  Downloads only parsers/src/main/assets of the 2FAS Android repository (about 13 MB of PNG plus
  services.json) into a throw-away temporary folder, then copies services.json and the PNGs to
  %APPDATA%\BSM\B-2FA\icons (or $env:B2FA_HOME\icons). B-2FA itself never uses the network.

  tools\build.ps1 takes the pack from there to put it in the installer and in the portable zip.

.PARAMETER Source
  A folder that already holds services.json and icons\ (no download).
.PARAMETER Ref
  The commit of the 2FAS repository to take the pack from. It is pinned (31 Oct 2026) so that a later change
  in that repository is never installed unseen. Pass 'HEAD' to take the latest, at your own risk.
#>
param([string]$Source, [string]$Ref = '4ad83b2b94967993db55dd36dcb2e258646eb7b6')

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
        $clone = Join-Path $tmp 'repo'
        # git writes progress to stderr, which Windows PowerShell would turn into an error: judge by the exit code
        function Invoke-Git([string[]]$GitArgs) {
            $old = $ErrorActionPreference
            $ErrorActionPreference = 'Continue'
            & git @GitArgs 2>&1 | Out-Null
            $code = $LASTEXITCODE
            $ErrorActionPreference = $old
            return $code
        }
        if ((Invoke-Git @('clone', '--no-checkout', '--depth', '1', '--filter=blob:none', $repo, $clone)) -ne 0) { throw 'git clone failed.' }
        if ((Invoke-Git @('-C', $clone, 'sparse-checkout', 'set', $assets)) -ne 0) { throw 'git sparse-checkout failed.' }
        if ($Ref -ne 'HEAD') {
            if ((Invoke-Git @('-C', $clone, 'fetch', '--depth', '1', 'origin', $Ref)) -ne 0) { throw "git fetch of $Ref failed." }
            if ((Invoke-Git @('-C', $clone, 'checkout', 'FETCH_HEAD')) -ne 0) { throw 'git checkout failed.' }
        } else {
            if ((Invoke-Git @('-C', $clone, 'checkout', 'HEAD')) -ne 0) { throw 'git checkout failed.' }
        }
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
