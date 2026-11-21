<#
.SYNOPSIS
  Build B-2FA, run the tests, check the program, and make the installer and the portable zip.

.DESCRIPTION
  Needs Visual Studio 2022 Build Tools (C++), CMake, and Inno Setup 6 (only for the installer).
  The program is one static executable: no DLL to ship, no runtime to install.
  Output goes to ..\distributions\B-2FA\ (next to the project), build files to .\build.

.PARAMETER SkipTests
  Do not run the tests.
.PARAMETER NoInstaller
  Build and check only.
#>
param([switch]$SkipTests, [switch]$NoInstaller)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$build = Join-Path $root 'build'
$out = Join-Path (Split-Path -Parent $root) 'distributions\B-2FA'
$version = (Select-String -Path (Join-Path $root 'src\version.h') -Pattern 'kVersionA = "([0-9.]+)"').Matches[0].Groups[1].Value
Write-Host "B-2FA $version"

# ---- build ----------------------------------------------------------------------------
cmake -S $root -B $build -G 'Visual Studio 17 2022' -A x64 | Out-Host
if ($LASTEXITCODE -ne 0) { throw 'cmake configure failed' }
cmake --build $build --config Release | Out-Host
if ($LASTEXITCODE -ne 0) { throw 'build failed' }
$exe = Join-Path $build 'Release\B-2FA.exe'
$tests = Join-Path $build 'Release\b2tests.exe'

# ---- tests ----------------------------------------------------------------------------
if (-not $SkipTests) {
    & $tests | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'tests failed' }
}

# ---- check what the program depends on ------------------------------------------------------
# A static build must not import any runtime DLL. Import names are plain ASCII in the file.
$bytes = [IO.File]::ReadAllBytes($exe)
$ascii = [Text.Encoding]::ASCII.GetString($bytes)
$dlls = [regex]::Matches($ascii, '[A-Za-z0-9_\-]{3,40}\.dll') | ForEach-Object { $_.Value.ToLowerInvariant() } | Sort-Object -Unique
Write-Host ("Imports: " + ($dlls -join ', '))
$forbidden = $dlls | Where-Object { $_ -match '^(vcruntime|msvcp|msvcr|ucrtbase|api-ms-win-crt|python|qt\d|libcrypto|libssl)' }
if ($forbidden) { throw ("The program imports runtime DLLs it must not need: " + ($forbidden -join ', ')) }
foreach ($needle in @('.pyc', 'python3')) { if ($ascii.Contains($needle)) { throw "Unexpected '$needle' in the program" } }
if ((Get-Item $exe).Length -gt 4MB) { throw 'The program is unexpectedly big' }
Write-Host ("Program: {0:N0} bytes, no runtime DLL needed" -f (Get-Item $exe).Length)

if ($NoInstaller) { return }

# ---- installer and portable zip ----------------------------------------------------------------
$iscc = @("$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe", "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe") |
        Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw 'Inno Setup 6 not found (ISCC.exe)' }
New-Item -ItemType Directory -Force -Path $out | Out-Null
& $iscc "/DAppVersion=$version" "/DSourceDir=$(Split-Path $exe)" "/DOutDir=$out" (Join-Path $root 'packaging\B-2FA.iss') | Out-Host
if ($LASTEXITCODE -ne 0) { throw 'installer failed' }

$zip = Join-Path $out "B-2FA-$version-portable.zip"
$stage = Join-Path $build 'portable\B-2FA'
Remove-Item -Recurse -Force (Join-Path $build 'portable') -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $stage | Out-Null
Copy-Item $exe (Join-Path $stage 'B-2FA.exe')
Copy-Item (Join-Path $root 'LICENSE') (Join-Path $stage 'LICENSE')
Remove-Item $zip -ErrorAction SilentlyContinue
Compress-Archive -Path $stage -DestinationPath $zip -CompressionLevel Optimal

Write-Host ''
Get-ChildItem $out -Filter "B-2FA-$version-*" | ForEach-Object {
    "{0}  {1,10:N0} bytes  SHA-256 {2}" -f $_.Name, $_.Length, (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
}
