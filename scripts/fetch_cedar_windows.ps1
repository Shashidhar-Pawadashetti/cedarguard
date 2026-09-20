# Fetches the official prebuilt cedar-policy-cli Windows x86_64 binary and places
# it in bin/cedar.exe for local Windows development and testing.
#
# Usage:
#   .\scripts\fetch_cedar_windows.ps1 [version]
# Default version: 4.12.0

[CmdletBinding()]
param(
    [string]$Version = "4.12.0"
)

$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$BinDir = Join-Path $RootDir "bin"
$ZipPath = Join-Path $BinDir "cedar-win.zip"
$ExtractDir = Join-Path $BinDir "cedar-temp"

if (!(Test-Path $BinDir)) {
    New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
}

$Url = "https://github.com/cedar-policy/cedar/releases/download/cedar-policy-cli-v${Version}/cedar-policy-cli-x86_64-pc-windows-msvc.zip"
Write-Host "Fetching cedar-policy-cli v${Version} (Windows x86_64) from $Url..."

Invoke-WebRequest -Uri $Url -OutFile $ZipPath

Write-Host "Extracting archive..."
Expand-Archive -Path $ZipPath -DestinationPath $ExtractDir -Force

$CedarExe = Get-ChildItem -Path $ExtractDir -Recurse -Filter "cedar.exe" | Select-Object -First 1
if ($CedarExe) {
    Copy-Item -Path $CedarExe.FullName -Destination (Join-Path $BinDir "cedar.exe") -Force
    Write-Host "Installed: $(Join-Path $BinDir 'cedar.exe')"
} else {
    throw "ERROR: could not locate 'cedar.exe' inside the downloaded archive."
}

Remove-Item -Path $ZipPath, $ExtractDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "Testing cedar.exe..."
& (Join-Path $BinDir "cedar.exe") --version
Write-Host "Ready! You can now run 'python -m pytest -q' and 'python -m cli.main scan ./demo-repo/broken'."
