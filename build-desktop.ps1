$ErrorActionPreference = "Stop"

$workspaceRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $workspaceRoot

Write-Host "Building NetSentinel desktop app (release)..." -ForegroundColor Cyan
cargo build -p netsentinel-desktop --release

$exePath = Join-Path $workspaceRoot "target\release\netsentinel-desktop.exe"
Write-Host "Build complete." -ForegroundColor Green
Write-Host "Run this file to open the desktop app:" -ForegroundColor Green
Write-Host $exePath
