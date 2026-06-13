$ErrorActionPreference = "Stop"

$workspaceRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $workspaceRoot

Write-Host "Starting NetSentinel desktop app..." -ForegroundColor Cyan
cargo run -p netsentinel-desktop
