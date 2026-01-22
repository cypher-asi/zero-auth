# Dev Server Script for Windows PowerShell
# Usage: .\scripts\dev.ps1
# Or with persistent key: .\scripts\dev.ps1 -Key "your-64-char-hex-key"

param(
    [string]$Key = "",
    [string]$Bind = "127.0.0.1:9999",
    [string]$LogLevel = "zid_server=debug,tower_http=debug"
)

$ErrorActionPreference = "Stop"

Write-Host "=== zid Dev Server ===" -ForegroundColor Cyan

# Set dev mode
$env:RUN_MODE = "dev"
$env:RUST_LOG = $LogLevel
$env:BIND_ADDRESS = $Bind

# Set master key if provided
if ($Key) {
    $env:SERVICE_MASTER_KEY = $Key
    Write-Host "Using provided SERVICE_MASTER_KEY" -ForegroundColor Green
} else {
    # Remove any existing key to trigger auto-generation
    Remove-Item Env:SERVICE_MASTER_KEY -ErrorAction SilentlyContinue
    Write-Host "Auto-generating SERVICE_MASTER_KEY for this session" -ForegroundColor Yellow
}

Write-Host "Bind Address: $Bind" -ForegroundColor Gray
Write-Host "Log Level: $LogLevel" -ForegroundColor Gray
Write-Host ""

# Run the server
cargo run -p zid-server
