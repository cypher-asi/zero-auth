# Production Server Script for Windows PowerShell
# Usage: .\scripts\prod.ps1 -Key "your-64-char-hex-key"

param(
    [Parameter(Mandatory=$true)]
    [string]$Key,
    [string]$Bind = "0.0.0.0:9999",
    [string]$LogLevel = "zid_server=info,tower_http=info"
)

$ErrorActionPreference = "Stop"

Write-Host "=== zid Production Server ===" -ForegroundColor Cyan

# Validate key length
if ($Key.Length -ne 64) {
    Write-Host "ERROR: SERVICE_MASTER_KEY must be 64 hex characters (32 bytes)" -ForegroundColor Red
    Write-Host "Generate one with: -join ((1..64) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })" -ForegroundColor Yellow
    exit 1
}

# Set prod mode
$env:RUN_MODE = "prod"
$env:SERVICE_MASTER_KEY = $Key
$env:RUST_LOG = $LogLevel
$env:BIND_ADDRESS = $Bind

Write-Host "Bind Address: $Bind" -ForegroundColor Gray
Write-Host "Log Level: $LogLevel" -ForegroundColor Gray
Write-Host ""

# Run the server in release mode
cargo run -p zid-server --release
