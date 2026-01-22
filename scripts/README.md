# Server Scripts

Helper scripts for running the zid server.

## Development

### Windows (PowerShell)

```powershell
# Basic dev server (auto-generates session key)
.\scripts\dev.ps1

# With persistent key (tokens survive restarts)
.\scripts\dev.ps1 -Key "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

# Custom bind address
.\scripts\dev.ps1 -Bind "0.0.0.0:8080"

# Verbose logging
.\scripts\dev.ps1 -LogLevel "zid_server=trace,tower_http=trace"
```

### Linux/macOS

```bash
# Make executable (first time only)
chmod +x scripts/dev.sh

# Basic dev server
./scripts/dev.sh

# With persistent key
SERVICE_MASTER_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef ./scripts/dev.sh

# Custom settings
BIND_ADDRESS=0.0.0.0:8080 RUST_LOG=trace ./scripts/dev.sh
```

## Production

### Windows (PowerShell)

```powershell
# Generate a secure key first
$key = -join ((1..64) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })
Write-Host "Your key: $key"

# Run production server
.\scripts\prod.ps1 -Key $key
```

### Linux/macOS

```bash
# Make executable (first time only)
chmod +x scripts/prod.sh

# Generate a secure key
export SERVICE_MASTER_KEY=$(openssl rand -hex 32)

# Run production server
./scripts/prod.sh
```

## Environment Variables

| Variable | Dev Default | Prod Default | Description |
|----------|-------------|--------------|-------------|
| `RUN_MODE` | `dev` | `prod` | Runtime mode |
| `SERVICE_MASTER_KEY` | (auto-generated) | (required) | 64-char hex key |
| `BIND_ADDRESS` | `127.0.0.1:9999` | `0.0.0.0:9999` | Listen address |
| `RUST_LOG` | `debug` | `info` | Log level |
| `DATABASE_PATH` | `./data/zid.db` | `./data/zid.db` | RocksDB path |

## Testing the Server

```bash
# Health check
curl http://127.0.0.1:9999/health

# Create identity (using client)
cargo run -p zid-client -- create-identity -d "Test Device"

# Create identity with PQ keys
cargo run -p zid-client -- create-identity -d "PQ Device" -k pq-hybrid
```
