# Run Dev Server

Runs the zid-server in development mode with auto-generated master key.

```powershell
$env:RUN_MODE = "dev"
$env:RUST_LOG = "zid_server=debug,tower_http=debug"
cargo run -p zid-server
```
