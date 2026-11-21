## Quick start

### Prerequisites

- **Bash and grep** (on Windows, use Git Bash).
- **Go 1.23 or later** and a **C compiler** for `blst`. Check that `go env CGO_ENABLED` prints `1`. If it prints `0`, run `export CGO_ENABLED=1` after installing the compiler.
  - **macOS:** Run `xcode-select --install`.
  - **Ubuntu/Debian:** Run `sudo apt install build-essential`.
  - **Windows:** Install MinGW-w64 GCC and add its `bin` directory to your `PATH`.
- **Node.js 18 or later** with **npm**. Make sure `go`, `node` and `npm` are available in your terminal.
- **Internet access** to download dependencies and reach the XRPL Testnet via JSON-RPC and WebSocket. The demo uses the Testnet faucet to fund its accounts automatically.

### Run

Extract the project, open a terminal in the folder containing `go.mod`, and run:

```bash
bash ./run_all.sh
```

The script installs the Go and npm dependencies, uses the included global CRS, runs the tests and checks, executes the XRPL Testnet demo, and finishes with benchmarks. A successful run ends with `ALL CHECKS PASSED.`
