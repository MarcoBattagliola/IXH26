#!/usr/bin/env bash
# Hackaton2026 — CA1/CA2 Jutla–Roy, CA3 public Schnorr,
# sensor/enclave hidden Schnorr, Groth–Sahai, globally pinned SXDH CRS.
# Windows Git Bash: bash ./run_all.sh
# The demo (step 7) needs Internet access to the XRPL testnet. Override with e.g.
# XRPL_REGISTRY_SEED=<funded mainnet seed> XRPL_REGISTRY_SIGNER_SEEDS=<seed1,seed2> XRPL_SEED=<funded mainnet seed> CAPTURE_DEMO_FLAGS='-xrpl-rpc https://xrplcluster.com -xrpl-wss wss://xrplcluster.com -xrpl-network 0' bash ./run_all.sh
# The T1 submitter needs Node.js (>= 18); dependencies are installed in step 7.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

echo '===== [1/8] Go environment ====='
go version

echo '===== [2/8] Format / dependencies / pinned global CRS ====='
gofmt -w capture/*.go equations/*.go cmd/capture-demo/main.go cmd/crs-setup/main.go
go mod tidy
if grep -q 'const globalCRSHex = ""' capture/global_crs_generated.go; then
  if [[ "${HACKATON_ALLOW_NEW_GLOBAL_CRS:-0}" == "1" ]]; then
    echo 'EXPLICIT NEW CRS SETUP requested: do this only for a genuinely NEW ecosystem.'
    go run ./cmd/crs-setup
  else
    echo 'ERROR: this copy has the EMPTY CRS placeholder.' >&2
    echo 'Copy capture/global_crs_generated.go from your PREVIOUS working project' >&2
    echo 'to this project BEFORE running tests, so the global CRS stays identical.' >&2
    echo 'Only for an independent first-ever ecosystem setup, run:' >&2
    echo '  HACKATON_ALLOW_NEW_GLOBAL_CRS=1 bash ./run_all.sh' >&2
    exit 1
  fi
else
  echo 'Using the existing pinned global CRS; it will NOT be regenerated.'
fi

echo '===== [3/8] Full test suite with real blst ====='
go test ./... -v -count=1

echo '===== [4/8] Five independent test runs ====='
go test ./... -count=5

echo '===== [5/8] Go vet ====='
go vet ./...

echo '===== [6/8] Proof and public CA3 signature decoder fuzzing ====='
go test ./capture -run '^$' -fuzz '^FuzzCaptureProofDecode$' -fuzztime=15s
go test ./capture -run '^$' -fuzz '^FuzzManifestCASignatureDecode$' -fuzztime=8s

echo '===== [7/8] Full capture demo (CA registry, T0, T1, revocation) and exact serialized sizes ====='
npm --prefix tools/t1-submit ci --no-audit --no-fund
# shellcheck disable=SC2086
go run ./cmd/capture-demo ${CAPTURE_DEMO_FLAGS:-}

echo '===== [8/8] CA3 / JR / layer / GS benchmarks ====='
go test ./capture -run '^$' -bench 'Benchmark(ManifestCA3Sign|ManifestCA3Verify|JRSign|JRVerify|LayerSensorSign|LayerEnclaveSign|CaptureProve|CaptureVerify)$' -benchmem -benchtime=1s -count=1

echo 'ALL CHECKS PASSED.'
