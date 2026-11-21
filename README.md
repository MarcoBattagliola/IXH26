# Hackaton2026 — Cryptographic photo provenance on XRPL

A Go prototype (BLS12-381 via [`blst`](https://github.com/supranational/blst)) that binds a captured image to:

- two hardware-certified signing layers (sensor and Secure Enclave), proven in zero knowledge with Groth–Sahai;
- a public manifest signed by a certificate authority;
- a timestamp anchored to the latest **validated XRPL ledger**.

The verifier (PCC) can confirm that a capture was signed by certified hardware, under an authentic manifest, and **not before** a specific XRPL ledger. It learns none of the device keys or certificates.

## How it works

1. **CA1** and **CA2** certify the public keys of the sensor (`E_s = x_s·P1`) and of the enclave (`E_e = x_e·P1`) with Jutla–Roy structure-preserving signatures.
2. **CA3** signs the canonical manifest with a public Schnorr signature `(R_3, z_3)`. The PCC checks it outside the NIZK.
3. The device fetches the latest validated XRPL ledger and encodes it as the timestamp `T0`.
4. The capture message is `M = HashToG1(bits, manifest, T0)`, using IETF hash-to-curve with an application-specific DST and length-prefixed encoding.
5. The **sensor** signs `M` with Schnorr: `R_s = k_s·P1`, `c_s = H("SENSOR", M, R_s)`, `z_s = k_s + c_s·x_s`.
6. The **enclave** signs `M` too, and binds the sensor nonce: `c_e = H("ENCLAVE", M, R_s, R_e)`, `z_e = k_e + c_e·x_e`.
7. A trusted prover builds the Groth–Sahai proof. The hidden witness is the two layer keys, the two JR certificates and `z_s, z_e`. It also adds a Fiat–Shamir proof of knowledge of the scalar openings.
8. The **PCC** pins CA1/CA2/CA3 keys and the global CRS, and then:
   - verifies the CA3 signature;
   - re-fetches the XRPL ledger by hash;
   - recomputes `M`;
   - verifies the NIZK.

Inside Groth–Sahai the circuit has 4 pairing-product equations, which check the two JR certificates, and 2 multi-scalar equations, which check the two Schnorr relations `z·P1 − c·E = R`.

## XRPL-anchored timestamp (T0)

`T0` is a fixed 78-byte encoding of the latest **validated** ledger (`capture/XRPLAnchor.go`):

```
"HACKATON2026_XRPL_LEDGER_ANCHOR_V1" || NetworkID (u32) || ledger_index (u32)
  || ledger_hash (32 B) || close_time (u32, seconds since 2000-01-01 UTC)
```

- **Device:** `capture.NewCaptureTimestamp(ctx, src, capture.DefaultLedgerMaxAge)` calls the rippled `ledger` method with `ledger_index: "validated"`. If the ledger's close time is more than 30 s from the local clock, it rejects the ledger.
- **PCC:** `capture.CaptureVerifyAnchoredTrusted(ctx, src, anchor, ...)` re-fetches the ledger **by hash** from a node and network the PCC chooses itself. It checks index, close time and network, then runs the full capture verification. It returns the verified ledger: `Time()` is a lower bound on the capture time.
- `ledger_hash` commits to the ledger header, which includes `close_time`. `M` depends on `T0`, and every challenge depends on `M`, so the anchor cannot be swapped after signing.

```go
src := capture.NewXRPLClient(capture.XRPLTestnetRPC, capture.XRPLNetworkTestnet)
t0, ledger, err := capture.NewCaptureTimestamp(ctx, src, capture.DefaultLedgerMaxAge)
m, err := capture.HashCaptureToG1(bits, bitCount, manifest, t0)
```

## Running

Requirements:
- Go 1.23+.
- A C compiler, because `blst` uses cgo: `xcode-select --install` on macOS, MinGW gcc on Windows/Git Bash.
- Internet access, for the demo only.

```bash
bash ./run_all.sh        # format, tests, x5 runs, vet, fuzzing, demo, benchmarks
```

Or step by step:

```bash
go test ./... -count=1                     # offline: XRPL is mocked locally
go run ./cmd/capture-demo                  # XRPL testnet (port 51234)
go run ./cmd/capture-demo -xrpl-rpc https://xrplcluster.com -xrpl-network 0   # mainnet (port 443)
```

If your network blocks port 51234, use the mainnet endpoint. Through the script, run `CAPTURE_DEMO_FLAGS='-xrpl-rpc https://xrplcluster.com -xrpl-network 0' bash ./run_all.sh`.

Focused tests:

```bash
go test ./capture -run 'TestLedgerAnchor|TestCaptureTimestampFreshness|TestVerifyLedgerAnchor|TestXRPLClient|TestCaptureVerifyAnchoredTrusted' -v
go test ./capture -run 'TestManifestCA3|TestPCCRejectsWrongCA3' -v
```

Benchmarks:

```bash
go test ./capture -run '^$' -bench 'Benchmark(ManifestCA3Sign|ManifestCA3Verify|JRSign|JRVerify|LayerSensorSign|LayerEnclaveSign|CaptureProve|CaptureVerify)$' -benchmem
```

## Global CRS

The Groth–Sahai CRS is a single SXDH soundness-mode CRS. It is generated once and pinned by its SHA-256 hash in `capture/global_crs_generated.go`.

- **Do not regenerate it** and do not create one per device. Every device and the PCC must use the same file.
- `run_all.sh` refuses to run if it finds the empty placeholder. Creating a new CRS is only for a genuinely new ecosystem: `HACKATON_ALLOW_NEW_GLOBAL_CRS=1 bash ./run_all.sh`.
- Check the pinned fingerprint with `grep globalCRSSHA256 capture/global_crs_generated.go`.

## Sizes (BLS12-381, compressed)

| Component | Bytes | Notes |
|---|---:|---|
| Groth–Sahai core | 4,416 | |
| Proof of knowledge of Schnorr openings | 512 | Fiat–Shamir |
| **Full NIZK** | **4,928** | |
| Sensor + enclave public nonces | 96 | |
| CA3 manifest signature (Schnorr) | 80 | |
| **Per-capture crypto overhead** | **5,104** | NIZK + nonces + CA3 signature |
| XRPL anchor `T0` | 78 | Public, stored in the DNG |
| CA3 verification key | 48 | Shared, not per photo |
| CA1/CA2 JR verification key | 672 each | Shared, not per photo |
| JR certificate | 336 | Hidden inside the NIZK |
| Global CRS | 576 | Shared, not per photo |

## Project layout

```
capture/        protocol: JR, layer Schnorr, CA3 Schnorr, Groth–Sahai, hash-to-curve, XRPL anchor, trust anchor
cmd/capture-demo   end-to-end demo with a live XRPL ledger
cmd/crs-setup      one-time global CRS ceremony (prototype)
equations/      toy linear-exponent circuit used in tests
```

## Security notes and limitations

- **Timestamp:** the XRPL anchor proves only that the capture was signed **no earlier than** that ledger. A device can hold a photo and sign it later with a fresh anchor. An upper bound would need `H(M)` published in a later XRPL transaction, which is not implemented. The 30 s freshness check runs on the device, which trusts its own RPC node and clock.
- **Trust anchors:** the PCC must get the CA keys, the CRS and its XRPL node from authenticated sources, never from the artifact under verification. Public testnet nodes keep limited history; old captures need a full-history node.
- **Trusted setup:** the CRS needs an honest ceremony with its trapdoors erased. A fingerprint does not prove that.
- **Hardware:** sensor, enclave and TEE are simulated in one Go process. In production, `z_s, z_e` must never reach the untrusted OS, since anyone holding them recovers the layer public keys.
- **Proofs:** `ForgeCapture` unforgeability, simulation-extractability and the security of the composed GS + Fiat–Shamir NIZK are not formally proven. Groth–Sahai proofs may be malleable. This is a research prototype, not production code.
