package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"hackaton2026/crypto/capture"

	blst "github.com/supranational/blst/bindings/go"
)

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	rpcURL := flag.String("xrpl-rpc", capture.XRPLTestnetRPC, "XRPL JSON-RPC endpoint")
	networkID := flag.Uint("xrpl-network", uint(capture.XRPLNetworkTestnet), "XRPL NetworkID of the endpoint (0 mainnet, 1 testnet, 2 devnet)")
	maxAge := flag.Duration("xrpl-max-age", capture.DefaultLedgerMaxAge, "max skew between local clock and ledger close time")
	flag.Parse()

	// T0 = latest validated XRPL ledger. In this demo device and PCC use the
	// same node; in production the PCC pins its own trusted node.
	ledgerSource := capture.NewXRPLClient(*rpcURL, uint32(*networkID))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	timestamp, ledger, err := capture.NewCaptureTimestamp(ctx, ledgerSource, *maxAge)
	if err != nil {
		log.Fatalf("cannot anchor capture to XRPL (%s): %v", *rpcURL, err)
	}
	fmt.Printf("T0 = XRPL network %d ledger #%d hash %X closed %s\n",
		ledger.NetworkID, ledger.LedgerIndex, ledger.LedgerHash, ledger.Time().Format(time.RFC3339))

	//random bit string represent a photo
	bits, err := capture.RandomBitString(256)
	must(err)
	manifest := []byte("factory manifest: two JR-certified hardware signing keys")
	m, err := capture.HashCaptureToG1(bits, 256, manifest, timestamp)
	must(err)
	sensor, err := capture.NewLayerSecret(capture.LayerSensor)
	must(err)
	defer sensor.Clear()
	enclave, err := capture.NewLayerSecret(capture.LayerEnclave)
	must(err)
	defer enclave.Clear()
	e1, err := sensor.PublicKey()
	must(err)
	e2, err := enclave.PublicKey()
	must(err)
	var ca1, ca2 capture.Sk
	var vk1, vk2 capture.Vk
	must(capture.GenerateKeyPair(&ca1, &vk1))
	defer ca1.Clear()
	must(capture.GenerateKeyPair(&ca2, &vk2))
	defer ca2.Clear()
	ca3, vk3, err := capture.NewManifestCAKeyPair()
	must(err)
	defer ca3.Clear()
	var cert1, cert2 capture.Signature
	e1Point := new(blst.P1)
	e1Point.FromAffine(&e1)
	e2Point := new(blst.P1)
	e2Point.FromAffine(&e2)
	must(capture.Sign(&ca1, e1Point, &cert1))
	must(capture.Sign(&ca2, e2Point, &cert2))
	cert3, err := ca3.SignManifest(manifest)
	must(err)
	must(sensor.InstallCertificate(&cert1, &vk1))
	must(enclave.InstallCertificate(&cert2, &vk2))
	must(sensor.CheckInstalledKeyIntegrity())
	must(enclave.CheckInstalledKeyIntegrity())

	// Trusted layer operations. The responses Z must stay out of the DNG.
	sensorAtt, err := sensor.SensorAttest(m.ToAffine())
	must(err)
	defer sensorAtt.Clear()
	enclaveAtt, err := enclave.EnclaveAttest(m.ToAffine(), &sensorAtt.R)
	must(err)
	defer enclaveAtt.Clear()

	crs, err := capture.NewCaptureCRSGlobal()
	must(err)
	statement := capture.CaptureStatement{M: *m.ToAffine(), SensorR: sensorAtt.R, EnclaveR: enclaveAtt.R, VK1: vk1, VK2: vk2}
	witness := capture.CaptureWitness{E1: *e1Point, E2: *e2Point, Sig1: cert1, Sig2: cert2, ZSensor: sensorAtt.Z, ZEnclave: enclaveAtt.Z}
	defer witness.ZSensor.Zeroize()
	defer witness.ZEnclave.Zeroize()
	// DEMO TRUST BOUNDARY: the witness below is assembled in one Go process.
	// Production requires trusted assembly or a separately designed distributed
	// GS prover; do not send the raw responses to an untrusted device OS.
	proof, err := capture.CaptureProve(crs, &statement, &witness)
	must(err)
	serialized, err := proof.MarshalBinary()
	must(err)
	ok, err := capture.CaptureVerifySerialized(crs, &statement, serialized)
	must(err)
	if !ok {
		log.Fatal("Groth-Sahai verifier rejected correct capture")
	}
	anchor, err := capture.NewCaptureTrustAnchor(&vk1, &vk2, &vk3, crs)
	must(err)
	ok, verifiedLedger, err := capture.CaptureVerifyAnchoredTrusted(ctx, ledgerSource, anchor, crs, bits, 256, manifest, timestamp, &cert3, &vk3, &statement, serialized)
	must(err)
	if !ok {
		log.Fatal("trusted PCC verifier rejected correct capture")
	}
	fmt.Printf("PCC: XRPL ledger anchor re-fetched by hash and matched; capture not before %s\n",
		verifiedLedger.Time().Format(time.RFC3339))

	fingerprint, err := capture.GlobalCaptureCRSFingerprint()
	must(err)
	fmt.Println("Verified random-bitstring capture artifact (JR + two hidden Schnorr signatures)")
	fmt.Println("Sensor and enclave private/public consistency + JR certificates: OK")
	fmt.Printf("Pinned global SXDH soundness CRS version: %s\n", capture.GlobalCaptureCRSVersion)
	fmt.Printf("Global CRS SHA-256 fingerprint: %x\n", fingerprint)
	fmt.Printf("Jutla-Roy certificate size: %d bytes per device key (inside NIZK)\n", capture.SignatureCompressedSize)
	fmt.Printf("Jutla-Roy CA1/CA2 VK size: %d bytes each (shared)\n", capture.VkCompressedSize)
	fmt.Printf("CA3 public Schnorr signature: %d bytes\n", capture.ManifestCASignatureSize)
	fmt.Printf("CA3 Schnorr verification key: %d bytes (shared)\n", capture.ManifestCAPublicKeySize)
	fmt.Printf("Public sensor+enclave Schnorr nonces: %d bytes\n", capture.SchnorrPublicNoncesSize)
	fmt.Printf("Groth-Sahai core size: %d bytes\n", capture.CaptureGSCoreBytes)
	fmt.Printf("Schnorr opening knowledge proof size: %d bytes\n", capture.CaptureOpeningPoKBytes)
	fmt.Printf("Complete NIZK size: %d bytes\n", len(serialized))
	fmt.Printf("Proof + public nonces total: %d bytes\n", len(serialized)+capture.SchnorrPublicNoncesSize)
	fmt.Printf("Proof + public nonces + CA3 manifest signature: %d bytes\n", len(serialized)+capture.SchnorrPublicNoncesSize+capture.ManifestCASignatureSize)
	fmt.Printf("Public GS CRS size: %d bytes (shared)\n", capture.CaptureCRSCompressedSize)
	fmt.Printf("XRPL ledger anchor T0: %d bytes (public, in DNG)\n", capture.LedgerAnchorEncodedSize)
	fmt.Println("Neither private signing scalar nor Schnorr response is serialized into the DNG")
}
