package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	blst "github.com/supranational/blst/bindings/go"
	"hackaton2026/crypto/capture"
)

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// xrplTool runs tools/t1-submit/submit_t1.mjs (Node + xrpl.js) and decodes
// its JSON stdout.
type xrplTool struct {
	script, wss string
	network     uint32
}

// signer selects who signs a transaction: a single seed, or the multisign
// signers of a governance account.
type signer struct {
	seed    string   // single-signature mode
	account string   // multisign mode: sending account
	signers []string // multisign mode: signer seeds
}

func (sg signer) env() []string {
	if len(sg.signers) > 0 {
		return []string{"XRPL_ACCOUNT=" + sg.account, "XRPL_SIGNER_SEEDS=" + strings.Join(sg.signers, ",")}
	}
	if sg.seed != "" {
		return []string{"XRPL_SEED=" + sg.seed}
	}
	return nil
}

func (x xrplTool) run(ctx context.Context, sg signer, out any, args ...string) error {
	cmd := exec.CommandContext(ctx, "node", append([]string{x.script}, args...)...)
	// Never inherit account settings from the caller's environment.
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "XRPL_SEED=") && !strings.HasPrefix(kv, "XRPL_ACCOUNT=") && !strings.HasPrefix(kv, "XRPL_SIGNER_SEEDS=") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	if x.wss != "" {
		cmd.Env = append(cmd.Env, "XRPL_WSS="+x.wss)
	}
	cmd.Env = append(cmd.Env, sg.env()...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("node %s %s: %w (did you run `npm ci` in tools/t1-submit?)", x.script, args[0], err)
	}
	return json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), out)
}

type txResult struct {
	Hash        string `json:"hash"`
	LedgerIndex uint32 `json:"ledger_index"`
}

// account returns (seed, address) from env var envName, or funds a throwaway
// testnet account. Accounts are prepared before T0 so faucet latency never
// eats into the [T0, T1] window.
func (x xrplTool) account(ctx context.Context, envName, label string) (string, string) {
	if seed := os.Getenv(envName); seed != "" {
		var who struct{ Address string }
		must(x.run(ctx, signer{seed: seed}, &who, "--whoami"))
		return seed, who.Address
	}
	if x.network == capture.XRPLNetworkMainnet {
		log.Fatalf("mainnet requires %s (a funded account) for the %s", envName, label)
	}
	var acct struct{ Address, Seed string }
	must(x.run(ctx, signer{}, &acct, "--fund"))
	fmt.Printf("%s account: funded throwaway testnet account %s\n", label, acct.Address)
	return acct.Seed, acct.Address
}

func registryArgs(mode string, events []capture.RegistryEvent) []string {
	args := []string{mode, capture.RegistryMemoType}
	for _, e := range events {
		args = append(args, hex.EncodeToString(e.Encode()))
	}
	return args
}

func (x xrplTool) publishRegistry(ctx context.Context, gov signer, events ...capture.RegistryEvent) txResult {
	var r txResult
	must(x.run(ctx, gov, &r, registryArgs("--memo", events)...))
	return r
}

// probeRegistry submits without waiting and returns the engine result.
func (x xrplTool) probeRegistry(ctx context.Context, gov signer, events ...capture.RegistryEvent) string {
	var r struct {
		EngineResult string `json:"engine_result"`
	}
	must(x.run(ctx, gov, &r, registryArgs("--probe-memo", events)...))
	return r.EngineResult
}

// setupGovernance turns the funded registry account into a 2-of-3 multisign
// account with its master key disabled.
func (x xrplTool) setupGovernance(ctx context.Context, masterSeed string) (string, []string) {
	var r struct {
		Account string   `json:"account"`
		Signers []string `json:"signers"`
	}
	must(x.run(ctx, signer{seed: masterSeed}, &r, "--setup-governance"))
	if len(r.Signers) != 3 {
		log.Fatalf("unexpected governance setup output %+v", r)
	}
	return r.Account, r.Signers
}

func (x xrplTool) publishT1(ctx context.Context, seed string, d [32]byte) []byte {
	var r txResult
	must(x.run(ctx, signer{seed: seed}, &r, hex.EncodeToString(d[:])))
	h, err := hex.DecodeString(r.Hash)
	if err != nil || len(h) != 32 || r.LedgerIndex == 0 {
		log.Fatalf("unexpected T1 submitter output %+v", r)
	}
	a := capture.T1Anchor{NetworkID: x.network, LedgerIndex: r.LedgerIndex}
	copy(a.TxHash[:], h)
	return a.Encode()
}

// Authorities: two JR CAs, the CA3 manifest key and the global CRS.
type authorities struct {
	ca1, ca2 capture.Sk
	vk1, vk2 capture.Vk
	ca3      *capture.ManifestCASecret
	vk3      capture.ManifestCAPublicKey
	crs      capture.CaptureCRS
}

// artifact is what ends up in the DNG (plus bits and manifest).
type artifact struct {
	bits, manifest, t0, t1, proof []byte
	cert3                         capture.ManifestCASignature
	statement                     capture.CaptureStatement
}

// captureOnce runs one full device-side capture: T0, both layer signatures,
// NIZK, then T1 publication.
func captureOnce(ctx context.Context, x xrplTool, src *capture.XRPLClient, deviceSeed string,
	auth *authorities, maxAge time.Duration) artifact {
	t0, ledger, err := capture.NewCaptureTimestamp(ctx, src, maxAge)
	if err != nil {
		log.Fatalf("cannot anchor capture to XRPL: %v", err)
	}
	fmt.Printf("  T0 = ledger #%d closed %s\n", ledger.LedgerIndex, ledger.Time().Format(time.RFC3339))

	bits, err := capture.RandomBitString(256)
	must(err)
	manifest := []byte("factory manifest: two JR-certified hardware signing keys")
	m, err := capture.HashCaptureToG1(bits, 256, manifest, t0)
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
	var cert1, cert2 capture.Signature
	e1Point := new(blst.P1)
	e1Point.FromAffine(&e1)
	e2Point := new(blst.P1)
	e2Point.FromAffine(&e2)
	must(capture.Sign(&auth.ca1, e1Point, &cert1))
	must(capture.Sign(&auth.ca2, e2Point, &cert2))
	cert3, err := auth.ca3.SignManifest(manifest)
	must(err)
	must(sensor.InstallCertificate(&cert1, &auth.vk1))
	must(enclave.InstallCertificate(&cert2, &auth.vk2))
	must(sensor.CheckInstalledKeyIntegrity())
	must(enclave.CheckInstalledKeyIntegrity())

	// Trusted layer operations. The responses Z must stay out of the DNG.
	sensorAtt, err := sensor.SensorAttest(m.ToAffine())
	must(err)
	defer sensorAtt.Clear()
	enclaveAtt, err := enclave.EnclaveAttest(m.ToAffine(), &sensorAtt.R)
	must(err)
	defer enclaveAtt.Clear()

	statement := capture.CaptureStatement{M: *m.ToAffine(), SensorR: sensorAtt.R, EnclaveR: enclaveAtt.R, VK1: auth.vk1, VK2: auth.vk2}
	witness := capture.CaptureWitness{E1: *e1Point, E2: *e2Point, Sig1: cert1, Sig2: cert2, ZSensor: sensorAtt.Z, ZEnclave: enclaveAtt.Z}
	defer witness.ZSensor.Zeroize()
	defer witness.ZEnclave.Zeroize()
	// DEMO TRUST BOUNDARY: the witness below is assembled in one Go process.
	// Production requires trusted assembly or a separately designed distributed
	// GS prover; do not send the raw responses to an untrusted device OS.
	proof, err := capture.CaptureProve(auth.crs, &statement, &witness)
	must(err)
	serialized, err := proof.MarshalBinary()
	must(err)

	commitment, err := capture.CaptureCommitment(&statement, serialized)
	must(err)
	t1 := x.publishT1(ctx, deviceSeed, commitment)
	t1Anchor, err := capture.DecodeT1Anchor(t1)
	must(err)
	fmt.Printf("  T1 = tx %X in ledger #%d (memo D = %X)\n", t1Anchor.TxHash, t1Anchor.LedgerIndex, commitment)
	return artifact{bits: bits, manifest: manifest, t0: t0, t1: t1, proof: serialized, cert3: cert3, statement: statement}
}

// pccVerify is the relying party: it reads the registry of the pinned
// governance account and verifies the artifact against it.
func pccVerify(ctx context.Context, src *capture.XRPLClient, registryAccount string, auth *authorities,
	a artifact, maxWindow time.Duration) (capture.CaptureWindow, error) {
	reg, err := capture.FetchCARegistry(ctx, src, registryAccount, src.NetworkID())
	if err != nil {
		return capture.CaptureWindow{}, err
	}
	st := a.statement
	ok, w, err := capture.CaptureVerifyWithRegistry(ctx, src, reg, auth.crs, a.bits, 256, a.manifest,
		a.t0, a.t1, maxWindow, &a.cert3, &auth.vk3, &st, a.proof)
	if err == nil && !ok {
		err = fmt.Errorf("verification returned false")
	}
	return w, err
}

func main() {
	rpcURL := flag.String("xrpl-rpc", capture.XRPLTestnetRPC, "XRPL JSON-RPC endpoint (T0, registry and PCC verification)")
	wssURL := flag.String("xrpl-wss", "", "XRPL WebSocket endpoint for the submitter script (default: its testnet endpoint)")
	networkID := flag.Uint("xrpl-network", uint(capture.XRPLNetworkTestnet), "XRPL NetworkID of the endpoints (0 mainnet, 1 testnet, 2 devnet)")
	maxAge := flag.Duration("xrpl-max-age", capture.DefaultLedgerMaxAge, "max skew between local clock and T0 close time")
	maxWindow := flag.Duration("max-window", capture.DefaultCaptureMaxWindow, "PCC policy: max close_time(T1) - close_time(T0)")
	script := flag.String("t1-script", "tools/t1-submit/submit_t1.mjs", "XRPL submitter script (Node + xrpl.js)")
	revocationDemo := flag.Bool("revocation-demo", true, "after the first capture, revoke CA3 and show old vs new captures")
	useMultisign := flag.Bool("multisign", true, "protect the registry account with 2-of-3 XRPL multisign (master key disabled)")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	x := xrplTool{script: *script, wss: *wssURL, network: uint32(*networkID)}
	src := capture.NewXRPLClient(*rpcURL, uint32(*networkID))

	// Accounts: governance (CA registry) and device (T1).
	regSeed, regAccount := x.account(ctx, "XRPL_REGISTRY_SEED", "CA registry")
	deviceSeed, _ := x.account(ctx, "XRPL_SEED", "Device (T1)")

	// Governance: registry events need 2 of 3 signatures; the master key is
	// disabled. Reuse an existing setup with XRPL_REGISTRY_SIGNER_SEEDS.
	gov := signer{seed: regSeed}
	if *useMultisign {
		signers := strings.Split(os.Getenv("XRPL_REGISTRY_SIGNER_SEEDS"), ",")
		if os.Getenv("XRPL_REGISTRY_SIGNER_SEEDS") == "" {
			if uint32(*networkID) == capture.XRPLNetworkMainnet {
				// Disabling the master key of a real account must be a deliberate step.
				log.Fatal("mainnet: set up governance once with `node tools/t1-submit/submit_t1.mjs --setup-governance`, " +
					"store the signer seeds safely, then pass XRPL_REGISTRY_SIGNER_SEEDS (or use -multisign=false)")
			}
			_, signers = x.setupGovernance(ctx, regSeed)
			fmt.Printf("Registry %s: 2-of-3 multisign enabled, master key disabled\n", regAccount)
		}
		if len(signers) < 2 {
			log.Fatal("XRPL_REGISTRY_SIGNER_SEEDS needs at least 2 comma-separated seeds")
		}
		gov = signer{account: regAccount, signers: signers[:2]}
	}

	// Authorities and their registration on XRPL.
	var auth authorities
	must(capture.GenerateKeyPair(&auth.ca1, &auth.vk1))
	defer auth.ca1.Clear()
	must(capture.GenerateKeyPair(&auth.ca2, &auth.vk2))
	defer auth.ca2.Clear()
	ca3, vk3, err := capture.NewManifestCAKeyPair()
	must(err)
	defer ca3.Clear()
	auth.ca3, auth.vk3 = ca3, vk3
	auth.crs, err = capture.NewCaptureCRSGlobal()
	must(err)
	id1, err := capture.KeyIDJR(capture.RoleCA1, &auth.vk1)
	must(err)
	id2, err := capture.KeyIDJR(capture.RoleCA2, &auth.vk2)
	must(err)
	id3, err := capture.KeyIDCA3(&auth.vk3)
	must(err)
	idCRS, err := capture.KeyIDCRS(auth.crs)
	must(err)
	act := x.publishRegistry(ctx, gov,
		capture.RegistryEvent{Op: capture.OpActivate, Role: capture.RoleCA1, KeyID: id1},
		capture.RegistryEvent{Op: capture.OpActivate, Role: capture.RoleCA2, KeyID: id2},
		capture.RegistryEvent{Op: capture.OpActivate, Role: capture.RoleCA3, KeyID: id3},
		capture.RegistryEvent{Op: capture.OpActivate, Role: capture.RoleCRS, KeyID: idCRS})
	fmt.Printf("Registry %s: ACTIVATE CA1, CA2, CA3, CRS in ledger #%d\n", regAccount, act.LedgerIndex)

	if *useMultisign {
		// A single key must not be able to write to the registry.
		var rogueCA3 capture.ManifestCAPublicKey
		_, rogueCA3, err = capture.NewManifestCAKeyPair()
		must(err)
		rogueID, err := capture.KeyIDCA3(&rogueCA3)
		must(err)
		rogue := capture.RegistryEvent{Op: capture.OpActivate, Role: capture.RoleCA3, KeyID: rogueID}
		one := signer{account: regAccount, signers: gov.signers[:1]}
		for _, probe := range []struct {
			label string
			sg    signer
		}{{"1 of 3 signers", one}, {"the disabled master key", signer{seed: regSeed}}} {
			res := x.probeRegistry(ctx, probe.sg, rogue)
			if strings.HasPrefix(res, "tes") {
				log.Fatalf("registry accepted an event signed by %s (%s)", probe.label, res)
			}
			fmt.Printf("Registry: ACTIVATE of a rogue CA3 signed by %s -> REFUSED by XRPL (%s)\n", probe.label, res)
		}
	}

	fmt.Println("Capture A:")
	photoA := captureOnce(ctx, x, src, deviceSeed, &auth, *maxAge)
	w, err := pccVerify(ctx, src, regAccount, &auth, photoA, *maxWindow)
	must(err)
	fmt.Printf("PCC: capture A VALID, hardware signed within %s\n", w)

	if *revocationDemo {
		// CA3 is found compromised "from now on".
		latest, err := src.LatestValidatedLedger(ctx)
		must(err)
		since := latest.LedgerIndex + 1
		rev := x.publishRegistry(ctx, gov, capture.RegistryEvent{
			Op: capture.OpRevoke, Role: capture.RoleCA3, KeyID: id3, CompromisedSince: since})
		fmt.Printf("Registry: REVOKE CA3 (compromised since ledger #%d) in ledger #%d\n", since, rev.LedgerIndex)

		fmt.Println("Capture B (signed with the compromised CA3 after the revocation):")
		photoB := captureOnce(ctx, x, src, deviceSeed, &auth, *maxAge)
		if _, err := pccVerify(ctx, src, regAccount, &auth, photoB, *maxWindow); err != nil {
			fmt.Printf("PCC: capture B REJECTED as expected: %v\n", err)
		} else {
			log.Fatal("capture B accepted after CA3 revocation")
		}
		w, err = pccVerify(ctx, src, regAccount, &auth, photoA, *maxWindow)
		must(err)
		fmt.Printf("PCC: capture A still VALID after the revocation (published before ledger #%d)\n", since)
	}

	fingerprint, err := capture.GlobalCaptureCRSFingerprint()
	must(err)
	serialized := photoA.proof
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
	fmt.Printf("XRPL transaction anchor T1: %d bytes (public, in DNG)\n", capture.T1AnchorEncodedSize)
	fmt.Printf("CA registry event: %d bytes per memo (on XRPL, not per photo)\n", capture.RegistryEventEncodedSize)
	fmt.Println("Neither private signing scalar nor Schnorr response is serialized into the DNG")
}
