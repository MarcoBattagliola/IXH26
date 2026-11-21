package capture

import (
	"bytes"
	"testing"

	blst "github.com/supranational/blst/bindings/go"
)

type captureFixture struct {
	CRS                       CaptureCRS
	Statement                 CaptureStatement
	Witness                   CaptureWitness
	Sensor, Enclave           *LayerSecret
	Manifest, Timestamp, Bits []byte
	BitCount                  int
	CA3Certificate            ManifestCASignature
	CA3VK                     ManifestCAPublicKey
	Anchor                    CaptureTrustAnchor
	Ledger                    LedgerAnchor
	LedgerSource              *fakeLedgerSource
}

func makeCaptureFixture(tb testing.TB) *captureFixture {
	tb.Helper()
	f := new(captureFixture)
	f.BitCount = 257
	var err error
	f.Bits, err = RandomBitString(f.BitCount)
	if err != nil {
		tb.Fatal(err)
	}
	f.Manifest = []byte("signed-manifest-schnorr-v1")
	f.Ledger = testLedgerAnchor()
	f.LedgerSource = newFakeLedgerSource(XRPLNetworkTestnet, f.Ledger)
	f.Timestamp = f.Ledger.Encode()
	f.Sensor, err = NewLayerSecret(LayerSensor)
	if err != nil {
		tb.Fatal(err)
	}
	f.Enclave, err = NewLayerSecret(LayerEnclave)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() {
		f.Sensor.Clear()
		f.Enclave.Clear()
		f.Witness.ZSensor.Zeroize()
		f.Witness.ZEnclave.Zeroize()
	})
	e1, err := f.Sensor.PublicKey()
	if err != nil {
		tb.Fatal(err)
	}
	e2, err := f.Enclave.PublicKey()
	if err != nil {
		tb.Fatal(err)
	}
	var ca1, ca2 Sk
	var vk1, vk2 Vk
	if err = GenerateKeyPair(&ca1, &vk1); err != nil {
		tb.Fatal(err)
	}
	if err = GenerateKeyPair(&ca2, &vk2); err != nil {
		tb.Fatal(err)
	}
	ca3, vk3, err := NewManifestCAKeyPair()
	if err != nil {
		tb.Fatal(err)
	}
	f.CA3VK = vk3
	defer ca1.Clear()
	defer ca2.Clear()
	defer ca3.Clear()
	e1Point := gsP1FromAff(&e1)
	e2Point := gsP1FromAff(&e2)
	var sig1, sig2 Signature
	if err = Sign(&ca1, &e1Point, &sig1); err != nil {
		tb.Fatal(err)
	}
	if err = Sign(&ca2, &e2Point, &sig2); err != nil {
		tb.Fatal(err)
	}
	if err = f.Sensor.InstallCertificate(&sig1, &vk1); err != nil {
		tb.Fatal(err)
	}
	if err = f.Enclave.InstallCertificate(&sig2, &vk2); err != nil {
		tb.Fatal(err)
	}
	f.CA3Certificate, err = ca3.SignManifest(f.Manifest)
	if err != nil {
		tb.Fatal(err)
	}
	f.CRS, err = NewCaptureCRSGlobal()
	if err != nil {
		tb.Fatal(err)
	}
	f.Anchor, err = NewCaptureTrustAnchor(&vk1, &vk2, &f.CA3VK, f.CRS)
	if err != nil {
		tb.Fatal(err)
	}
	f.Statement.VK1, f.Statement.VK2 = vk1, vk2
	f.Witness.E1, f.Witness.E2 = e1Point, e2Point
	f.Witness.Sig1, f.Witness.Sig2 = sig1, sig2
	f.setCapture(tb, f.Bits, f.BitCount, f.Manifest, f.Timestamp)
	return f
}

func (f *captureFixture) setCapture(tb testing.TB, bits []byte, n int, manifest, time []byte) {
	tb.Helper()
	m, err := HashCaptureToG1(bits, n, manifest, time)
	if err != nil {
		tb.Fatal(err)
	}
	a, err := f.Sensor.SensorAttest(m.ToAffine())
	if err != nil {
		tb.Fatal(err)
	}
	b, err := f.Enclave.EnclaveAttest(m.ToAffine(), &a.R)
	if err != nil {
		tb.Fatal(err)
	}
	f.Witness.ZSensor.Zeroize()
	f.Witness.ZEnclave.Zeroize()
	f.Witness.ZSensor, f.Witness.ZEnclave = a.Z, b.Z
	f.Statement.M = *m.ToAffine()
	f.Statement.SensorR = a.R
	f.Statement.EnclaveR = b.R
}

func mustProve(tb testing.TB, f *captureFixture) CaptureProof {
	tb.Helper()
	p, err := CaptureProve(f.CRS, &f.Statement, &f.Witness)
	if err != nil {
		tb.Fatalf("CaptureProve: %v", err)
	}
	return p
}
func mustReject(tb testing.TB, crs CaptureCRS, st *CaptureStatement, p *CaptureProof) {
	tb.Helper()
	ok, err := CaptureVerify(crs, st, p)
	if err == nil && ok {
		tb.Fatal("malformed or forged capture accepted")
	}
}
func differentG1Point(original blst.P1Affine) blst.P1Affine {
	p := gsP1FromAff(&original)
	p.AddAssign(blst.P1Generator())
	return *p.ToAffine()
}

func TestCaptureGrothSahaiEndToEnd(t *testing.T) {
	f := makeCaptureFixture(t)
	p := mustProve(t, f)
	ok, err := CaptureVerify(f.CRS, &f.Statement, &p)
	if err != nil || !ok {
		t.Fatalf("GS: %v %v", ok, err)
	}
	data, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != CaptureGSProofCompressedSize {
		t.Fatalf("proof size %d", len(data))
	}
	var decoded CaptureProof
	if err = decoded.UnmarshalBinary(data); err != nil {
		t.Fatal(err)
	}
	ok, err = CaptureVerify(f.CRS, &f.Statement, &decoded)
	if err != nil || !ok {
		t.Fatalf("roundtrip: %v %v", ok, err)
	}
	encoded, err := decoded.MarshalBinary()
	if err != nil || !bytes.Equal(data, encoded) {
		t.Fatal("noncanonical proof roundtrip")
	}
	ok, err = CaptureVerifyBoundTrusted(f.Anchor, f.CRS, f.Bits, f.BitCount, f.Manifest, f.Timestamp,
		&f.CA3Certificate, &f.CA3VK, &f.Statement, data)
	if err != nil || !ok {
		t.Fatalf("PCC: %v %v", ok, err)
	}
}

func TestCaptureRejectsTampering(t *testing.T) {
	f := makeCaptureFixture(t)
	p := mustProve(t, f)
	tests := []struct {
		name   string
		modify func(*CaptureStatement)
	}{
		{"message", func(st *CaptureStatement) { st.M = differentG1Point(st.M) }},
		{"sensor_nonce", func(st *CaptureStatement) { st.SensorR = differentG1Point(st.SensorR) }},
		{"enclave_nonce", func(st *CaptureStatement) { st.EnclaveR = differentG1Point(st.EnclaveR) }},
		{"wrong_ca1", func(st *CaptureStatement) { st.VK1 = st.VK2 }},
		{"wrong_ca2", func(st *CaptureStatement) { st.VK2 = st.VK1 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { st := f.Statement; tc.modify(&st); mustReject(t, f.CRS, &st, &p) })
	}
}

func TestCaptureBoundToManifestAndBitstring(t *testing.T) {
	f := makeCaptureFixture(t)
	p := mustProve(t, f)
	checks := []struct {
		name     string
		bits     []byte
		manifest []byte
		time     []byte
		count    int
	}{
		{"bits", append([]byte(nil), f.Bits...), f.Manifest, f.Timestamp, f.BitCount},
		{"manifest", f.Bits, []byte("wrong-manifest"), f.Timestamp, f.BitCount},
		{"timestamp", f.Bits, f.Manifest, []byte("wrong time"), f.BitCount},
	}
	checks[0].bits[0] ^= 0x80
	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := CaptureVerifyBound(f.CRS, tc.bits, tc.count, tc.manifest, tc.time,
				&f.CA3Certificate, &f.CA3VK, &f.Statement, &p)
			if err == nil && ok {
				t.Fatal("accepted changed photo binding")
			}
		})
	}
}

func TestPCCRejectsChangedPhotoWithOriginalProof(t *testing.T) {
	f := makeCaptureFixture(t)
	p := mustProve(t, f)
	proofBytes, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	fakeBits := append([]byte(nil), f.Bits...)
	fakeBits[0] ^= 0x80
	fakeM, err := HashCaptureToG1(fakeBits, f.BitCount, f.Manifest, f.Timestamp)
	if err != nil {
		t.Fatal(err)
	}
	forged := f.Statement
	forged.M = *fakeM.ToAffine() // attacker retains both public nonces and unchanged GS proof
	ok, err := CaptureVerifyBoundTrusted(f.Anchor, f.CRS, fakeBits, f.BitCount, f.Manifest, f.Timestamp,
		&f.CA3Certificate, &f.CA3VK, &forged, proofBytes)
	if err == nil && ok {
		t.Fatal("photograph substitution accepted")
	}
}
