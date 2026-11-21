package capture

import (
	"bytes"
	blst "github.com/supranational/blst/bindings/go"
	"testing"
)

func TestGlobalCRSDeterminismAndPinning(t *testing.T) {
	if !GlobalCRSConfigured() {
		t.Fatal("run setup before testing")
	}

	a, err := NewCaptureCRSGlobal()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewCaptureCRSGlobal()
	if err != nil {
		t.Fatal(err)
	}
	ba, err := a.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	bb, err := b.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(ba) != 576 || !bytes.Equal(ba, bb) {
		t.Fatal("CRS not deterministic and 576 bytes")
	}
	if err := ValidateGlobalCaptureCRS(a); err != nil {
		t.Fatal(err)
	}
	var decoded CaptureCRS
	if err := decoded.UnmarshalBinary(ba); err != nil {
		t.Fatal(err)
	}
	if err := ValidateGlobalCaptureCRS(decoded); err != nil {
		t.Fatal(err)
	}
	decoded.U1[1].AddAssign(blst.P1Generator())
	if err := ValidateGlobalCaptureCRS(decoded); err == nil {
		t.Fatal("accepted altered CRS")
	}
}

func TestGlobalCRSRejectsCustomProverAndVerifier(t *testing.T) {
	f := makeCaptureFixture(t)
	p := mustProve(t, f)
	altered := f.CRS
	altered.V2[0].AddAssign(blst.P2Generator())
	if _, err := CaptureProve(altered, &f.Statement, &f.Witness); err == nil {
		t.Fatal("prover accepted unpinned CRS")
	}
	if ok, err := CaptureVerify(altered, &f.Statement, &p); err == nil || ok {
		t.Fatal("verifier accepted unpinned CRS")
	}
	if _, err := NewCaptureTrustAnchor(&f.Statement.VK1, &f.Statement.VK2, &f.CA3VK, altered); err == nil {
		t.Fatal("anchor accepted attacker CRS")
	}
}

func TestInstalledHardwareKeyIntegrity(t *testing.T) {
	f := makeCaptureFixture(t)
	if err := f.Sensor.CheckInstalledKeyIntegrity(); err != nil {
		t.Fatal(err)
	}
	if err := f.Enclave.CheckInstalledKeyIntegrity(); err != nil {
		t.Fatal(err)
	}
	key := f.Sensor
	// Changing the private scalar must invalidate the old CA-certified public key.
	one := scalarOne()
	key.secret.AddAssign(&one)
	if err := key.CheckInstalledKeyIntegrity(); err == nil {
		t.Fatal("accepted modified sensor scalar")
	}
	if _, err := key.SensorAttest(&f.Statement.M); err == nil {
		t.Fatal("corrupted scalar used to sign")
	}
}

func TestHardwareCertificateAndRoleIntegrity(t *testing.T) {
	f := makeCaptureFixture(t)
	f.Enclave.certificate = f.Sensor.certificate
	if err := f.Enclave.CheckInstalledKeyIntegrity(); err == nil {
		t.Fatal("accepted foreign CA certificate")
	}
	if _, err := f.Enclave.EnclaveAttest(&f.Statement.M, &f.Statement.SensorR); err == nil {
		t.Fatal("signed with corrupt certificate")
	}
	g := makeCaptureFixture(t)
	g.Sensor.role = LayerEnclave
	if err := g.Sensor.CheckInstalledKeyIntegrity(); err == nil {
		t.Fatal("accepted changed hardware role")
	}
}

func TestPublicKeyAndPrivateScalarMismatch(t *testing.T) {
	f := makeCaptureFixture(t)
	other := f.Sensor.public
	pp := gsP1FromAff(&other)
	pp.AddAssign(blst.P1Generator())
	f.Sensor.public = *pp.ToAffine()
	if err := f.Sensor.CheckInstalledKeyIntegrity(); err == nil {
		t.Fatal("accepted mismatched pubkey")
	}
}

// A random *validly generated* soundness CRS must not replace the pinned one.
func TestOtherSoundnessCRSRejected(t *testing.T) {
	randomCRS, err := NewCaptureCRSSoundness()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateGlobalCaptureCRS(randomCRS); err == nil {
		t.Fatal("accepted a different structurally sound but unpinned CRS")
	}
}
