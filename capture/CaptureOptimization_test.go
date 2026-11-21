package capture

import (
	blst "github.com/supranational/blst/bindings/go"
	"testing"
)

func TestCaptureOptimizedProofLayout(t *testing.T) {
	if CaptureG1WitnessCount != 12 || CaptureG2WitnessCount != 2 || CaptureScalarWitnessCount != 2 {
		t.Fatal("wrong JR/Schnorr witness counts")
	}
	if CapturePPECount != 4 || CaptureMSM1Count != 2 {
		t.Fatal("expected four JR PPE and two Schnorr MSM")
	}
	if CaptureGSProofG1Count != 36 || CaptureGSProofG2Count != 28 || CaptureGSCoreBytes != 4416 || CaptureOpeningPoKBytes != 512 || CaptureGSProofCompressedSize != 4928 {
		t.Fatalf("wrong proof layout %d G1 %d G2 %d B", CaptureGSProofG1Count, CaptureGSProofG2Count, CaptureGSProofCompressedSize)
	}
	if SchnorrPublicNoncesSize != 96 || CaptureCRSCompressedSize != 576 {
		t.Fatal("public wire format changed")
	}
}

func TestLinearJRBaseElementSimulation(t *testing.T) {
	f := makeCaptureFixture(t)
	pp, _, err := captureEquations(&f.Statement)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if !pp[i].Linear {
			t.Fatalf("JR %d not linear", i)
		}
	}
	// Real CRS proof is tested end-to-end. This test checks the simulator's
	// special base-element compensation on a crafted simulation CRS.
	crs := f.CRS
	var k blst.Scalar
	RandomScalar(&k)
	defer k.Zeroize()
	for row := 0; row < 2; row++ {
		crs.U2[row] = crs.U1[row]
		crs.U2[row].MultAssign(&k)
	}
	crs.U2[1].SubAssign(blst.P1Generator())
	for ca := 0; ca < 2; ca++ {
		var proof gsPPEProof
		// pi0 = -k T ; pi1 = +T
		proof.Pi[0][0] = pp[ca].Target
		proof.Pi[0][0].MultAssign(&k)
		proof.Pi[0][0] = gsNeg2(proof.Pi[0][0])
		proof.Pi[1][0] = pp[ca].Target
		var zeros [12]gsVec1
		var other [2]gsVec2
		if !gsVerifyPPE(crs, pp[ca], proof, zeros, other) {
			t.Fatal("linear PPE simulation failed")
		}
	}
}

func BenchmarkCaptureProve(b *testing.B) {
	f := makeCaptureFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := CaptureProve(f.CRS, &f.Statement, &f.Witness); err != nil {
			b.Fatal(err)
		}
	}
}
func BenchmarkCaptureVerify(b *testing.B) {
	f := makeCaptureFixture(b)
	p := mustProve(b, f)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ok, err := CaptureVerify(f.CRS, &f.Statement, &p)
		if err != nil || !ok {
			b.Fatalf("%v %v", ok, err)
		}
	}
}
func BenchmarkLayerSensorSign(b *testing.B) {
	f := makeCaptureFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a, err := f.Sensor.SensorAttest(&f.Statement.M)
		if err != nil {
			b.Fatal(err)
		}
		a.Clear()
	}
}
func BenchmarkLayerEnclaveSign(b *testing.B) {
	f := makeCaptureFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a, err := f.Enclave.EnclaveAttest(&f.Statement.M, &f.Statement.SensorR)
		if err != nil {
			b.Fatal(err)
		}
		a.Clear()
	}
}
