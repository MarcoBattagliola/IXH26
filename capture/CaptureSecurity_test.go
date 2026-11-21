package capture

import (
	"bytes"
	blst "github.com/supranational/blst/bindings/go"
	"testing"
)

func TestCaptureProverRejectsWrongWitness(t *testing.T) {
	f := makeCaptureFixture(t)
	checks := []struct {
		name   string
		modify func(*CaptureWitness)
	}{
		{"wrong_sensor_key", func(w *CaptureWitness) { w.E1.AddAssign(blst.P1Generator()) }},
		{"wrong_enclave_key", func(w *CaptureWitness) { w.E2.AddAssign(blst.P1Generator()) }},
		{"wrong_sensor_ca_signature", func(w *CaptureWitness) {
			p := gsP1FromAff(&w.Sig1.pi)
			p.AddAssign(blst.P1Generator())
			w.Sig1.pi = *p.ToAffine()
		}},
		{"wrong_enclave_ca_signature", func(w *CaptureWitness) {
			p := gsP1FromAff(&w.Sig2.pi)
			p.AddAssign(blst.P1Generator())
			w.Sig2.pi = *p.ToAffine()
		}},
		{"wrong_sensor_schnorr_response", func(w *CaptureWitness) { one := scalarOne(); w.ZSensor.AddAssign(&one) }},
		{"wrong_enclave_schnorr_response", func(w *CaptureWitness) { one := scalarOne(); w.ZEnclave.AddAssign(&one) }},
	}
	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) {
			w := f.Witness
			tc.modify(&w)
			if _, err := CaptureProve(f.CRS, &f.Statement, &w); err == nil {
				t.Fatal("incorrect witness accepted")
			}
		})
	}
}

func scalarOne() blst.Scalar {
	var s blst.Scalar
	var buf [32]byte
	buf[31] = 1
	s.FromBEndian(buf[:])
	return s
}

func TestCaptureRejectsTamperedProofEquations(t *testing.T) {
	f := makeCaptureFixture(t)
	valid := mustProve(t, f)
	checks := []struct {
		name   string
		modify func(*CaptureProof)
	}{
		{"hidden_key_commitment", func(p *CaptureProof) { p.C[0][1].AddAssign(blst.P1Generator()) }},
		{"hidden_signature_commitment", func(p *CaptureProof) { p.C[3][1].AddAssign(blst.P1Generator()) }},
		{"G2_signature_commitment", func(p *CaptureProof) { p.D[0][1].AddAssign(blst.P2Generator()) }},
		{"sensor_response_commitment", func(p *CaptureProof) { p.ScalarD[0][1].AddAssign(blst.P2Generator()) }},
		{"enclave_response_commitment", func(p *CaptureProof) { p.ScalarD[1][1].AddAssign(blst.P2Generator()) }},
		{"JR_linear_pi", func(p *CaptureProof) { p.PPE[0].Pi[0][0].AddAssign(blst.P2Generator()) }},
		{"JR_tag_theta", func(p *CaptureProof) { p.PPE[2].Theta[0][0].AddAssign(blst.P1Generator()) }},
		{"sensor_Schnorr_pi", func(p *CaptureProof) { p.SchnorrMSM[0].Pi[0][0].AddAssign(blst.P2Generator()) }},
		{"sensor_Schnorr_theta", func(p *CaptureProof) { p.SchnorrMSM[0].Theta[1].AddAssign(blst.P1Generator()) }},
		{"enclave_Schnorr_pi", func(p *CaptureProof) { p.SchnorrMSM[1].Pi[0][0].AddAssign(blst.P2Generator()) }},
		{"enclave_Schnorr_theta", func(p *CaptureProof) { p.SchnorrMSM[1].Theta[1].AddAssign(blst.P1Generator()) }},
		{"opening_commitment_sensor", func(p *CaptureProof) { p.OpeningPoK.T[0][1].AddAssign(blst.P2Generator()) }},
		{"opening_response_sensor", func(p *CaptureProof) { one := scalarOne(); p.OpeningPoK.Response[0][0].AddAssign(&one) }},
		{"opening_response_enclave", func(p *CaptureProof) { one := scalarOne(); p.OpeningPoK.Response[1][1].AddAssign(&one) }},
	}
	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) { p := valid; tc.modify(&p); mustReject(t, f.CRS, &f.Statement, &p) })
	}
}

func TestCaptureRejectsDifferentCRS(t *testing.T) {
	f := makeCaptureFixture(t)
	valid := mustProve(t, f)
	other, err := NewCaptureCRSGlobal()
	if err != nil {
		t.Fatal(err)
	}
	other.U1[0].AddAssign(blst.P1Generator())
	mustReject(t, other, &f.Statement, &valid)
}
func TestCaptureFreshProofRandomness(t *testing.T) {
	f := makeCaptureFixture(t)
	p1 := mustProve(t, f)
	p2 := mustProve(t, f)
	b1, err := p1.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	b2, err := p2.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(b1, b2) {
		t.Fatal("identical randomized proof")
	}
}
func TestCaptureRejectsMalformedProofEncoding(t *testing.T) {
	f := makeCaptureFixture(t)
	p := mustProve(t, f)
	data, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	malformed := map[string][]byte{
		"empty": {}, "truncated": data[:len(data)-1],
		"extra": append(append([]byte(nil), data...), 0),
		"zeros": make([]byte, len(data)),
	}
	for name, b := range malformed {
		t.Run(name, func(t *testing.T) {
			var decoded CaptureProof
			if err := decoded.UnmarshalBinary(b); err == nil {
				ok, _ := CaptureVerify(f.CRS, &f.Statement, &decoded)
				if ok {
					t.Fatal("accepted invalid proof bytes")
				}
			}
		})
	}
}
func FuzzCaptureProofDecode(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, CaptureGSProofCompressedSize))
	f.Fuzz(func(t *testing.T, data []byte) {
		var p CaptureProof
		if err := p.UnmarshalBinary(data); err == nil {
			encoded, err := p.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			if len(encoded) != CaptureGSProofCompressedSize {
				t.Fatal("inconsistent decoder length")
			}
		}
	})
}

// The GS pairing equations alone are not enough to extract a Schnorr scalar.
// The extra Fiat-Shamir proof of openings is mandatory, never optional.
func TestGSWithoutScalarKnowledgeIsRejected(t *testing.T) {
	f := makeCaptureFixture(t)
	p := mustProve(t, f)
	ok, err := CaptureVerify(f.CRS, &f.Statement, &p)
	if err != nil || !ok {
		t.Fatal("valid full GS+PoK rejected")
	}
	p.OpeningPoK = gsOpeningPoK{}
	mustReject(t, f.CRS, &f.Statement, &p)
}

func TestSchnorrOpeningProofSerialization(t *testing.T) {
	f := makeCaptureFixture(t)
	p := mustProve(t, f)
	bytes, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(bytes) != CaptureGSCoreBytes+CaptureOpeningPoKBytes {
		t.Fatal("wrong proof length")
	}
	// The first byte in the Fiat-Shamir PoK (after the GS core) is tampered.
	// If the mutated point is still on the curve, verification MUST fail.
	t.Run("mutated_proof", func(t *testing.T) {
		altered := p
		altered.OpeningPoK.T[0][0].AddAssign(blst.P2Generator())
		mustReject(t, f.CRS, &f.Statement, &altered)
	})
}
