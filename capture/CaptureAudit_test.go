package capture

import (
	"bytes"
	blst "github.com/supranational/blst/bindings/go"
	"testing"
)

func TestCaptureTrustedVerificationPinsCAsAndCRS(t *testing.T) {
	f := makeCaptureFixture(t)
	p := mustProve(t, f)
	data, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	verify := func(anchor CaptureTrustAnchor, crs CaptureCRS, st CaptureStatement, ca3 *ManifestCAPublicKey) (bool, error) {
		return CaptureVerifyBoundTrusted(anchor, crs, f.Bits, f.BitCount, f.Manifest, f.Timestamp,
			&f.CA3Certificate, ca3, &st, data)
	}
	ok, err := verify(f.Anchor, f.CRS, f.Statement, &f.CA3VK)
	if err != nil || !ok {
		t.Fatalf("valid anchor rejected %v %v", ok, err)
	}
	tests := []struct {
		name   string
		modify func(*CaptureStatement)
	}{
		{"wrong_ca1", func(st *CaptureStatement) { st.VK1 = st.VK2 }},
		{"wrong_ca2", func(st *CaptureStatement) { st.VK2 = st.VK1 }},
		{"modified_message", func(st *CaptureStatement) { st.M = differentG1Point(st.M) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := f.Statement
			tc.modify(&st)
			accepted, _ := verify(f.Anchor, f.CRS, st, &f.CA3VK)
			if accepted {
				t.Fatal("invalid anchor accepted")
			}
		})
	}
	t.Run("wrong_ca3", func(t *testing.T) {
		otherCA3Secret, otherCA3VK, err := NewManifestCAKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		defer otherCA3Secret.Clear()
		ok, _ := verify(f.Anchor, f.CRS, f.Statement, &otherCA3VK)
		if ok {
			t.Fatal("untrusted CA3 accepted")
		}
	})
	t.Run("wrong_crs", func(t *testing.T) {
		other, err := NewCaptureCRSGlobal()
		if err != nil {
			t.Fatal(err)
		}
		other.U1[0].AddAssign(blst.P1Generator())
		ok, _ := verify(f.Anchor, other, f.Statement, &f.CA3VK)
		if ok {
			t.Fatal("untrusted CRS accepted")
		}
	})
	t.Run("wrong_manifest", func(t *testing.T) {
		ok, _ := CaptureVerifyBoundTrusted(f.Anchor, f.CRS, f.Bits, f.BitCount, []byte("other manifest"), f.Timestamp, &f.CA3Certificate, &f.CA3VK, &f.Statement, data)
		if ok {
			t.Fatal("wrong manifest accepted")
		}
	})
}

func TestCaptureFailedDecodeInvalidatesReceiver(t *testing.T) {
	f := makeCaptureFixture(t)
	p := mustProve(t, f)
	data, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var decoded CaptureProof
	if err = decoded.UnmarshalBinary(data); err != nil {
		t.Fatal(err)
	}
	if err = decoded.UnmarshalBinary(data[:len(data)-1]); err == nil {
		t.Fatal("accepted truncated proof")
	}
	after, err := decoded.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(data, after) {
		t.Fatal("failed decode kept old proof")
	}
	original, err := f.CRS.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var decodedCRS CaptureCRS
	if err = decodedCRS.UnmarshalBinary(original); err != nil {
		t.Fatal(err)
	}
	if err = decodedCRS.UnmarshalBinary(original[:len(original)-1]); err == nil {
		t.Fatal("accepted truncated CRS")
	}
	after, err = decodedCRS.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(original, after) {
		t.Fatal("failed decode kept old CRS")
	}
}

func TestCaptureSerializedVerifierRejectsChangedPoint(t *testing.T) {
	f := makeCaptureFixture(t)
	p := mustProve(t, f)
	data, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	altered := f.Statement
	altered.SensorR = differentG1Point(f.Statement.SensorR)
	ok, err := CaptureVerifySerialized(f.CRS, &altered, data)
	if err == nil && ok {
		t.Fatal("accepted altered sensor attestation")
	}
}
