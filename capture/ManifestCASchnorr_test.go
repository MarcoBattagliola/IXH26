package capture

import (
	"bytes"
	"testing"
)

func TestManifestCA3SchnorrRoundtripAndTampering(t *testing.T) {
	secret, pk, err := NewManifestCAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Clear()
	manifest := []byte("canonical manifest v1: roles + secure hardware policy")
	sig, err := secret.SignManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyManifestCASignature(&pk, manifest, &sig)
	if err != nil || !ok {
		t.Fatalf("CA3 valid signature rejected: %v, %v", ok, err)
	}
	encoded, err := sig.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) != 80 {
		t.Fatalf("expected 80-byte CA3 signature, got %d", len(encoded))
	}
	var decoded ManifestCASignature
	if err := decoded.UnmarshalBinary(encoded); err != nil {
		t.Fatal(err)
	}
	ok, err = VerifyManifestCASignature(&pk, manifest, &decoded)
	if err != nil || !ok {
		t.Fatalf("CA3 signature failed after decoding: %v, %v", ok, err)
	}
	again, err := decoded.MarshalBinary()
	if err != nil || !bytes.Equal(encoded, again) {
		t.Fatal("noncanonical signature roundtrip")
	}

	pkEncoded, err := pk.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(pkEncoded) != 48 {
		t.Fatalf("expected 48-byte CA3 key, got %d", len(pkEncoded))
	}
	var decodedPK ManifestCAPublicKey
	if err := decodedPK.UnmarshalBinary(pkEncoded); err != nil {
		t.Fatal(err)
	}
	ok, err = VerifyManifestCASignature(&decodedPK, manifest, &decoded)
	if err != nil || !ok {
		t.Fatalf("decoded key failed: %v, %v", ok, err)
	}
	pkAgain, err := decodedPK.MarshalBinary()
	if err != nil || !bytes.Equal(pkEncoded, pkAgain) {
		t.Fatal("noncanonical public key roundtrip")
	}

	t.Run("changed_manifest", func(t *testing.T) {
		modified := append([]byte(nil), manifest...)
		modified[3] ^= 1
		accepted, _ := VerifyManifestCASignature(&pk, modified, &sig)
		if accepted {
			t.Fatal("CA3 accepted changed manifest")
		}
	})
	t.Run("different_key", func(t *testing.T) {
		other, otherPK, err := NewManifestCAKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		defer other.Clear()
		accepted, _ := VerifyManifestCASignature(&otherPK, manifest, &sig)
		if accepted {
			t.Fatal("CA3 accepted foreign verification key")
		}
	})
	t.Run("nonce_point", func(t *testing.T) {
		forged := sig
		forged.R = differentG1Point(sig.R)
		accepted, _ := VerifyManifestCASignature(&pk, manifest, &forged)
		if accepted {
			t.Fatal("CA3 accepted altered nonce")
		}
	})
	t.Run("response", func(t *testing.T) {
		forged := sig
		one := scalarOne()
		forged.Z.AddAssign(&one)
		accepted, _ := VerifyManifestCASignature(&pk, manifest, &forged)
		if accepted {
			t.Fatal("CA3 accepted altered response")
		}
	})
	t.Run("empty_manifest", func(t *testing.T) {
		if _, err := secret.SignManifest(nil); err == nil {
			t.Fatal("CA3 signed empty manifest")
		}
		if accepted, _ := VerifyManifestCASignature(&pk, nil, &sig); accepted {
			t.Fatal("CA3 verified empty manifest")
		}
	})
}

func TestManifestCA3SchnorrDecodingFailsClosed(t *testing.T) {
	sk, pk, err := NewManifestCAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer sk.Clear()
	sig, err := sk.SignManifest([]byte("manifest"))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := sig.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		payload []byte
	}{
		{"empty", nil},
		{"short", encoded[:len(encoded)-1]},
		{"extra", append(append([]byte(nil), encoded...), 0)},
		{"zero", make([]byte, ManifestCASignatureSize)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			decoded := sig
			if err := decoded.UnmarshalBinary(tc.payload); err == nil {
				t.Fatal("bad signature accepted")
			}
			if decoded.IsSet() {
				t.Fatal("failed decode preserved a valid signature")
			}
		})
	}
	t.Run("invalid_public_key", func(t *testing.T) {
		decoded := pk
		if err := decoded.UnmarshalBinary(pkBytes[:len(pkBytes)-1]); err == nil {
			t.Fatal("bad key accepted")
		}
		if decoded.IsSet() {
			t.Fatal("failed decode preserved a valid key")
		}
	})
	t.Run("scalar_zero", func(t *testing.T) {
		altered := append([]byte(nil), encoded...)
		clear(altered[CompressedP1AffineSize:])
		var decoded ManifestCASignature
		err := decoded.UnmarshalBinary(altered)
		if err == nil && decoded.IsSet() {
			t.Fatal("zero response accepted")
		}
	})
}

func TestManifestCA3SchnorrRejectsCorruptPrivateKey(t *testing.T) {
	sk, _, err := NewManifestCAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer sk.Clear()
	one := scalarOne()
	sk.x.AddAssign(&one)
	if _, err := sk.SignManifest([]byte("manifest")); err == nil {
		t.Fatal("CA3 signed using private scalar different from certified public point")
	}
	sk.Clear()
	if _, err := sk.SignManifest([]byte("manifest")); err == nil {
		t.Fatal("cleared key signed")
	}
}

func TestPCCRejectsWrongCA3ManifestSignature(t *testing.T) {
	f := makeCaptureFixture(t)
	proof := mustProve(t, f)
	data, err := proof.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	altered := f.CA3Certificate
	altered.R = differentG1Point(altered.R)
	accepted, _ := CaptureVerifyBoundTrusted(f.Anchor, f.CRS, f.Bits, f.BitCount, f.Manifest, f.Timestamp,
		&altered, &f.CA3VK, &f.Statement, data)
	if accepted {
		t.Fatal("PCC accepted corrupted CA3 public manifest signature")
	}

	sk, otherPK, err := NewManifestCAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer sk.Clear()
	otherSig, err := sk.SignManifest(f.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	accepted, _ = CaptureVerifyBoundTrusted(f.Anchor, f.CRS, f.Bits, f.BitCount, f.Manifest, f.Timestamp,
		&otherSig, &otherPK, &f.Statement, data)
	if accepted {
		t.Fatal("PCC accepted CA3 signature from untrusted CA3")
	}
	// Reject re-signing a different manifest and changing the manifest bytes,
	// while retaining a capture statement/proof for the original manifest.
	newManifest := []byte("attacker-supplied manifest")
	anotherSig, err := sk.SignManifest(newManifest)
	if err != nil {
		t.Fatal(err)
	}
	// Even if the manifest receives a VALID CA3 signature and the trust anchor
	// explicitly pins that new CA3, the old photo proof cannot be rebound.
	anotherAnchor, err := NewCaptureTrustAnchor(&f.Statement.VK1, &f.Statement.VK2, &otherPK, f.CRS)
	if err != nil {
		t.Fatal(err)
	}
	accepted, _ = CaptureVerifyBoundTrusted(anotherAnchor, f.CRS, f.Bits, f.BitCount, newManifest, f.Timestamp,
		&anotherSig, &otherPK, &f.Statement, data)
	if accepted {
		t.Fatal("PCC accepted different (validly certified) manifest for original capture")
	}
}

func BenchmarkManifestCA3Sign(b *testing.B) {
	sk, _, err := NewManifestCAKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	defer sk.Clear()
	manifest := []byte("manifest benchmark")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := sk.SignManifest(manifest); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkManifestCA3Verify(b *testing.B) {
	sk, pk, err := NewManifestCAKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	defer sk.Clear()
	manifest := []byte("manifest benchmark")
	sig, err := sk.SignManifest(manifest)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ok, err := VerifyManifestCASignature(&pk, manifest, &sig)
		if err != nil || !ok {
			b.Fatalf("verify: %v %v", ok, err)
		}
	}
}

func FuzzManifestCASignatureDecode(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, ManifestCASignatureSize))
	f.Add(make([]byte, ManifestCASignatureSize-1))
	f.Fuzz(func(t *testing.T, data []byte) {
		var s ManifestCASignature
		if err := s.UnmarshalBinary(data); err != nil {
			return
		}
		encoded, err := s.MarshalBinary()
		if err != nil {
			t.Fatalf("successfully decoded signature fails to reencode: %v", err)
		}
		var decoded ManifestCASignature
		if err := decoded.UnmarshalBinary(encoded); err != nil {
			t.Fatalf("reencoded valid signature rejected: %v", err)
		}
		if !decoded.IsSet() {
			t.Fatal("valid signature lost during roundtrip")
		}
	})
}
