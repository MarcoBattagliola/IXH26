package capture

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
)

// CaptureTrustAnchor is provisioned by the relying party from an authenticated
// channel, NOT from the untrusted DNG. It pins the CA1/CA2 Jutla-Roy
// verification keys, the public Schnorr CA3 key and the exact GS CRS. The verification function does not establish
// that an alleged sensor really captured the photo or authenticate T0.
type CaptureTrustAnchor struct {
	CA1       Vk
	CA2       Vk
	CA3       ManifestCAPublicKey
	CRSSHA256 [32]byte
}

// NewCaptureTrustAnchor is a provisioning helper: call it ONLY for CA keys and
// CRS acquired from an authenticated source; never construct an anchor from
// the keys/CRS supplied by the artifact under verification.
func NewCaptureTrustAnchor(ca1, ca2 *Vk, ca3 *ManifestCAPublicKey, crs CaptureCRS) (CaptureTrustAnchor, error) {
	var anchor CaptureTrustAnchor
	if ca1 == nil || ca2 == nil || ca3 == nil || !ca1.set || !ca2.set || !ca3.IsSet() {
		return anchor, errors.New("all three CA verification keys are required")
	}
	if err := captureValidateVK(ca1); err != nil {
		return anchor, fmt.Errorf("CA1: %w", err)
	}
	if err := captureValidateVK(ca2); err != nil {
		return anchor, fmt.Errorf("CA2: %w", err)
	}
	if !ca3.IsSet() {
		return anchor, errors.New("CA3: invalid public Schnorr key")
	}
	if err := ValidateGlobalCaptureCRS(crs); err != nil {
		return anchor, err
	}
	encoded, err := crs.MarshalBinary()
	if err != nil {
		return anchor, err
	}
	return CaptureTrustAnchor{CA1: *ca1, CA2: *ca2, CA3: *ca3, CRSSHA256: sha256.Sum256(encoded)}, nil
}

// captureEqualCA3VK compares pinned manifest Schnorr public keys.
func captureEqualCA3VK(a, b *ManifestCAPublicKey) bool {
	if a == nil || b == nil || !a.IsSet() || !b.IsSet() {
		return false
	}
	aa, errA := a.MarshalBinary()
	bb, errB := b.MarshalBinary()
	if errA != nil || errB != nil {
		return false
	}
	return subtle.ConstantTimeCompare(aa, bb) == 1
}

// captureEqualVK compares the entire Jutla-Roy VK, not just the key identifier.
func captureEqualVK(a, b *Vk) bool {
	if a == nil || b == nil || !a.set || !b.set {
		return false
	}
	for j := 0; j < 5; j++ {
		if !a.c0[j].Equals(&b.c0[j]) {
			return false
		}
	}
	if !a.c1.Equals(&b.c1) || !a.a.Equals(&b.a) {
		return false
	}
	return true
}

func captureValidateVK(v *Vk) error {
	if v == nil || !v.set {
		return errors.New("unset verification key")
	}
	for j := 0; j < 5; j++ {
		if !v.c0[j].InG2() {
			return errors.New("invalid JR VK C0")
		}
	}
	if !v.c1.InG2() || !v.a.InG2() {
		return errors.New("invalid JR VK C1/A")
	}
	return nil
}

func captureValidateCRSPoints(crs CaptureCRS) error {
	for _, vec := range []gsVec1{crs.U1, crs.U2} {
		for j := 0; j < 2; j++ {
			if !vec[j].ToAffine().InG1() {
				return errors.New("CRS point outside G1")
			}
		}
	}
	for _, vec := range []gsVec2{crs.V1, crs.V2} {
		for j := 0; j < 2; j++ {
			if !vec[j].ToAffine().InG2() {
				return errors.New("CRS point outside G2")
			}
		}
	}
	return nil
}

// CaptureVerifyBoundTrusted verifies a serialized GS proof and CA3 manifest
// signature against *pre-provisioned* CA keys and CRS. The trust anchor must be
// immutable within the intended verification policy. It verifies hash binding,
// NOT the XRPL ledger anchor (use CaptureVerifyAnchoredTrusted for that) nor
// physical image acquisition.
func CaptureVerifyBoundTrusted(
	anchor CaptureTrustAnchor,
	crs CaptureCRS,
	raw []byte, bitCount int,
	manifest, timestamp []byte,
	ca3sig *ManifestCASignature, ca3VK *ManifestCAPublicKey,
	st *CaptureStatement,
	proofBytes []byte,
) (bool, error) {
	if st == nil || ca3VK == nil || ca3sig == nil {
		return false, errors.New("missing statement or manifest certificate")
	}
	if !captureEqualVK(&st.VK1, &anchor.CA1) ||
		!captureEqualVK(&st.VK2, &anchor.CA2) ||
		!captureEqualCA3VK(ca3VK, &anchor.CA3) {
		return false, errors.New("untrusted certificate authority verification key")
	}
	if err := captureValidateVK(&st.VK1); err != nil {
		return false, err
	}
	if err := captureValidateVK(&st.VK2); err != nil {
		return false, err
	}
	if !ca3VK.IsSet() {
		return false, errors.New("invalid CA3 Schnorr public key")
	}
	if err := ValidateGlobalCaptureCRS(crs); err != nil {
		return false, err
	}
	crsBytes, err := crs.MarshalBinary()
	if err != nil {
		return false, err
	}
	h := sha256.Sum256(crsBytes)
	if subtle.ConstantTimeCompare(h[:], anchor.CRSSHA256[:]) != 1 {
		return false, errors.New("CRS does not match pinned trust anchor")
	}
	var proof CaptureProof
	if err := proof.UnmarshalBinary(proofBytes); err != nil {
		return false, err
	}
	return CaptureVerifyBound(crs, raw, bitCount, manifest, timestamp, ca3sig, ca3VK, st, &proof)
}
