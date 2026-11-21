package capture

// Public CA3 Schnorr certification of the canonical device manifest.
//
// Unlike the CA1/CA2 Jutla-Roy signatures on hidden device keys, this signature
// is checked PUBLICLY by the PCC. It is deliberately outside the GS circuit.
// The CA3 key is a distinct signing key; do not reuse a hardware layer key.
// This is a domain-separated Schnorr variant for the BLS12-381 G1 group, NOT
// BIP-340 byte-compatible Schnorr for secp256k1.

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	blst "github.com/supranational/blst/bindings/go"
)

const (
	ManifestCASchnorrVersion = "HACKATON2026_CA3_MANIFEST_SCHNORR_G1_V1"
	ManifestCASignatureSize  = CompressedP1AffineSize + ScalarSize // 48 + 32 = 80
	ManifestCAPublicKeySize  = CompressedP1AffineSize              // 48
	manifestMaxBytes         = 1 << 20
)

// ManifestCASecret is owned by CA3 and never provisioned onto the capture device.
// The public verifier key must be pinned by the PCC via its trust anchor.
type ManifestCASecret struct {
	x           blst.Scalar
	public      ManifestCAPublicKey
	initialized bool
}

type ManifestCAPublicKey struct {
	point blst.P1Affine
	set   bool
}

type ManifestCASignature struct {
	R   blst.P1Affine
	Z   blst.Scalar
	set bool
}

func (pk *ManifestCAPublicKey) IsSet() bool {
	return pk != nil && pk.set && pk.point.InG1() && !schnorrIdentity(&pk.point)
}

func (sig *ManifestCASignature) IsSet() bool {
	return sig != nil && sig.set && sig.R.InG1() && !schnorrIdentity(&sig.R) && sig.Z.Valid()
}

func (sk *ManifestCASecret) Clear() {
	if sk == nil {
		return
	}
	sk.x.Zeroize()
	sk.public = ManifestCAPublicKey{}
	sk.initialized = false
}

func NewManifestCAKeyPair() (*ManifestCASecret, ManifestCAPublicKey, error) {
	sk := new(ManifestCASecret)
	RandomScalar(&sk.x)
	if !sk.x.Valid() {
		return nil, ManifestCAPublicKey{}, errors.New("invalid CA3 private key")
	}
	p := *blst.P1Generator()
	p.MultAssign(&sk.x)
	sk.public = ManifestCAPublicKey{point: *p.ToAffine(), set: true}
	if !sk.public.IsSet() {
		sk.Clear()
		return nil, ManifestCAPublicKey{}, errors.New("invalid CA3 public key")
	}
	sk.initialized = true
	return sk, sk.public, nil
}

func (pk *ManifestCAPublicKey) MarshalBinary() ([]byte, error) {
	if !pk.IsSet() {
		return nil, errors.New("invalid CA3 public key")
	}
	out := pk.point.Compress()
	if len(out) != ManifestCAPublicKeySize {
		return nil, errors.New("wrong CA3 public key size")
	}
	return out, nil
}

// UnmarshalBinary rejects noncanonical/wrong-subgroup/identity public keys and
// clears the receiver on failure, even when it previously held a valid key.
func (pk *ManifestCAPublicKey) UnmarshalBinary(in []byte) error {
	if pk == nil {
		return errors.New("nil CA3 public key")
	}
	*pk = ManifestCAPublicKey{}
	if len(in) != ManifestCAPublicKeySize {
		return fmt.Errorf("invalid CA3 public key length %d", len(in))
	}
	var p blst.P1Affine
	if err := UncompressP1AffineInto(&p, in); err != nil {
		return err
	}
	parsed := ManifestCAPublicKey{point: p, set: true}
	if !parsed.IsSet() {
		return errors.New("identity CA3 public key")
	}
	*pk = parsed
	return nil
}

func (sig *ManifestCASignature) MarshalBinary() ([]byte, error) {
	if !sig.IsSet() {
		return nil, errors.New("invalid CA3 Schnorr signature")
	}
	out := make([]byte, ManifestCASignatureSize)
	copy(out[:CompressedP1AffineSize], sig.R.Compress())
	if err := SerializeScalarTo(out[CompressedP1AffineSize:], &sig.Z); err != nil {
		return nil, err
	}
	return out, nil
}

func (sig *ManifestCASignature) UnmarshalBinary(in []byte) error {
	if sig == nil {
		return errors.New("nil CA3 signature")
	}
	*sig = ManifestCASignature{}
	if len(in) != ManifestCASignatureSize {
		return fmt.Errorf("invalid CA3 signature length %d", len(in))
	}
	var parsed ManifestCASignature
	if err := UncompressP1AffineInto(&parsed.R, in[:CompressedP1AffineSize]); err != nil {
		return err
	}
	if err := DeserializeScalarInto(&parsed.Z, in[CompressedP1AffineSize:]); err != nil {
		return err
	}
	parsed.set = true
	if !parsed.IsSet() {
		return errors.New("invalid CA3 Schnorr signature elements")
	}
	*sig = parsed
	return nil
}

func validateManifestForCA3(manifest []byte) error {
	if len(manifest) == 0 || len(manifest) > manifestMaxBytes {
		return errors.New("manifest must be a nonempty canonical byte string of at most 1 MiB")
	}
	return nil
}

// manifestCAChallenge binds the version, CA3 verification key, public nonce,
// and the FULL byte-for-byte manifest (with an unambiguous length prefix).
// The challenge is derived by rejection sampling into a nonzero Scalar.
func manifestCAChallenge(pk *ManifestCAPublicKey, r *blst.P1Affine, manifest []byte) (blst.Scalar, error) {
	var c blst.Scalar
	if pk == nil || !pk.IsSet() || r == nil || !r.InG1() || schnorrIdentity(r) {
		return c, errors.New("invalid CA3 challenge point")
	}
	if err := validateManifestForCA3(manifest); err != nil {
		return c, err
	}
	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		return c, err
	}
	transcript := make([]byte, 0, len(ManifestCASchnorrVersion)+2*CompressedP1AffineSize+8+len(manifest)+4)
	transcript = append(transcript, []byte(ManifestCASchnorrVersion)...)
	transcript = append(transcript, 0) // unambiguous termination of protocol tag
	transcript = append(transcript, pkBytes...)
	transcript = append(transcript, r.Compress()...)
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(manifest)))
	transcript = append(transcript, length[:]...)
	transcript = append(transcript, manifest...)
	transcript = append(transcript, 0, 0, 0, 0)
	for attempt := uint32(0); ; attempt++ {
		binary.BigEndian.PutUint32(transcript[len(transcript)-4:], attempt)
		digest := sha256.Sum256(transcript)
		if c.FromBEndian(digest[:]) != nil && c.Valid() {
			return c, nil
		}
		if attempt == ^uint32(0) {
			return c, errors.New("CA3 challenge rejection sampling exhausted")
		}
	}
}

// SignManifest is restricted to the CA3 private key. It samples fresh secret
// nonces; a repeated nonce between two messages would leak the private scalar.
func (sk *ManifestCASecret) SignManifest(manifest []byte) (ManifestCASignature, error) {
	var sig ManifestCASignature
	if sk == nil || !sk.initialized || !sk.x.Valid() || !sk.public.IsSet() {
		return sig, errors.New("CA3 secret key uninitialized")
	}
	if err := validateManifestForCA3(manifest); err != nil {
		return sig, err
	}
	expected := *blst.P1Generator()
	expected.MultAssign(&sk.x)
	if !sk.public.point.Equals(expected.ToAffine()) {
		return sig, errors.New("CA3 private/public key integrity failure")
	}
	for i := 0; i < 64; i++ {
		var nonce blst.Scalar
		RandomScalar(&nonce)
		p := *blst.P1Generator()
		p.MultAssign(&nonce)
		sig.R = *p.ToAffine()
		c, err := manifestCAChallenge(&sk.public, &sig.R, manifest)
		if err != nil {
			nonce.Zeroize()
			return ManifestCASignature{}, err
		}
		z := c
		z.MulAssign(&sk.x)
		z.AddAssign(&nonce)
		nonce.Zeroize()
		c.Zeroize()
		if z.Valid() {
			sig.Z = z
			sig.set = true
			return sig, nil
		}
		z.Zeroize()
	}
	return ManifestCASignature{}, errors.New("could not generate nonzero CA3 Schnorr signature")
}

// VerifyManifestCASignature is a PUBLIC check: z*P1 = R + H(pk,R,m)*pk.
// There is no GS witness or extra PPE for CA3.
func VerifyManifestCASignature(pk *ManifestCAPublicKey, manifest []byte, sig *ManifestCASignature) (bool, error) {
	if pk == nil || !pk.IsSet() || sig == nil || !sig.IsSet() {
		return false, errors.New("invalid CA3 Schnorr key/signature")
	}
	c, err := manifestCAChallenge(pk, &sig.R, manifest)
	if err != nil {
		return false, err
	}
	defer c.Zeroize()
	lhs := *blst.P1Generator()
	lhs.MultAssign(&sig.Z)
	rhs := gsP1FromAff(&pk.point)
	rhs.MultAssign(&c)
	r := gsP1FromAff(&sig.R)
	rhs.AddAssign(&r)
	return lhs.Equals(&rhs), nil
}
