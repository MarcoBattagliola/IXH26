package capture

// Hardware-layer Schnorr attestations bound to the same public capture hash.
//
// This package models two non-exportable signing scalars, separately certified
// by Jutla-Roy CA1 and CA2. For the demo it returns private Schnorr responses
// to a TRUSTED proof assembler. In a real device those responses MUST NOT be
// exported to the operating system: (R,z,c) reveals the public key E via
// E=(z*P1-R)/c. Distributed GS proving / a secure trusted assembler is outside
// this prototype. No claim of physical provenance follows from software alone.
//
// The hash challenge includes the public nonce point R. This is essential for
// Schnorr unforgeability. The verifier can hash it outside Groth-Sahai.

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"

	blst "github.com/supranational/blst/bindings/go"
)

type CaptureLayer uint8

const (
	LayerSensor  CaptureLayer = 1
	LayerEnclave CaptureLayer = 2
)

const SchnorrPublicNoncesSize = 2 * CompressedP1AffineSize // R_s, R_e
const SchnorrProofVersion = "HACKATON2026_LAYER_SCHNORR_V1"

// LayerSecret models a non-exportable hardware secret. Keep the object confined
// to the appropriate physical layer in a real deployment.
type LayerSecret struct {
	secret          blst.Scalar
	public          blst.P1Affine
	role            CaptureLayer
	installed       bool
	certificate     Signature
	caVK            Vk
	provisionedRole CaptureLayer
}

// NewLayerSecret generates a fresh Schnorr scalar and its public group element.
// Before signing, the corresponding CA's JR certificate must be installed.
func NewLayerSecret(role CaptureLayer) (*LayerSecret, error) {
	if role != LayerSensor && role != LayerEnclave {
		return nil, errors.New("invalid hardware role")
	}
	k := &LayerSecret{role: role}
	RandomScalar(&k.secret)
	if !k.secret.Valid() {
		return nil, errors.New("invalid private scalar")
	}
	pub := *blst.P1Generator()
	pub.MultAssign(&k.secret)
	k.public = *pub.ToAffine()
	return k, nil
}

func (k *LayerSecret) PublicKey() (blst.P1Affine, error) {
	if k == nil || !k.secret.Valid() || !k.public.InG1() {
		return blst.P1Affine{}, errors.New("unset layer key")
	}
	return k.public, nil
}

// CheckKeyIntegrity recomputes the public key directly from the *current*
// private scalar and then checks the Jutla-Roy certificate against the
// authenticated CA key. This must be done at provisioning and before use.
func (k *LayerSecret) CheckKeyIntegrity(cert *Signature, caVK *Vk) error {
	if k == nil || cert == nil || caVK == nil || !k.secret.Valid() || !cert.IsSet() || !caVK.IsSet() {
		return errors.New("invalid Schnorr key/certificate/CA")
	}
	if k.role != LayerSensor && k.role != LayerEnclave {
		return errors.New("invalid hardware role")
	}
	if !k.public.InG1() || schnorrIdentity(&k.public) {
		return errors.New("invalid certified public point")
	}
	recomputed := *blst.P1Generator()
	recomputed.MultAssign(&k.secret)
	if !k.public.Equals(recomputed.ToAffine()) {
		return errors.New("private Schnorr scalar does not match certified public key")
	}
	valid, err := Verify(&k.public, cert, caVK)
	if err != nil {
		return err
	}
	if valid != 1 {
		return errors.New("Jutla-Roy CA certificate does not verify for recomputed public key")
	}
	return nil
}

// CheckInstalledKeyIntegrity rechecks BOTH private/public consistency and JR
// certification each time a sensor or enclave signs. It also fails closed if
// its provisioned hardware role has changed.
func (k *LayerSecret) CheckInstalledKeyIntegrity() error {
	if k == nil || !k.installed {
		return errors.New("unprovisioned Schnorr layer")
	}
	if k.role != k.provisionedRole {
		k.installed = false
		return errors.New("hardware role differs from provisioned role")
	}
	if err := k.CheckKeyIntegrity(&k.certificate, &k.caVK); err != nil {
		k.installed = false
		return err
	}
	return nil
}

// InstallCertificate enforces E=xP1 and checks JR certification against a
// CA verification key that MUST already be authenticated/pinned by provisioning.
func (k *LayerSecret) InstallCertificate(cert *Signature, caVK *Vk) error {
	if k == nil {
		return errors.New("nil layer")
	}
	k.installed = false
	k.certificate = Signature{}
	k.caVK = Vk{}
	if err := k.CheckKeyIntegrity(cert, caVK); err != nil {
		return err
	}
	k.certificate = *cert
	k.caVK = *caVK
	k.provisionedRole = k.role
	k.installed = true
	return nil
}

func (k *LayerSecret) Clear() {
	if k == nil {
		return
	}
	k.secret.Zeroize()
	k.public = blst.P1Affine{}
	k.installed = false
	k.certificate = Signature{}
	k.caVK = Vk{}
	k.provisionedRole = 0
}

// SchnorrAttestation contains the private response z. It MUST NOT be put into
// the public DNG; only R is public and z is a witness inside Groth-Sahai.
type SchnorrAttestation struct {
	R blst.P1Affine
	Z blst.Scalar
}

func (a *SchnorrAttestation) Clear() {
	if a != nil {
		a.Z.Zeroize()
	}
}

func schnorrIdentity(p *blst.P1Affine) bool {
	if p == nil {
		return true
	}
	var neutral blst.P1
	v := gsP1FromAff(p)
	return v.Equals(&neutral)
}

// hashSchnorrScalar hashes canonically compressed PUBLIC points, with role-
// specific transcript tags, to a nonzero scalar using rejection sampling.
// It does not use digest-to-scalar times P1 or a secret input.
func hashSchnorrScalar(role CaptureLayer, points ...*blst.P1Affine) (blst.Scalar, error) {
	var result blst.Scalar
	if role != LayerSensor && role != LayerEnclave {
		return result, errors.New("invalid Schnorr role")
	}
	if (role == LayerSensor && len(points) != 2) || (role == LayerEnclave && len(points) != 3) {
		return result, errors.New("invalid Schnorr transcript shape")
	}
	transcript := make([]byte, 0, 128+len(points)*CompressedP1AffineSize)
	transcript = append(transcript, []byte(SchnorrProofVersion)...)
	transcript = append(transcript, byte(role))
	transcript = append(transcript, byte(len(points)))
	for _, p := range points {
		if p == nil || !p.InG1() || schnorrIdentity(p) {
			return result, errors.New("invalid Schnorr transcript point")
		}
		transcript = append(transcript, p.Compress()...)
	}
	for attempt := uint32(0); ; attempt++ {
		b := make([]byte, len(transcript)+4)
		copy(b, transcript)
		binary.BigEndian.PutUint32(b[len(transcript):], attempt)
		digest := sha256.Sum256(b)
		if result.FromBEndian(digest[:]) != nil && result.Valid() {
			return result, nil
		}
		if attempt == ^uint32(0) {
			return result, errors.New("Schnorr challenge sampling exhausted")
		}
	}
}

func SensorChallenge(message, nonce *blst.P1Affine) (blst.Scalar, error) {
	return hashSchnorrScalar(LayerSensor, message, nonce)
}
func EnclaveChallenge(message, sensorNonce, enclaveNonce *blst.P1Affine) (blst.Scalar, error) {
	return hashSchnorrScalar(LayerEnclave, message, sensorNonce, enclaveNonce)
}

func (k *LayerSecret) sign(message, sensorNonce *blst.P1Affine) (SchnorrAttestation, error) {
	var a SchnorrAttestation
	if k == nil || message == nil || !message.InG1() || schnorrIdentity(message) {
		return a, errors.New("invalid layer or message")
	}
	if err := k.CheckInstalledKeyIntegrity(); err != nil {
		return a, err
	}
	if k.role == LayerEnclave && (sensorNonce == nil || !sensorNonce.InG1() || schnorrIdentity(sensorNonce)) {
		return a, errors.New("missing sensor attestation nonce")
	}
	for attempt := 0; attempt < 64; attempt++ {
		var nonce blst.Scalar
		RandomScalar(&nonce)
		r := *blst.P1Generator()
		r.MultAssign(&nonce)
		a.R = *r.ToAffine()
		var c blst.Scalar
		var err error
		if k.role == LayerSensor {
			c, err = SensorChallenge(message, &a.R)
		} else {
			c, err = EnclaveChallenge(message, sensorNonce, &a.R)
		}
		if err != nil {
			nonce.Zeroize()
			return SchnorrAttestation{}, err
		}
		z := c
		z.MulAssign(&k.secret)
		z.AddAssign(&nonce)
		nonce.Zeroize()
		c.Zeroize()
		if z.Valid() {
			a.Z = z
			return a, nil
		}
		z.Zeroize()
	}
	return SchnorrAttestation{}, errors.New("could not sample Schnorr signature")
}

// SensorAttest signs only the public digest M of a sensor-authorized capture.
// Access control to actual sensor frames is outside this Go prototype.
func (k *LayerSecret) SensorAttest(m *blst.P1Affine) (SchnorrAttestation, error) {
	if k == nil || k.role != LayerSensor {
		return SchnorrAttestation{}, errors.New("not a sensor key")
	}
	return k.sign(m, nil)
}

// EnclaveAttest cryptographically binds the enclave signature to M and R_s.
// A trusted enclosure should additionally authenticate the sensor interface.
func (k *LayerSecret) EnclaveAttest(m, sensorR *blst.P1Affine) (SchnorrAttestation, error) {
	if k == nil || k.role != LayerEnclave {
		return SchnorrAttestation{}, errors.New("not an enclave key")
	}
	return k.sign(m, sensorR)
}

// VerifyLayerAttestation is a local check for the trusted proof assembler.
// The public PCC DOES NOT receive Z or E and instead verifies their relation
// inside Groth-Sahai.
func VerifyLayerAttestation(role CaptureLayer, m, sensorR, pk *blst.P1Affine, a *SchnorrAttestation) (bool, error) {
	if m == nil || pk == nil || a == nil || !m.InG1() || !pk.InG1() || schnorrIdentity(pk) || !a.R.InG1() || schnorrIdentity(&a.R) || !a.Z.Valid() {
		return false, errors.New("invalid layer signature inputs")
	}
	var c blst.Scalar
	var err error
	if role == LayerSensor {
		c, err = SensorChallenge(m, &a.R)
	} else if role == LayerEnclave {
		c, err = EnclaveChallenge(m, sensorR, &a.R)
	} else {
		return false, errors.New("invalid role")
	}
	if err != nil {
		return false, err
	}
	defer c.Zeroize()
	lhs := *blst.P1Generator()
	lhs.MultAssign(&a.Z)
	check := gsP1FromAff(pk)
	check.MultAssign(&c)
	noncePoint := gsP1FromAff(&a.R)
	check.AddAssign(&noncePoint)
	return lhs.Equals(&check), nil
}
