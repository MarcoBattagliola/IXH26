package capture

// Jutla–Roy SXDH structure-preserving signature, PKC 2017, Figure 2,
// instantiated for one message in G1 (n=1, k=1).
// The affine-language QA-NIZK verification key is generated using the
// strong split-CRS construction in Section 2.2 of the same paper.
//
// Signature: (rho, rhoHat, psi, gamma, tau, pi) in G1^5 x G2.
// Verification equations:
//   e(mu,C0[0]) e(rho,C0[1]) e(rhoHat,C0[2])
//   e(psi,C0[3]) e(gamma,C0[4]) e(P1,C1) = e(pi,A)
//   e(rho,tau) = e(psi,P2).
//
// IMPORTANT: These are NOT KPW signatures and are incompatible with old
// certificates, old serialized signatures, and old verification keys.

import (
	"errors"
	"fmt"
	blst "github.com/supranational/blst/bindings/go"
)

const (
	VkCompressedSize        = 7 * CompressedP2AffineSize
	SignatureCompressedSize = 5*CompressedP1AffineSize + CompressedP2AffineSize
)

type Sk struct {
	b, k0, k, d, e blst.Scalar
	v              [5]blst.Scalar
	kappa          blst.Scalar
	set            bool
}

func (sk *Sk) IsSet() bool { return sk != nil && sk.set }
func (sk *Sk) Clear() {
	if sk == nil {
		return
	}
	sk.b.Zeroize()
	sk.k0.Zeroize()
	sk.k.Zeroize()
	sk.d.Zeroize()
	sk.e.Zeroize()
	for i := range sk.v {
		sk.v[i].Zeroize()
	}
	sk.kappa.Zeroize()
	sk.set = false
}

// Vk consists of 5+1+1 elements in G2. The A component is a
// random nonidentity generator multiple, not a secret.
type Vk struct {
	c0  [5]blst.P2Affine
	c1  blst.P2Affine
	a   blst.P2Affine
	set bool
}

func (vk *Vk) IsSet() bool { return vk != nil && vk.set }
func (vk *Vk) Clear() {
	if vk != nil {
		*vk = Vk{}
	}
}
func (vk *Vk) points() [7]*blst.P2Affine {
	return [7]*blst.P2Affine{&vk.c0[0], &vk.c0[1], &vk.c0[2], &vk.c0[3], &vk.c0[4], &vk.c1, &vk.a}
}
func (vk *Vk) CompressToAndClear(out []byte) error {
	if vk == nil || !vk.set || len(out) != VkCompressedSize {
		if vk != nil {
			vk.Clear()
		}
		SecureClearByteSlice(out)
		return errors.New("invalid Jutla–Roy VK/output")
	}
	defer vk.Clear()
	for i, p := range vk.points() {
		if err := compressP2AffineTo(out[i*CompressedP2AffineSize:(i+1)*CompressedP2AffineSize], p); err != nil {
			SecureClearByteSlice(out)
			return err
		}
	}
	return nil
}
func (vk *Vk) UncompressAndClear(in []byte) error {
	defer SecureClearByteSlice(in)
	if vk == nil {
		return errors.New("nil JR VK")
	}
	vk.Clear()
	if len(in) != VkCompressedSize {
		return fmt.Errorf("invalid JR VK length %d", len(in))
	}
	var next Vk
	for i, p := range next.points() {
		if err := uncompressP2AffineInto(p, in[i*CompressedP2AffineSize:(i+1)*CompressedP2AffineSize]); err != nil {
			return err
		}
	}
	next.set = true
	*vk = next
	return nil
}

type Signature struct {
	rho, rhoHat, psi, gamma, pi blst.P1Affine
	tau                         blst.P2Affine
	set                         bool
}

func (s *Signature) IsSet() bool { return s != nil && s.set }
func (s *Signature) Clear() {
	if s != nil {
		*s = Signature{}
	}
}
func (s *Signature) points() [5]*blst.P1Affine {
	return [5]*blst.P1Affine{&s.rho, &s.rhoHat, &s.psi, &s.gamma, &s.pi}
}
func (s *Signature) CompressToAndClear(out []byte) error {
	if s == nil || !s.set || len(out) != SignatureCompressedSize {
		if s != nil {
			s.Clear()
		}
		SecureClearByteSlice(out)
		return errors.New("invalid JR signature/output")
	}
	defer s.Clear()
	for i, p := range s.points() {
		if err := CompressP1AffineTo(out[i*CompressedP1AffineSize:(i+1)*CompressedP1AffineSize], p); err != nil {
			SecureClearByteSlice(out)
			return err
		}
	}
	if err := compressP2AffineTo(out[5*CompressedP1AffineSize:], &s.tau); err != nil {
		SecureClearByteSlice(out)
		return err
	}
	return nil
}
func (s *Signature) UncompressAndClear(in []byte) error {
	defer SecureClearByteSlice(in)
	if s == nil {
		return errors.New("nil JR signature")
	}
	s.Clear()
	if len(in) != SignatureCompressedSize {
		return fmt.Errorf("invalid JR signature length %d", len(in))
	}
	var next Signature
	for i, p := range next.points() {
		if err := UncompressP1AffineInto(p, in[i*CompressedP1AffineSize:(i+1)*CompressedP1AffineSize]); err != nil {
			return err
		}
	}
	if err := uncompressP2AffineInto(&next.tau, in[5*CompressedP1AffineSize:]); err != nil {
		return err
	}
	next.set = true
	*s = next
	return nil
}

func jrMult1(point *blst.P1, v *blst.Scalar) blst.P1 {
	result := *point
	result.MultAssign(v)
	return result
}
func jrMult2(point *blst.P2, v *blst.Scalar) blst.P2 {
	result := *point
	result.MultAssign(v)
	return result
}
func jrProduct(x, y *blst.Scalar) blst.Scalar { r := *x; r.MulAssign(y); return r }

func GenerateKeyPair(sk *Sk, vk *Vk) error {
	if sk == nil || vk == nil {
		return errors.New("nil JR signing key")
	}
	sk.Clear()
	vk.Clear()
	var a blst.Scalar
	RandomScalar(&a)
	defer a.Zeroize()
	RandomScalar(&sk.b)
	RandomScalar(&sk.k0)
	RandomScalar(&sk.k)
	RandomScalar(&sk.d)
	RandomScalar(&sk.e)
	for j := 0; j < 5; j++ {
		RandomScalar(&sk.v[j])
		coeff := jrProduct(&sk.v[j], &a)
		p := jrMult2(blst.P2Generator(), &coeff)
		vk.c0[j] = *p.ToAffine()
		coeff.Zeroize()
	}
	RandomScalar(&sk.kappa)
	c1 := jrProduct(&sk.kappa, &a)
	p := jrMult2(blst.P2Generator(), &c1)
	vk.c1 = *p.ToAffine()
	c1.Zeroize()
	p = jrMult2(blst.P2Generator(), &a)
	vk.a = *p.ToAffine()
	sk.set = true
	vk.set = true
	return nil
}

// Sign uses the QA-NIZK simulator trapdoor retained by the signing authority
// (v[0..4] and kappa), exactly as JR Figure 2 prescribes.
func Sign(sk *Sk, msg *blst.P1, sigma *Signature) error {
	if sk == nil || !sk.set || msg == nil || sigma == nil || !msg.ToAffine().InG1() {
		return errors.New("invalid JR signing inputs")
	}
	sigma.Clear()
	var r, tag blst.Scalar
	RandomScalar(&r)
	RandomScalar(&tag)
	defer r.Zeroize()
	defer tag.Zeroize()
	br := jrProduct(&sk.b, &r)
	tr := jrProduct(&tag, &r)
	defer br.Zeroize()
	defer tr.Zeroize()

	rho := jrMult1(blst.P1Generator(), &r)
	rhoHat := jrMult1(blst.P1Generator(), &br)
	psi := jrMult1(blst.P1Generator(), &tr)
	gamma := jrMult1(msg, &sk.k)
	coeff := sk.k0
	dr := jrProduct(&sk.d, &r)
	coeff.AddAssign(&dr)
	dr.Zeroize()
	er := jrProduct(&sk.e, &tr)
	coeff.AddAssign(&er)
	er.Zeroize()
	extra := jrMult1(blst.P1Generator(), &coeff)
	gamma.AddAssign(&extra)
	coeff.Zeroize()

	y := [5]blst.P1{*msg, rho, rhoHat, psi, gamma}
	pi := jrMult1(blst.P1Generator(), &sk.kappa)
	for j := 0; j < 5; j++ {
		t := jrMult1(&y[j], &sk.v[j])
		pi.AddAssign(&t)
	}
	tau := jrMult2(blst.P2Generator(), &tag)
	*sigma = Signature{rho: *rho.ToAffine(), rhoHat: *rhoHat.ToAffine(), psi: *psi.ToAffine(), gamma: *gamma.ToAffine(), pi: *pi.ToAffine(), tau: *tau.ToAffine(), set: true}
	return nil
}

// Verify evaluates the two JR pairing-product equations. Both checks are
// required. A proof of only the tag pairing is NOT a JR signature.
func Verify(msg *blst.P1Affine, sig *Signature, vk *Vk) (uint8, error) {
	if msg == nil || sig == nil || vk == nil || !sig.set || !vk.set || !msg.InG1() {
		return 0, errors.New("invalid JR verifier inputs")
	}
	for _, p := range sig.points() {
		if !p.InG1() {
			return 0, errors.New("JR signature outside G1")
		}
	}
	if !sig.tau.InG2() {
		return 0, errors.New("JR tag outside G2")
	}
	for _, p := range vk.points() {
		if !p.InG2() {
			return 0, errors.New("JR key outside G2")
		}
	}
	y := [5]*blst.P1Affine{msg, &sig.rho, &sig.rhoHat, &sig.psi, &sig.gamma}
	leftP := make([]blst.P1Affine, 0, 6)
	leftQ := make([]blst.P2Affine, 0, 6)
	for j := 0; j < 5; j++ {
		leftP = append(leftP, *y[j])
		leftQ = append(leftQ, vk.c0[j])
	}
	leftP = append(leftP, *blst.P1Generator().ToAffine())
	leftQ = append(leftQ, vk.c1)
	lhs := blst.Fp12MillerLoopN(leftQ, leftP)
	rhs := blst.Fp12MillerLoop(&vk.a, &sig.pi)
	if !blst.Fp12FinalVerify(lhs, rhs) {
		return 0, nil
	}
	lhs = blst.Fp12MillerLoop(&sig.tau, &sig.rho)
	rhs = blst.Fp12MillerLoop(blst.P2Generator().ToAffine(), &sig.psi)
	if !blst.Fp12FinalVerify(lhs, rhs) {
		return 0, nil
	}
	return 1, nil
}
