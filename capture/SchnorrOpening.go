package capture

// Fiat-Shamir proof of knowledge of the two scalar-commitment openings.
//
// Groth-Sahai soundness alone extracts z*P2, not the Schnorr scalar z.
// The PoK below proves knowledge of (z_s,lambda_s,z_e,lambda_e) such that
//   ScalarD_i = z_i*w2 + lambda_i*V1,  i=s,e.
//
// It is a combined Schnorr sigma protocol for two linear maps into G2^2,
// made noninteractive with Fiat-Shamir in the RANDOM ORACLE MODEL. This is
// NOT covered by Groth-Sahai's standalone SXDH standard-model theorem.
// Transcript binds CRS, public statement, all GS proof bytes and PoK nonces.
// The proof adds 4 compressed G2 points and 4 scalars = 512 bytes.

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	blst "github.com/supranational/blst/bindings/go"
)

const CaptureOpeningPoKBytes = 4*CompressedP2AffineSize + 4*ScalarSize
const openingPoKDomain = "HACKATON2026_GS_SCHNORR_SCALAR_OPENINGS_FS_V1"

type gsOpeningPoK struct {
	T        [2]gsVec2         // public sigma commitments for opening of the two scalar GS commitments
	Response [2][2]blst.Scalar // [i][0] response for z_i; [i][1] for lambda_i
}

func openingChallenge(crs CaptureCRS, st *CaptureStatement, proof *CaptureProof, pok *gsOpeningPoK) (blst.Scalar, error) {
	var challenge blst.Scalar
	if st == nil || proof == nil || pok == nil || !st.VK1.set || !st.VK2.set {
		return challenge, errors.New("invalid opening challenge inputs")
	}
	crsBytes, err := crs.MarshalBinary()
	if err != nil {
		return challenge, err
	}
	gsBytes, err := proof.marshalGSCore()
	if err != nil {
		return challenge, err
	}
	raw := make([]byte, 0, 128+len(crsBytes)+len(gsBytes)+2*VkCompressedSize+4*CompressedP2AffineSize)
	raw = append(raw, []byte(openingPoKDomain)...)
	appendBytes := func(data []byte) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(data)))
		raw = append(raw, n[:]...)
		raw = append(raw, data...)
	}
	appendBytes(crsBytes)
	appendBytes(st.M.Compress())
	appendBytes(st.SensorR.Compress())
	appendBytes(st.EnclaveR.Compress())
	for _, vk := range []*Vk{&st.VK1, &st.VK2} {
		for _, p := range vk.points() {
			appendBytes(p.Compress())
		}
	}
	appendBytes(gsBytes)
	for i := range pok.T {
		for j := 0; j < 2; j++ {
			appendBytes(pok.T[i][j].ToAffine().Compress())
		}
	}
	for ctr := uint32(0); ; ctr++ {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], ctr)
		hashed := sha256.New()
		hashed.Write(raw)
		hashed.Write(b[:])
		digest := hashed.Sum(nil)
		if challenge.FromBEndian(digest) != nil && challenge.Valid() {
			return challenge, nil
		}
		if ctr == ^uint32(0) {
			return challenge, errors.New("opening challenge sampling exhausted")
		}
	}
}

func proveOpeningKnowledge(crs CaptureCRS, st *CaptureStatement, proof *CaptureProof,
	responses [3]blst.Scalar, lambdas [3]blst.Scalar) (gsOpeningPoK, error) {
	var out gsOpeningPoK
	var r [2][2]blst.Scalar
	defer func() {
		for i := range r {
			for j := 0; j < 2; j++ {
				r[i][j].Zeroize()
			}
		}
	}()
	w2 := crs.w2()
	for i := 0; i < 2; i++ {
		RandomScalar(&r[i][0])
		RandomScalar(&r[i][1])
		out.T[i].addScaled(w2, &r[i][0], 1)
		out.T[i].addScaled(crs.V1, &r[i][1], 1)
	}
	challenge, err := openingChallenge(crs, st, proof, &out)
	if err != nil {
		return out, err
	}
	defer challenge.Zeroize()
	for i := 0; i < 2; i++ {
		out.Response[i][0] = gsProduct(&challenge, &responses[i])
		out.Response[i][0].AddAssign(&r[i][0])
		out.Response[i][1] = gsProduct(&challenge, &lambdas[i])
		out.Response[i][1].AddAssign(&r[i][1])
	}
	return out, nil
}

func verifyOpeningKnowledge(crs CaptureCRS, st *CaptureStatement, p *CaptureProof) bool {
	challenge, err := openingChallenge(crs, st, p, &p.OpeningPoK)
	if err != nil {
		return false
	}
	defer challenge.Zeroize()
	w2 := crs.w2()
	for i := 0; i < 2; i++ {
		var lhs gsVec2
		lhs.addScaled(w2, &p.OpeningPoK.Response[i][0], 1)
		lhs.addScaled(crs.V1, &p.OpeningPoK.Response[i][1], 1)
		rhs := p.OpeningPoK.T[i]
		rhs.addScaled(p.ScalarD[i], &challenge, 1)
		for row := 0; row < 2; row++ {
			if !lhs[row].Equals(&rhs[row]) {
				return false
			}
		}
	}
	return true
}

func (p CaptureProof) marshalOpeningPoK() ([]byte, error) {
	out := make([]byte, 0, CaptureOpeningPoKBytes)
	for i := 0; i < 2; i++ {
		for j := 0; j < 2; j++ {
			out = append(out, p.OpeningPoK.T[i][j].ToAffine().Compress()...)
		}
	}
	for i := 0; i < 2; i++ {
		for j := 0; j < 2; j++ {
			if !p.OpeningPoK.Response[i][j].Valid() && !scalarZero(&p.OpeningPoK.Response[i][j]) {
				return nil, fmt.Errorf("invalid opening response %d,%d", i, j)
			}
			out = append(out, p.OpeningPoK.Response[i][j].Serialize()...)
		}
	}
	if len(out) != CaptureOpeningPoKBytes {
		return nil, fmt.Errorf("unexpected opening proof size %d", len(out))
	}
	return out, nil
}

func scalarZero(s *blst.Scalar) bool {
	if s == nil {
		return false
	}
	for _, v := range s.Serialize() {
		if v != 0 {
			return false
		}
	}
	return true
}
