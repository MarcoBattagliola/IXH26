// Package equations is a TEST-ONLY toy exponent model of the JR and Schnorr
// relations. It is NOT a cryptographic implementation or a security proof.
package equations

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

const P int64 = 65537
const (
	G1Witness     = 12
	G2Witness     = 2
	ScalarWitness = 2
	PPECount      = 4
	MSMCount      = 2
)

func Mod(x int64) int64 {
	x %= P
	if x < 0 {
		x += P
	}
	return x
}

type VK struct {
	C0    [5]int64
	C1, A int64
}
type Signature struct{ Rho, RhoHat, Psi, Gamma, Pi, Tau int64 }
type Statement struct {
	M, RS, RE int64
	VK        [2]VK
}
type Witness struct {
	E   [2]int64
	Sig [2]Signature
	Z   [2]int64
}

// Model Schnorr public challenges; these are NOT witnesses.
func Challenge(role int64, st Statement) int64 {
	var buf [32]byte
	binary.BigEndian.PutUint64(buf[:8], uint64(role))
	binary.BigEndian.PutUint64(buf[8:16], uint64(Mod(st.M)))
	binary.BigEndian.PutUint64(buf[16:24], uint64(Mod(st.RS)))
	if role == 2 {
		binary.BigEndian.PutUint64(buf[24:], uint64(Mod(st.RE)))
	}
	h := sha256.Sum256(append([]byte("JR_SCHNORR_TOY_V1"), buf[:]...))
	return 1 + int64(binary.BigEndian.Uint64(h[:8])%uint64(P-1))
}
func Check(st Statement, w Witness) error {
	for ca := 0; ca < 2; ca++ {
		vk := st.VK[ca]
		sg := w.Sig[ca]
		if Mod(w.E[ca]*vk.C0[0]+sg.Rho*vk.C0[1]+sg.RhoHat*vk.C0[2]+sg.Psi*vk.C0[3]+sg.Gamma*vk.C0[4]+vk.C1-sg.Pi*vk.A) != 0 {
			return fmt.Errorf("JR CA%d main PPE", ca+1)
		}
		if Mod(sg.Rho*sg.Tau-sg.Psi) != 0 {
			return fmt.Errorf("JR CA%d tag PPE", ca+1)
		}
	}
	if st.RS == 0 || st.RE == 0 || st.M == 0 {
		return fmt.Errorf("identity nonce or message")
	}
	if Mod(w.Z[0]-Challenge(1, st)*w.E[0]-st.RS) != 0 {
		return fmt.Errorf("invalid sensor Schnorr signature")
	}
	if Mod(w.Z[1]-Challenge(2, st)*w.E[1]-st.RE) != 0 {
		return fmt.Errorf("invalid enclave Schnorr signature")
	}
	return nil
}
