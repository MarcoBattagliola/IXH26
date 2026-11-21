package equations

import "testing"

func TestJRFourPPETwoSchnorrMSM(t *testing.T) {
	if G1Witness != 12 || G2Witness != 2 || ScalarWitness != 2 || PPECount != 4 || MSMCount != 2 {
		t.Fatal("wrong circuit dimensions")
	}
	// Affine tag PPE e(rho,tau)=e(psi,P2) and main PPE fit toy exponents.
	vk := VK{C0: [5]int64{2, 3, 5, 7, 11}, C1: 13, A: 1}
	st := Statement{M: 91, RS: 17, RE: 29, VK: [2]VK{vk, vk}}
	w := Witness{E: [2]int64{12, 18}}
	for i := 0; i < 2; i++ {
		sg := Signature{Rho: 3, RhoHat: 4, Psi: 6, Gamma: 5, Tau: 2}
		sg.Pi = Mod(w.E[i]*vk.C0[0] + sg.Rho*vk.C0[1] + sg.RhoHat*vk.C0[2] + sg.Psi*vk.C0[3] + sg.Gamma*vk.C0[4] + vk.C1)
		w.Sig[i] = sg
	}
	w.Z[0] = Mod(st.RS + Challenge(1, st)*w.E[0])
	w.Z[1] = Mod(st.RE + Challenge(2, st)*w.E[1])
	if err := Check(st, w); err != nil {
		t.Fatal(err)
	}
	altered := st
	altered.M++
	if err := Check(altered, w); err == nil {
		t.Fatal("changed message accepted")
	}
	altered = st
	altered.RS++
	if err := Check(altered, w); err == nil {
		t.Fatal("changed sensor nonce accepted")
	}
	altered = st
	altered.RE++
	if err := Check(altered, w); err == nil {
		t.Fatal("changed enclave nonce accepted")
	}
	bad := w
	bad.Z[1]++
	if err := Check(st, bad); err == nil {
		t.Fatal("invalid enclave response accepted")
	}
}
