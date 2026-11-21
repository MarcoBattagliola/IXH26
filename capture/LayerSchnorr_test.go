package capture

import (
	blst "github.com/supranational/blst/bindings/go"
	"testing"
)

func TestLayerSchnorrSignaturesAndHardwareRoles(t *testing.T) {
	f := makeCaptureFixture(t)
	e1, err := f.Sensor.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	e2, err := f.Enclave.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	s := SchnorrAttestation{R: f.Statement.SensorR, Z: f.Witness.ZSensor}
	e := SchnorrAttestation{R: f.Statement.EnclaveR, Z: f.Witness.ZEnclave}
	ok, err := VerifyLayerAttestation(LayerSensor, &f.Statement.M, nil, &e1, &s)
	if err != nil || !ok {
		t.Fatalf("sensor signature invalid %v %v", ok, err)
	}
	ok, err = VerifyLayerAttestation(LayerEnclave, &f.Statement.M, &f.Statement.SensorR, &e2, &e)
	if err != nil || !ok {
		t.Fatalf("enclave signature invalid %v %v", ok, err)
	}
	fake := f.Statement.M
	fake = differentG1Point(fake)
	ok, _ = VerifyLayerAttestation(LayerSensor, &fake, nil, &e1, &s)
	if ok {
		t.Fatal("sensor signature accepted other photo")
	}
	ok, _ = VerifyLayerAttestation(LayerEnclave, &fake, &f.Statement.SensorR, &e2, &e)
	if ok {
		t.Fatal("enclave signature accepted other photo")
	}
	badSensorNonce := differentG1Point(f.Statement.SensorR)
	ok, _ = VerifyLayerAttestation(LayerEnclave, &f.Statement.M, &badSensorNonce, &e2, &e)
	if ok {
		t.Fatal("enclave signature accepted other sensor nonce")
	}
	if _, err = f.Sensor.EnclaveAttest(&f.Statement.M, &s.R); err == nil {
		t.Fatal("sensor key signed as enclave")
	}
	if _, err = f.Enclave.SensorAttest(&f.Statement.M); err == nil {
		t.Fatal("enclave key signed as sensor")
	}
}

func TestProvisionRejectsIncorrectCAAndUncertifiedUse(t *testing.T) {
	l, err := NewLayerSecret(LayerSensor)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Clear()
	if _, err = l.SensorAttest(blst.P1Generator().ToAffine()); err == nil {
		t.Fatal("signed before CA enrollment")
	}
	e, err := l.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	var ca1, ca2 Sk
	var v1, v2 Vk
	if err = GenerateKeyPair(&ca1, &v1); err != nil {
		t.Fatal(err)
	}
	if err = GenerateKeyPair(&ca2, &v2); err != nil {
		t.Fatal(err)
	}
	defer ca1.Clear()
	defer ca2.Clear()
	ep := gsP1FromAff(&e)
	var cert Signature
	if err = Sign(&ca1, &ep, &cert); err != nil {
		t.Fatal(err)
	}
	if err = l.InstallCertificate(&cert, &v2); err == nil {
		t.Fatal("accepted unrelated CA")
	}
	if err = l.InstallCertificate(&cert, &v1); err != nil {
		t.Fatal(err)
	}
	if _, err = l.SensorAttest(blst.P1Generator().ToAffine()); err != nil {
		t.Fatalf("certified key unable to sign: %v", err)
	}
}

func TestLayerChallengeDomainSeparation(t *testing.T) {
	f := makeCaptureFixture(t)
	a, err := SensorChallenge(&f.Statement.M, &f.Statement.SensorR)
	if err != nil {
		t.Fatal(err)
	}
	b, err := EnclaveChallenge(&f.Statement.M, &f.Statement.SensorR, &f.Statement.EnclaveR)
	if err != nil {
		t.Fatal(err)
	}
	if string(a.Serialize()) == string(b.Serialize()) {
		t.Fatal("role separation failed")
	}
	if _, err = SensorChallenge(&f.Statement.M, nil); err == nil {
		t.Fatal("accepted absent public nonce")
	}
	if _, err = EnclaveChallenge(&f.Statement.M, &f.Statement.SensorR, nil); err == nil {
		t.Fatal("accepted absent enclave nonce")
	}
}
