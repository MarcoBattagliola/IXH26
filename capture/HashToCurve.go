package capture

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	blst "github.com/supranational/blst/bindings/go"
)

// Domain separation is application-specific; do not reuse across protocols.
var captureHashDST = []byte("HACKATON2026_CAPTURE_MSG_BLS12381G1_XMD:SHA-256_SSWU_RO_V1")

const PhotoHashVersion = "HACKATON2026_CAPTURE_INPUT_V1"

// RandomBitString samples exactly bitCount bits. Unused least-significant bits
// of the last byte are cleared. bitCount is limited to avoid accidental OOM.
func RandomBitString(bitCount int) ([]byte, error) {
	if bitCount <= 0 || bitCount > 8*1024*1024 {
		return nil, errors.New("bitCount must be between 1 and 8388608")
	}
	buf := make([]byte, (bitCount+7)/8)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	if extra := uint((8 - bitCount%8) % 8); extra != 0 {
		buf[len(buf)-1] &= byte(0xff << extra)
	}
	return buf, nil
}

func validateBits(bits []byte, count int) error {
	if count <= 0 || count > 8*1024*1024 || len(bits) != (count+7)/8 {
		return fmt.Errorf("invalid bitstring length/count")
	}
	if extra := uint((8 - count%8) % 8); extra != 0 && bits[len(bits)-1]&byte((1<<extra)-1) != 0 {
		return errors.New("non-canonical bitstring: unused bits must be zero")
	}
	return nil
}

// EncodeCaptureInput is an unambiguous, deterministic, length-prefixed encoding.
// rawBitCount disambiguates random bit strings whose length is not a multiple of 8.
// The inputs manifest and timestamp are public and authenticated by the caller.
// In this protocol timestamp (T0) is LedgerAnchor.Encode() of the latest
// validated XRPL ledger (see XRPLAnchor.go); the PCC authenticates it with
// VerifyLedgerAnchor / CaptureVerifyAnchoredTrusted.
func EncodeCaptureInput(rawBits []byte, rawBitCount int, manifest []byte, timestamp []byte) ([]byte, error) {
	if err := validateBits(rawBits, rawBitCount); err != nil {
		return nil, err
	}
	if len(manifest) == 0 || len(manifest) > 1<<20 {
		return nil, errors.New("invalid manifest size")
	}
	if len(timestamp) == 0 || len(timestamp) > 4096 {
		return nil, errors.New("invalid timestamp size")
	}
	if len(rawBits) > 1<<20 {
		return nil, errors.New("raw bitstring too large")
	}
	var out []byte
	out = append(out, []byte(PhotoHashVersion)...)
	appendU64 := func(v uint64) { var b [8]byte; binary.BigEndian.PutUint64(b[:], v); out = append(out, b[:]...) }
	appendU64(uint64(rawBitCount))
	appendU64(uint64(len(rawBits)))
	out = append(out, rawBits...)
	appendU64(uint64(len(manifest)))
	out = append(out, manifest...)
	appendU64(uint64(len(timestamp)))
	out = append(out, timestamp...)
	return out, nil
}

// HashCaptureToG1 uses blst's IETF-compatible random-oracle hash-to-curve
// implementation (not a naive digest-to-scalar or point compression).
func HashCaptureToG1(rawBits []byte, rawBitCount int, manifest []byte, timestamp []byte) (*blst.P1, error) {
	encoded, err := EncodeCaptureInput(rawBits, rawBitCount, manifest, timestamp)
	if err != nil {
		return nil, err
	}
	point := blst.HashToG1(encoded, captureHashDST)
	if point == nil {
		return nil, errors.New("blst HashToG1 returned nil")
	}
	return point, nil
}
