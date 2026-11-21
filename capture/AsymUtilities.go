package capture

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	blst "github.com/supranational/blst/bindings/go"
)

// Application-specific domain-separation tags.
//
// These values are public and do not require zeroization.
var (
	dstRandomG1 = []byte("CR-ACE_GROTH-SAHAI_RANDOM_G1_V1")
	dstRandomG2 = []byte("CR-ACE_GROTH-SAHAI_RANDOM_G2_V1")
)

// Witness dimensions for the capture protocol are defined in CaptureGS.go.
// The obsolete dimensions of the supplied reference circuit are not reused.

// useful constant for serializtion
const (
	CompressedP1AffineSize = 48
	CompressedP2AffineSize = 96

	ScalarSize = blst.BLST_SCALAR_BYTES
)

// functions to compress affine points into byte slices
func CompressP1AffineTo(out []byte, p *blst.P1Affine) error {
	if p == nil {
		return errors.New("nil G1 affine point")
	}

	if len(out) != CompressedP1AffineSize {
		return fmt.Errorf(
			"invalid compressed G1 output length: got %d, want %d",
			len(out),
			CompressedP1AffineSize,
		)
	}

	if !p.InG1() {
		return errors.New("G1 affine point is not in G1")
	}

	compressed := p.Compress()
	if len(compressed) != CompressedP1AffineSize {
		SecureClearByteSlice(compressed)
		return fmt.Errorf(
			"unexpected compressed G1 length: got %d, want %d",
			len(compressed),
			CompressedP1AffineSize,
		)
	}

	copy(out, compressed)
	SecureClearByteSlice(compressed)

	return nil
}

func compressP2AffineTo(out []byte, p *blst.P2Affine) error {
	if p == nil {
		return errors.New("nil G2 affine point")
	}

	if len(out) != CompressedP2AffineSize {
		return fmt.Errorf(
			"invalid compressed G2 output length: got %d, want %d",
			len(out),
			CompressedP2AffineSize,
		)
	}

	if !p.InG2() {
		return errors.New("G2 affine point is not in G2")
	}

	compressed := p.Compress()
	if len(compressed) != CompressedP2AffineSize {
		SecureClearByteSlice(compressed)
		return fmt.Errorf(
			"unexpected compressed G2 length: got %d, want %d",
			len(compressed),
			CompressedP2AffineSize,
		)
	}

	copy(out, compressed)
	SecureClearByteSlice(compressed)

	return nil
}

// function to uncompress byte slices into affine points
func UncompressP1AffineInto(out *blst.P1Affine, in []byte) error {
	if out == nil {
		return errors.New("nil G1 affine output")
	}

	if len(in) != CompressedP1AffineSize {
		return fmt.Errorf(
			"invalid compressed G1 input length: got %d, want %d",
			len(in),
			CompressedP1AffineSize,
		)
	}

	if out.Uncompress(in) == nil {
		SecureClearP1Affine(out)
		return errors.New("invalid compressed G1 affine point")
	}

	if !out.InG1() {
		SecureClearP1Affine(out)
		return errors.New("decoded G1 affine point is not in G1")
	}

	return nil
}

func uncompressP2AffineInto(out *blst.P2Affine, in []byte) error {
	if out == nil {
		return errors.New("nil G2 affine output")
	}

	if len(in) != CompressedP2AffineSize {
		return fmt.Errorf(
			"invalid compressed G2 input length: got %d, want %d",
			len(in),
			CompressedP2AffineSize,
		)
	}

	if out.Uncompress(in) == nil {
		SecureClearP2Affine(out)
		return errors.New("invalid compressed G2 affine point")
	}

	if !out.InG2() {
		SecureClearP2Affine(out)
		return errors.New("decoded G2 affine point is not in G2")
	}

	return nil
}

// function to serialize scalars
func SerializeScalarTo(out []byte, s *blst.Scalar) error {
	if s == nil {
		return errors.New("nil scalar")
	}

	if len(out) != ScalarSize {
		return fmt.Errorf(
			"invalid scalar output length: got %d, want %d",
			len(out),
			ScalarSize,
		)
	}

	serialized := s.Serialize()
	if len(serialized) != ScalarSize {
		SecureClearByteSlice(serialized)
		return fmt.Errorf(
			"unexpected scalar serialization length: got %d, want %d",
			len(serialized),
			ScalarSize,
		)
	}

	copy(out, serialized)
	SecureClearByteSlice(serialized)

	return nil
}

// function to deserialize scalars
func DeserializeScalarInto(out *blst.Scalar, in []byte) error {
	if out == nil {
		return errors.New("nil scalar output")
	}

	if len(in) != ScalarSize {
		zeroizeScalar(out)
		return fmt.Errorf(
			"invalid scalar input length: got %d, want %d",
			len(in),
			ScalarSize,
		)
	}

	if out.FromBEndian(in) == nil {
		zeroizeScalar(out)
		return errors.New("invalid scalar encoding")
	}

	return nil
}

// NegP1Into replaces P with -P.
func negP1Into(P *blst.P1) *blst.P1 {
	if P == nil {
		return nil
	}

	var out blst.P1

	defer func() {
		SecureClearP1(&out)
	}()

	out.SubAssign(P) // out = 0 - P = -P
	*P = out

	return P
}

// NegP2Into replaces P with -P.
func negP2Into(P *blst.P2) *blst.P2 {
	if P == nil {
		return nil
	}

	var out blst.P2

	defer func() {
		SecureClearP2(&out)
	}()

	out.SubAssign(P) // out = 0 - P = -P
	*P = out

	return P
}

// Generate_random_point_in_G1 generates a random point in G1.
//
// The destination is owned by the caller and is not cleared by this function.
func RandomG1Point(pointer *blst.P1) *blst.P1 {
	if pointer == nil {
		panic("generate_random_point_in_G1 failed: destination pointer cannot be nil")
	}

	var randomBytes [32]byte
	var randomPoint *blst.P1

	defer func() {
		SecureClearByteSlice(randomBytes[:])

		if randomPoint != nil {
			SecureClearP1(randomPoint)
		}
	}()

	if _, err := rand.Read(randomBytes[:]); err != nil {
		panic("generate_random_point_in_G1 failed: unable to obtain secure entropy from the OS")
	}

	randomPoint = blst.HashToG1(randomBytes[:], dstRandomG1)
	if randomPoint == nil {
		panic("generate_random_point_in_G1() failed: HashToG1 returned nil")
	}

	// The entropy is no longer needed after HashToG1.
	SecureClearByteSlice(randomBytes[:])

	// Copy the result to the caller-owned destination.
	*pointer = *randomPoint

	// Remove the temporary duplicate immediately.
	SecureClearP1(randomPoint)

	return pointer
}

// Generate_random_point_in_G2 generates a random point in G2.
//
// The destination is owned by the caller and is not cleared by this function.
func RandomG2Point(pointer *blst.P2) *blst.P2 {
	if pointer == nil {
		panic("generate_random_point_in_G2() failed: destination pointer cannot be nil")
	}

	var randomBytes [32]byte
	var randomPoint *blst.P2

	defer func() {
		SecureClearByteSlice(randomBytes[:])

		if randomPoint != nil {
			SecureClearP2(randomPoint)
		}
	}()

	if _, err := rand.Read(randomBytes[:]); err != nil {
		panic("generate_random_point_in_G2() failed: unable to obtain secure entropy from the OS")
	}

	randomPoint = blst.HashToG2(randomBytes[:], dstRandomG2)
	if randomPoint == nil {
		panic("generate_random_point_in_G2() failed: HashToG2 returned nil")
	}

	// The entropy is no longer needed after HashToG2.
	SecureClearByteSlice(randomBytes[:])

	// Copy the result to the caller-owned destination.
	*pointer = *randomPoint

	// Remove the temporary duplicate immediately.
	SecureClearP2(randomPoint)

	return pointer
}

// Generate_random_scalar generates a random non-zero scalar.
//
// The destination is owned by the caller and is not cleared by this function.
func RandomScalar(pointer *blst.Scalar) *blst.Scalar {
	if pointer == nil {
		panic("generate_random_scalar() failed: destination pointer cannot be nil")
	}

	var ikm [32]byte
	var secret *blst.SecretKey

	defer func() {
		SecureClearByteSlice(ikm[:])

		if secret != nil {
			secret.Zeroize()
			runtime.KeepAlive(secret)
		}
	}()

	if _, err := rand.Read(ikm[:]); err != nil {
		panic("generate_random_scalar() failed: unable to obtain secure entropy from the OS")
	}

	secret = blst.KeyGen(ikm[:])
	if secret == nil {
		panic("generate_random_scalar() failed: blst.KeyGen returned nil")
	}

	// KeyGen has already consumed the input keying material.
	SecureClearByteSlice(ikm[:])

	// SecretKey is an alias of Scalar, so no serialization round-trip is
	// necessary. This avoids creating the additional secretBytes copy.
	*pointer = *secret

	// Remove the temporary SecretKey immediately.
	secret.Zeroize()
	runtime.KeepAlive(secret)

	return pointer
}

// boolToMaskBestEffort converts a boolean to a 0/1 mask and clears it.
//
// The conversion avoids a Go-level branch on the boolean value by comparing the
// byte representation of b with the byte representation of a local true value.
// This is a best-effort helper, not a constant-time guarantee for the caller as
// a whole.
func boolToMaskBestEffort(b *bool) uint8 {
	if b == nil {
		return 0
	}

	trueValue := true
	size := int(unsafe.Sizeof(trueValue))

	bBytes := unsafe.Slice(
		(*byte)(unsafe.Pointer(b)),
		size,
	)
	trueBytes := unsafe.Slice(
		(*byte)(unsafe.Pointer(&trueValue)),
		size,
	)

	mask := uint8(subtle.ConstantTimeCompare(bBytes, trueBytes))

	SecureClearBool(b)
	SecureClearBool(&trueValue)

	return mask
}

//go:noinline
func SecureClearByteSlice(buf []byte) {
	clear(buf)
	runtime.KeepAlive(buf)
}

//go:noinline
func SecureClearP1(p *blst.P1) {
	if p == nil {
		return
	}

	*p = blst.P1{}
	runtime.KeepAlive(p)
}

//go:noinline
func SecureClearP2(p *blst.P2) {
	if p == nil {
		return
	}

	*p = blst.P2{}
	runtime.KeepAlive(p)
}

//go:noinline
func SecureClearP1Affine(p *blst.P1Affine) {
	if p == nil {
		return
	}

	*p = blst.P1Affine{}
	runtime.KeepAlive(p)
}

//go:noinline
func SecureClearP2Affine(p *blst.P2Affine) {
	if p == nil {
		return
	}

	*p = blst.P2Affine{}
	runtime.KeepAlive(p)
}

//go:noinline
func SecureClearFp12(f *blst.Fp12) {
	if f == nil {
		return
	}

	*f = blst.Fp12{}
	runtime.KeepAlive(f)
}

//go:noinline
func SecureClearP1Slice(points []blst.P1) {
	for i := range points {
		points[i] = blst.P1{}
	}

	runtime.KeepAlive(points)
}

//go:noinline
func SecureClearP2Slice(points []blst.P2) {
	for i := range points {
		points[i] = blst.P2{}
	}

	runtime.KeepAlive(points)
}

//go:noinline
func SecureClearP1AffineSlice(points []blst.P1Affine) {
	for i := range points {
		points[i] = blst.P1Affine{}
	}

	runtime.KeepAlive(points)
}

//go:noinline
func SecureClearP2AffineSlice(points []blst.P2Affine) {
	for i := range points {
		points[i] = blst.P2Affine{}
	}

	runtime.KeepAlive(points)
}

// ZeroizeScalar deliberately uses blst.Scalar.Zeroize rather than
// assigning a homemade zero value.
//
//go:noinline
func zeroizeScalar(s *blst.Scalar) {
	if s == nil {
		return
	}

	s.Zeroize()
	runtime.KeepAlive(s)
}

//go:noinline
func zeroizeScalarSlice(scalars []blst.Scalar) {
	for i := range scalars {
		scalars[i].Zeroize()
	}

	runtime.KeepAlive(scalars)
}

//go:noinline
func SecureClearUint8(p *uint8) {
	if p == nil {
		return
	}

	*p = 0
	runtime.KeepAlive(p)
}

//go:noinline
func SecureClearBool(p *bool) {
	if p == nil {
		return
	}

	*p = false
	runtime.KeepAlive(p)
}

//go:noinline
func SecureClearBoolSlice(booleans []bool) {
	clear(booleans)
	runtime.KeepAlive(&booleans)
}
