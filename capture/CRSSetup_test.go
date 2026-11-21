package capture

import "testing"

// The soundness CRS must be genuinely freshly sampled, rather than generated
// deterministically from a public hash-derived scalar. This test is a sanity
// check on the implementation, NOT a proof of the ceremony's honesty.
func TestCRSSetupSamplesFreshRankOneDistribution(t *testing.T) {
	a, err := NewCaptureCRSSoundness()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewCaptureCRSSoundness()
	if err != nil {
		t.Fatal(err)
	}
	if err := captureValidateCRSPoints(a); err != nil {
		t.Fatal(err)
	}
	if err := captureValidateCRSPoints(b); err != nil {
		t.Fatal(err)
	}
	aBytes, err := a.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	bBytes, err := b.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if string(aBytes) == string(bBytes) {
		t.Fatal("two random soundness CRS instances were identical")
	}
	if err := ValidateGlobalCaptureCRS(a); err == nil {
		t.Fatal("new, unpinned soundness CRS was accepted")
	}
}
