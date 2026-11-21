package capture

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// T0 = an XRPL validated-ledger anchor.
//
// The capture timestamp passed to HashCaptureToG1 is the canonical encoding of
// the most recent *validated* XRPL ledger at capture time. The ledger hash
// commits to the ledger header, which contains close_time, so a verifier that
// re-fetches the ledger by hash from a node it trusts authenticates both the
// ledger and its time. This yields a "not before" bound only: it does NOT
// prove that the capture happened shortly after that ledger.

// Public JSON-RPC endpoints. NetworkID must match the endpoint.
const (
	XRPLMainnetRPC = "https://xrplcluster.com" // full-history cluster
	XRPLTestnetRPC = "https://s.altnet.rippletest.net:51234"
	XRPLDevnetRPC  = "https://s.devnet.rippletest.net:51234"
)

// XRPL NetworkID values.
const (
	XRPLNetworkMainnet uint32 = 0
	XRPLNetworkTestnet uint32 = 1
	XRPLNetworkDevnet  uint32 = 2
)

// rippleEpochOffset: XRPL times are seconds since 2000-01-01T00:00:00Z.
const rippleEpochOffset = 946684800

const LedgerAnchorVersion = "HACKATON2026_XRPL_LEDGER_ANCHOR_V1"

// LedgerAnchorEncodedSize: version || networkID || ledgerIndex || ledgerHash || closeTime.
const LedgerAnchorEncodedSize = len(LedgerAnchorVersion) + 4 + 4 + 32 + 4

// DefaultLedgerMaxAge is the device-side freshness bound on the fetched ledger.
const DefaultLedgerMaxAge = 30 * time.Second

// LedgerAnchor binds a capture to a specific validated XRPL ledger.
type LedgerAnchor struct {
	NetworkID   uint32
	LedgerIndex uint32
	LedgerHash  [32]byte
	CloseTime   uint32 // Ripple-epoch seconds, rounded to close_time_resolution
}

// Time returns the ledger close time in UTC.
func (a LedgerAnchor) Time() time.Time {
	return time.Unix(int64(a.CloseTime)+rippleEpochOffset, 0).UTC()
}

// Encode returns the fixed-length canonical encoding used as T0.
func (a LedgerAnchor) Encode() []byte {
	out := make([]byte, 0, LedgerAnchorEncodedSize)
	out = append(out, LedgerAnchorVersion...)
	out = binary.BigEndian.AppendUint32(out, a.NetworkID)
	out = binary.BigEndian.AppendUint32(out, a.LedgerIndex)
	out = append(out, a.LedgerHash[:]...)
	out = binary.BigEndian.AppendUint32(out, a.CloseTime)
	return out
}

// DecodeLedgerAnchor is the strict inverse of Encode.
func DecodeLedgerAnchor(b []byte) (LedgerAnchor, error) {
	var a LedgerAnchor
	if len(b) != LedgerAnchorEncodedSize || !bytes.HasPrefix(b, []byte(LedgerAnchorVersion)) {
		return a, errors.New("invalid XRPL ledger anchor encoding")
	}
	p := b[len(LedgerAnchorVersion):]
	a.NetworkID = binary.BigEndian.Uint32(p[0:4])
	a.LedgerIndex = binary.BigEndian.Uint32(p[4:8])
	copy(a.LedgerHash[:], p[8:40])
	a.CloseTime = binary.BigEndian.Uint32(p[40:44])
	if a.LedgerIndex == 0 || a.CloseTime == 0 || a.LedgerHash == ([32]byte{}) {
		return LedgerAnchor{}, errors.New("invalid XRPL ledger anchor fields")
	}
	return a, nil
}

// LedgerSource abstracts the XRPL so tests and the PCC can pin their own node.
type LedgerSource interface {
	NetworkID() uint32
	LatestValidatedLedger(ctx context.Context) (LedgerAnchor, error)
	LedgerByHash(ctx context.Context, hash [32]byte) (LedgerAnchor, error)
}

// XRPLClient is a minimal JSON-RPC client for the rippled `ledger` method.
type XRPLClient struct {
	RPCURL  string
	Network uint32
	HTTP    *http.Client // nil => 10s-timeout client
}

func NewXRPLClient(rpcURL string, networkID uint32) *XRPLClient {
	return &XRPLClient{RPCURL: rpcURL, Network: networkID}
}

func (c *XRPLClient) NetworkID() uint32 { return c.Network }

// LatestValidatedLedger returns the last validated ledger. "current" is NOT
// used: it is the open ledger, has no final hash and no close_time.
func (c *XRPLClient) LatestValidatedLedger(ctx context.Context) (LedgerAnchor, error) {
	return c.ledger(ctx, map[string]any{"ledger_index": "validated"})
}

// LedgerByHash fetches a ledger header by hash. The node must still hold that
// ledger (use a full-history node for old captures).
func (c *XRPLClient) LedgerByHash(ctx context.Context, hash [32]byte) (LedgerAnchor, error) {
	return c.ledger(ctx, map[string]any{"ledger_hash": hex.EncodeToString(hash[:])})
}

type xrplLedgerResponse struct {
	Result struct {
		Status      string `json:"status"`
		Error       string `json:"error"`
		Validated   bool   `json:"validated"`
		LedgerHash  string `json:"ledger_hash"`
		LedgerIndex uint32 `json:"ledger_index"`
		Ledger      struct {
			LedgerHash string `json:"ledger_hash"`
			CloseTime  int64  `json:"close_time"`
			Closed     bool   `json:"closed"`
		} `json:"ledger"`
	} `json:"result"`
}

func (c *XRPLClient) ledger(ctx context.Context, params map[string]any) (LedgerAnchor, error) {
	params["transactions"] = false
	params["expand"] = false
	body, err := json.Marshal(map[string]any{"method": "ledger", "params": []any{params}})
	if err != nil {
		return LedgerAnchor{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.RPCURL, bytes.NewReader(body))
	if err != nil {
		return LedgerAnchor{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return LedgerAnchor{}, fmt.Errorf("xrpl rpc: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return LedgerAnchor{}, fmt.Errorf("xrpl rpc: http %d", resp.StatusCode)
	}
	var r xrplLedgerResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&r); err != nil {
		return LedgerAnchor{}, fmt.Errorf("xrpl rpc: decode: %w", err)
	}
	return anchorFromXRPLResponse(&r, c.Network)
}

func anchorFromXRPLResponse(r *xrplLedgerResponse, networkID uint32) (LedgerAnchor, error) {
	var a LedgerAnchor
	res := r.Result
	if res.Status != "success" {
		return a, fmt.Errorf("xrpl rpc: status=%q error=%q", res.Status, res.Error)
	}
	if !res.Validated || !res.Ledger.Closed {
		return a, errors.New("xrpl: ledger is not closed and validated")
	}
	if res.Ledger.LedgerHash != "" && res.Ledger.LedgerHash != res.LedgerHash {
		return a, errors.New("xrpl: inconsistent ledger_hash in response")
	}
	h, err := hex.DecodeString(res.LedgerHash)
	if err != nil || len(h) != 32 {
		return a, errors.New("xrpl: invalid ledger_hash")
	}
	if res.LedgerIndex == 0 {
		return a, errors.New("xrpl: invalid ledger_index")
	}
	if res.Ledger.CloseTime <= 0 || res.Ledger.CloseTime > 0xFFFFFFFF {
		return a, errors.New("xrpl: invalid close_time")
	}
	a.NetworkID = networkID
	a.LedgerIndex = res.LedgerIndex
	copy(a.LedgerHash[:], h)
	a.CloseTime = uint32(res.Ledger.CloseTime)
	return a, nil
}

// NewCaptureTimestamp (device side) fetches the latest validated ledger and
// rejects it if its close time differs from the local clock by more than
// maxAge, to catch a stale or lying RPC node. Returns T0 bytes and the anchor.
func NewCaptureTimestamp(ctx context.Context, src LedgerSource, maxAge time.Duration) ([]byte, LedgerAnchor, error) {
	return newCaptureTimestampAt(ctx, src, maxAge, time.Now())
}

func newCaptureTimestampAt(ctx context.Context, src LedgerSource, maxAge time.Duration, now time.Time) ([]byte, LedgerAnchor, error) {
	if src == nil {
		return nil, LedgerAnchor{}, errors.New("nil ledger source")
	}
	a, err := src.LatestValidatedLedger(ctx)
	if err != nil {
		return nil, LedgerAnchor{}, err
	}
	if a.NetworkID != src.NetworkID() {
		return nil, LedgerAnchor{}, errors.New("ledger anchor from unexpected XRPL network")
	}
	if age := now.Sub(a.Time()); age > maxAge || age < -maxAge {
		return nil, LedgerAnchor{}, fmt.Errorf("ledger %d close time skew %v exceeds %v", a.LedgerIndex, age, maxAge)
	}
	return a.Encode(), a, nil
}

// VerifyLedgerAnchor (PCC side) decodes T0 and checks it against the ledger
// served by src for the same hash: network, index and close time must match.
func VerifyLedgerAnchor(ctx context.Context, src LedgerSource, timestamp []byte) (LedgerAnchor, error) {
	if src == nil {
		return LedgerAnchor{}, errors.New("nil ledger source")
	}
	claimed, err := DecodeLedgerAnchor(timestamp)
	if err != nil {
		return LedgerAnchor{}, err
	}
	if claimed.NetworkID != src.NetworkID() {
		return LedgerAnchor{}, errors.New("ledger anchor from untrusted XRPL network")
	}
	onChain, err := src.LedgerByHash(ctx, claimed.LedgerHash)
	if err != nil {
		return LedgerAnchor{}, err
	}
	if onChain != claimed {
		return LedgerAnchor{}, errors.New("ledger anchor does not match XRPL ledger")
	}
	return claimed, nil
}

// CaptureVerifyAnchoredTrusted is CaptureVerifyBoundTrusted plus XRPL
// verification of T0. src must be chosen by the relying party (pinned node and
// network), never taken from the artifact. On success it returns the verified
// anchor, whose Time() is a lower bound on the capture time.
func CaptureVerifyAnchoredTrusted(
	ctx context.Context,
	src LedgerSource,
	anchor CaptureTrustAnchor,
	crs CaptureCRS,
	raw []byte, bitCount int,
	manifest, timestamp []byte,
	ca3sig *ManifestCASignature, ca3VK *ManifestCAPublicKey,
	st *CaptureStatement,
	proofBytes []byte,
) (bool, LedgerAnchor, error) {
	ledger, err := VerifyLedgerAnchor(ctx, src, timestamp)
	if err != nil {
		return false, LedgerAnchor{}, err
	}
	ok, err := CaptureVerifyBoundTrusted(anchor, crs, raw, bitCount, manifest, timestamp, ca3sig, ca3VK, st, proofBytes)
	if err != nil || !ok {
		return false, LedgerAnchor{}, err
	}
	return true, ledger, nil
}
