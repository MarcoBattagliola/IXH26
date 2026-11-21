package capture

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// T1 = an XRPL transaction that publishes a commitment to the finished capture.
//
// T0 (XRPLAnchor.go) is inside M, so it must exist BEFORE the layers sign:
// "not before". On its own it allows backdating, because an old ledger is
// still a valid ledger. T1 closes the window: after signing and proving, the
// device publishes
//
//	D = SHA-256(T1CommitmentTag || M || R_s || R_e || len(proof) || proof)
//
// in the Memo of an XRPL transaction. R_s and R_e are fresh signing nonces,
// so D cannot exist before the hardware signatures: the ledger that includes
// the transaction is a "not after" bound. The PCC requires
//
//	ledger(T0) < ledger(T1)  and  close_time(T1) - close_time(T0) <= maxWindow
//
// so the hardware signing time is pinned to [T0, T1] without trusting the
// device. T1 is outside M and outside the NIZK: proof format and sizes are
// unchanged.

const (
	T1CommitmentTag = "HACKATON2026_T1_COMMIT_V1"
	T1MemoType      = "HACKATON2026_T1" // MemoType (hex-encoded on ledger)
	T1AnchorVersion = "HACKATON2026_XRPL_T1_ANCHOR_V1"
)

// T1AnchorEncodedSize: version || networkID || txHash || ledgerIndex.
const T1AnchorEncodedSize = len(T1AnchorVersion) + 4 + 32 + 4

// DefaultCaptureMaxWindow is the PCC policy on close_time(T1)-close_time(T0).
// Ledgers close every 3-5 s and close_time is rounded to ~10 s.
const DefaultCaptureMaxWindow = 60 * time.Second

// T1Anchor identifies the XRPL transaction carrying the capture commitment.
// It is stored in the DNG next to T0.
type T1Anchor struct {
	NetworkID   uint32
	TxHash      [32]byte
	LedgerIndex uint32
}

func (a T1Anchor) Encode() []byte {
	out := make([]byte, 0, T1AnchorEncodedSize)
	out = append(out, T1AnchorVersion...)
	out = binary.BigEndian.AppendUint32(out, a.NetworkID)
	out = append(out, a.TxHash[:]...)
	out = binary.BigEndian.AppendUint32(out, a.LedgerIndex)
	return out
}

// DecodeT1Anchor is the strict inverse of Encode.
func DecodeT1Anchor(b []byte) (T1Anchor, error) {
	var a T1Anchor
	if len(b) != T1AnchorEncodedSize || !bytes.HasPrefix(b, []byte(T1AnchorVersion)) {
		return a, errors.New("invalid XRPL T1 anchor encoding")
	}
	p := b[len(T1AnchorVersion):]
	a.NetworkID = binary.BigEndian.Uint32(p[0:4])
	copy(a.TxHash[:], p[4:36])
	a.LedgerIndex = binary.BigEndian.Uint32(p[36:40])
	if a.LedgerIndex == 0 || a.TxHash == ([32]byte{}) {
		return T1Anchor{}, errors.New("invalid XRPL T1 anchor fields")
	}
	return a, nil
}

// CaptureCommitment computes D, the value published in the T1 memo. It binds
// M (hence bits, manifest and T0), both public signing nonces and the exact
// serialized NIZK.
func CaptureCommitment(st *CaptureStatement, proofBytes []byte) ([32]byte, error) {
	if st == nil || len(proofBytes) == 0 {
		return [32]byte{}, errors.New("missing statement or proof")
	}
	h := sha256.New()
	h.Write([]byte(T1CommitmentTag))
	h.Write(st.M.Compress())
	h.Write(st.SensorR.Compress())
	h.Write(st.EnclaveR.Compress())
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(proofBytes)))
	h.Write(n[:])
	h.Write(proofBytes)
	var d [32]byte
	copy(d[:], h.Sum(nil))
	return d, nil
}

// XRPLMemo is one decoded Memo (MemoType/MemoData are hex on the ledger).
type XRPLMemo struct {
	Type, Data []byte
}

// XRPLTransaction is the subset of a `tx` reply the PCC needs.
type XRPLTransaction struct {
	Hash        [32]byte
	LedgerIndex uint32
	Validated   bool
	Result      string // meta.TransactionResult, e.g. "tesSUCCESS"
	Memos       []XRPLMemo
}

type xrplMemoWrapper struct {
	Memo struct {
		MemoType string `json:"MemoType"`
		MemoData string `json:"MemoData"`
	} `json:"Memo"`
}

// Accepts both API v1 (fields at top level) and API v2 (fields in tx_json).
type xrplTxResponse struct {
	Result struct {
		Status      string            `json:"status"`
		Error       string            `json:"error"`
		Validated   bool              `json:"validated"`
		Hash        string            `json:"hash"`
		LedgerIndex uint32            `json:"ledger_index"`
		Meta        json.RawMessage   `json:"meta"`
		Memos       []xrplMemoWrapper `json:"Memos"`
		TxJSON      *struct {
			Memos []xrplMemoWrapper `json:"Memos"`
		} `json:"tx_json"`
	} `json:"result"`
}

// TransactionByHash looks up a transaction with the rippled `tx` method.
func (c *XRPLClient) TransactionByHash(ctx context.Context, hash [32]byte) (XRPLTransaction, error) {
	var r xrplTxResponse
	params := map[string]any{"transaction": strings.ToUpper(hex.EncodeToString(hash[:])), "binary": false}
	if err := c.rpc(ctx, "tx", params, &r); err != nil {
		return XRPLTransaction{}, err
	}
	return txFromXRPLResponse(&r)
}

func txFromXRPLResponse(r *xrplTxResponse) (XRPLTransaction, error) {
	var tx XRPLTransaction
	res := r.Result
	if res.Status != "success" {
		return tx, fmt.Errorf("xrpl rpc: status=%q error=%q", res.Status, res.Error)
	}
	h, err := hex.DecodeString(res.Hash)
	if err != nil || len(h) != 32 {
		return tx, errors.New("xrpl: invalid transaction hash")
	}
	copy(tx.Hash[:], h)
	tx.LedgerIndex = res.LedgerIndex
	tx.Validated = res.Validated
	if len(res.Meta) > 0 {
		var meta struct {
			TransactionResult string `json:"TransactionResult"`
		}
		if json.Unmarshal(res.Meta, &meta) != nil {
			return tx, errors.New("xrpl: unsupported transaction metadata (request binary=false)")
		}
		tx.Result = meta.TransactionResult
	}
	memos := res.Memos
	if res.TxJSON != nil && len(res.TxJSON.Memos) > 0 {
		memos = res.TxJSON.Memos
	}
	for _, m := range memos {
		typ, err1 := hex.DecodeString(m.Memo.MemoType)
		data, err2 := hex.DecodeString(m.Memo.MemoData)
		if err1 != nil || err2 != nil {
			continue // not one of ours
		}
		tx.Memos = append(tx.Memos, XRPLMemo{Type: typ, Data: data})
	}
	return tx, nil
}

// CaptureWindow is the verified interval in which the hardware signed.
type CaptureWindow struct {
	T0       LedgerAnchor // ledger hashed into M: not before
	T1       T1Anchor     // transaction carrying the commitment
	T1Ledger LedgerAnchor // ledger that validated T1: not after
}

func (w CaptureWindow) NotBefore() time.Time { return w.T0.Time() }
func (w CaptureWindow) NotAfter() time.Time  { return w.T1Ledger.Time() }
func (w CaptureWindow) Width() time.Duration { return w.NotAfter().Sub(w.NotBefore()) }
func (w CaptureWindow) String() string {
	return fmt.Sprintf("[%s, %s] (%v, ledgers #%d..#%d)",
		w.NotBefore().Format(time.RFC3339), w.NotAfter().Format(time.RFC3339),
		w.Width(), w.T0.LedgerIndex, w.T1Ledger.LedgerIndex)
}

// VerifyT1Anchor checks that the T1 transaction is validated and successful,
// carries the expected commitment, and closes at most maxWindow after T0.
// t0 must already be verified with VerifyLedgerAnchor on the same src.
func VerifyT1Anchor(ctx context.Context, src LedgerSource, t0 LedgerAnchor, t1Bytes []byte,
	commitment [32]byte, maxWindow time.Duration) (CaptureWindow, error) {
	if src == nil {
		return CaptureWindow{}, errors.New("nil ledger source")
	}
	if maxWindow <= 0 {
		return CaptureWindow{}, errors.New("maxWindow must be positive")
	}
	t1, err := DecodeT1Anchor(t1Bytes)
	if err != nil {
		return CaptureWindow{}, err
	}
	if t1.NetworkID != src.NetworkID() || t0.NetworkID != t1.NetworkID {
		return CaptureWindow{}, errors.New("T1 anchor from untrusted XRPL network")
	}
	tx, err := src.TransactionByHash(ctx, t1.TxHash)
	if err != nil {
		return CaptureWindow{}, err
	}
	if tx.Hash != t1.TxHash {
		return CaptureWindow{}, errors.New("T1: node returned a different transaction")
	}
	if !tx.Validated || tx.Result != "tesSUCCESS" {
		return CaptureWindow{}, fmt.Errorf("T1: transaction not validated/successful (validated=%v result=%q)", tx.Validated, tx.Result)
	}
	if tx.LedgerIndex != t1.LedgerIndex {
		return CaptureWindow{}, errors.New("T1: transaction is in a different ledger")
	}
	found := false
	for _, m := range tx.Memos {
		if string(m.Type) == T1MemoType && bytes.Equal(m.Data, commitment[:]) {
			found = true
			break
		}
	}
	if !found {
		return CaptureWindow{}, errors.New("T1: transaction does not carry this capture's commitment")
	}
	ledger, err := src.LedgerByIndex(ctx, t1.LedgerIndex)
	if err != nil {
		return CaptureWindow{}, err
	}
	if ledger.LedgerIndex != t1.LedgerIndex || ledger.NetworkID != t1.NetworkID {
		return CaptureWindow{}, errors.New("T1: ledger mismatch")
	}
	w := CaptureWindow{T0: t0, T1: t1, T1Ledger: ledger}
	if ledger.LedgerIndex <= t0.LedgerIndex || ledger.CloseTime < t0.CloseTime {
		return CaptureWindow{}, errors.New("T1 is not after T0")
	}
	if w.Width() > maxWindow {
		return CaptureWindow{}, fmt.Errorf("capture window %v exceeds %v (possible backdated T0)", w.Width(), maxWindow)
	}
	return w, nil
}

// CaptureVerifyAnchoredTrusted is the full PCC check: XRPL T0, CA3 signature,
// recomputed M, NIZK (CaptureVerifyBoundTrusted), then XRPL T1 and the
// [T0, T1] window. src must be chosen by the relying party (pinned node and
// network), never taken from the artifact.
func CaptureVerifyAnchoredTrusted(
	ctx context.Context,
	src LedgerSource,
	anchor CaptureTrustAnchor,
	crs CaptureCRS,
	raw []byte, bitCount int,
	manifest, t0, t1 []byte,
	maxWindow time.Duration,
	ca3sig *ManifestCASignature, ca3VK *ManifestCAPublicKey,
	st *CaptureStatement,
	proofBytes []byte,
) (bool, CaptureWindow, error) {
	ledger0, err := VerifyLedgerAnchor(ctx, src, t0)
	if err != nil {
		return false, CaptureWindow{}, err
	}
	ok, err := CaptureVerifyBoundTrusted(anchor, crs, raw, bitCount, manifest, t0, ca3sig, ca3VK, st, proofBytes)
	if err != nil || !ok {
		return false, CaptureWindow{}, err
	}
	commitment, err := CaptureCommitment(st, proofBytes)
	if err != nil {
		return false, CaptureWindow{}, err
	}
	w, err := VerifyT1Anchor(ctx, src, ledger0, t1, commitment, maxWindow)
	if err != nil {
		return false, CaptureWindow{}, err
	}
	return true, w, nil
}
