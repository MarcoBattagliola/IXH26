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
	"time"
)

// CA registry on XRPL: key activation and revocation.
//
// A governance XRPL account (pinned by the PCC, ideally protected by XRPL
// multisign) publishes events in transaction memos:
//
//	ACTIVATE(role, keyID)                    the key may be used from now on
//	REVOKE(role, keyID, compromisedSince)    the key is untrusted from ledger compromisedSince
//
// A capture that uses key K is accepted only if K was activated no later than
// the T0 ledger (T0 is a closed ledger, so signing happens after it) and,
// if K was revoked, the capture's T1 ledger is BEFORE compromisedSince. T1
// cannot be backdated, so a thief of K cannot produce captures that appear to
// predate the compromise, while genuine older captures stay valid.
//
// The PCC no longer pins individual CA keys: it pins the registry account and
// accepts keys from the artifact only if their keyID is registered. CA1, CA2,
// CA3 and the global CRS are all registry-controlled.

const (
	RegistryMemoType     = "HACKATON2026_CA_REGISTRY"
	RegistryEventVersion = "HACKATON2026_CA_REGISTRY_V1"
	registryKeyIDTag     = "HACKATON2026_CA_KEYID_V1"
)

// RegistryEventEncodedSize: version || op || role || keyID || compromisedSince.
const RegistryEventEncodedSize = len(RegistryEventVersion) + 1 + 1 + 32 + 4

type RegistryRole uint8

const (
	RoleCA1 RegistryRole = 1 // Jutla-Roy CA for sensor keys
	RoleCA2 RegistryRole = 2 // Jutla-Roy CA for enclave keys
	RoleCA3 RegistryRole = 3 // Schnorr manifest CA
	RoleCRS RegistryRole = 4 // global Groth-Sahai CRS
)

func (r RegistryRole) String() string {
	switch r {
	case RoleCA1:
		return "CA1"
	case RoleCA2:
		return "CA2"
	case RoleCA3:
		return "CA3"
	case RoleCRS:
		return "CRS"
	}
	return fmt.Sprintf("role(%d)", uint8(r))
}

type RegistryOp uint8

const (
	OpActivate RegistryOp = 1
	OpRevoke   RegistryOp = 2
)

// RegistryEvent is one entry of the registry. Ledger and TxHash come from the
// XRPL transaction that carried it, not from the memo.
type RegistryEvent struct {
	Op               RegistryOp
	Role             RegistryRole
	KeyID            [32]byte
	CompromisedSince uint32 // REVOKE only: first untrusted ledger
	Ledger           uint32
	TxHash           [32]byte
}

// Encode returns the canonical memo payload.
func (e RegistryEvent) Encode() []byte {
	out := make([]byte, 0, RegistryEventEncodedSize)
	out = append(out, RegistryEventVersion...)
	out = append(out, byte(e.Op), byte(e.Role))
	out = append(out, e.KeyID[:]...)
	return binary.BigEndian.AppendUint32(out, e.CompromisedSince)
}

// DecodeRegistryEvent is the strict inverse of Encode.
func DecodeRegistryEvent(b []byte) (RegistryEvent, error) {
	var e RegistryEvent
	if len(b) != RegistryEventEncodedSize || !bytes.HasPrefix(b, []byte(RegistryEventVersion)) {
		return e, errors.New("invalid registry event encoding")
	}
	p := b[len(RegistryEventVersion):]
	e.Op, e.Role = RegistryOp(p[0]), RegistryRole(p[1])
	copy(e.KeyID[:], p[2:34])
	e.CompromisedSince = binary.BigEndian.Uint32(p[34:38])
	if e.Role < RoleCA1 || e.Role > RoleCRS || e.KeyID == ([32]byte{}) {
		return RegistryEvent{}, errors.New("invalid registry event fields")
	}
	switch e.Op {
	case OpActivate:
		if e.CompromisedSince != 0 {
			return RegistryEvent{}, errors.New("ACTIVATE must not carry compromisedSince")
		}
	case OpRevoke:
		if e.CompromisedSince == 0 {
			return RegistryEvent{}, errors.New("REVOKE requires compromisedSince")
		}
	default:
		return RegistryEvent{}, errors.New("unknown registry operation")
	}
	return e, nil
}

// ---- key identifiers -------------------------------------------------------

func registryKeyID(role RegistryRole, keyBytes []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(registryKeyIDTag))
	h.Write([]byte{byte(role)})
	h.Write(keyBytes)
	var id [32]byte
	copy(id[:], h.Sum(nil))
	return id
}

// KeyIDJR identifies a Jutla-Roy CA key (role CA1 or CA2).
func KeyIDJR(role RegistryRole, vk *Vk) ([32]byte, error) {
	if role != RoleCA1 && role != RoleCA2 {
		return [32]byte{}, errors.New("JR keys are CA1 or CA2")
	}
	if !vk.IsSet() {
		return [32]byte{}, errors.New("unset JR VK")
	}
	cp := *vk // CompressToAndClear clears its receiver
	buf := make([]byte, VkCompressedSize)
	if err := cp.CompressToAndClear(buf); err != nil {
		return [32]byte{}, err
	}
	return registryKeyID(role, buf), nil
}

// KeyIDCA3 identifies the manifest CA key.
func KeyIDCA3(pk *ManifestCAPublicKey) ([32]byte, error) {
	if pk == nil || !pk.IsSet() {
		return [32]byte{}, errors.New("unset CA3 key")
	}
	b, err := pk.MarshalBinary()
	if err != nil {
		return [32]byte{}, err
	}
	return registryKeyID(RoleCA3, b), nil
}

// KeyIDCRS identifies the global Groth-Sahai CRS.
func KeyIDCRS(crs CaptureCRS) ([32]byte, error) {
	b, err := crs.MarshalBinary()
	if err != nil {
		return [32]byte{}, err
	}
	return registryKeyID(RoleCRS, b), nil
}

// ---- registry state --------------------------------------------------------

// KeyStatus is the reconstructed history of one key.
type KeyStatus struct {
	Role             RegistryRole
	ActivatedLedger  uint32 // 0 if never activated
	RevokedLedger    uint32 // 0 if never revoked
	CompromisedSince uint32 // earliest declared, 0 if never revoked
}

// CARegistry is the registry state rebuilt from the governance account history.
type CARegistry struct {
	Account   string
	NetworkID uint32
	Keys      map[[32]byte]KeyStatus
}

// BuildCARegistry replays events in ledger order. The first ACTIVATE of a
// key counts; a revoked key cannot be re-activated; several REVOKEs keep the
// earliest compromisedSince. compromisedSince is clamped to the revocation
// ledger (a key cannot be declared trusted after it was revoked).
func BuildCARegistry(account string, networkID uint32, events []RegistryEvent) (*CARegistry, error) {
	reg := &CARegistry{Account: account, NetworkID: networkID, Keys: map[[32]byte]KeyStatus{}}
	var last uint32
	for _, e := range events {
		if e.Ledger == 0 || e.Ledger < last {
			return nil, errors.New("registry events must be in ledger order")
		}
		last = e.Ledger
		st, known := reg.Keys[e.KeyID]
		if known && st.Role != e.Role {
			return nil, fmt.Errorf("key %x registered under two roles", e.KeyID[:4])
		}
		st.Role = e.Role
		switch e.Op {
		case OpActivate:
			if st.ActivatedLedger == 0 && st.RevokedLedger == 0 {
				st.ActivatedLedger = e.Ledger
			}
		case OpRevoke:
			cs := e.CompromisedSince
			if cs > e.Ledger {
				cs = e.Ledger
			}
			if st.RevokedLedger == 0 {
				st.RevokedLedger = e.Ledger
			}
			if st.CompromisedSince == 0 || cs < st.CompromisedSince {
				st.CompromisedSince = cs
			}
		}
		reg.Keys[e.KeyID] = st
	}
	return reg, nil
}

// CheckKey applies the registry rule to one key used by a capture whose
// verified window is [t0Ledger, t1Ledger].
func (r *CARegistry) CheckKey(role RegistryRole, id [32]byte, t0Ledger, t1Ledger uint32) error {
	if r == nil {
		return errors.New("nil CA registry")
	}
	st, ok := r.Keys[id]
	if !ok || st.ActivatedLedger == 0 {
		return fmt.Errorf("%s key %x is not registered", role, id[:4])
	}
	if st.Role != role {
		return fmt.Errorf("%s key %x is registered as %s", role, id[:4], st.Role)
	}
	if st.ActivatedLedger > t0Ledger {
		return fmt.Errorf("%s key %x activated in ledger %d, after T0 (%d)", role, id[:4], st.ActivatedLedger, t0Ledger)
	}
	if st.CompromisedSince != 0 && t1Ledger >= st.CompromisedSince {
		return fmt.Errorf("%s key %x revoked: compromised since ledger %d, capture published in ledger %d",
			role, id[:4], st.CompromisedSince, t1Ledger)
	}
	return nil
}

// ---- reading the registry from XRPL ----------------------------------------

// XRPLAccountTx is one transaction from an account's history.
type XRPLAccountTx struct {
	Hash        [32]byte
	Account     string // sender
	LedgerIndex uint32
	Validated   bool
	Result      string
	Memos       []XRPLMemo
}

// AccountHistorySource lists every transaction involving an account, oldest first.
type AccountHistorySource interface {
	AccountTransactions(ctx context.Context, account string) ([]XRPLAccountTx, error)
}

type xrplAccountTxEntry struct {
	Validated   bool            `json:"validated"`
	Hash        string          `json:"hash"`         // API v2
	LedgerIndex uint32          `json:"ledger_index"` // API v2
	Meta        json.RawMessage `json:"meta"`
	Tx          *xrplTxFields   `json:"tx"`      // API v1
	TxJSON      *xrplTxFields   `json:"tx_json"` // API v2
}

type xrplTxFields struct {
	Account     string            `json:"Account"`
	Hash        string            `json:"hash"`
	LedgerIndex uint32            `json:"ledger_index"`
	Memos       []xrplMemoWrapper `json:"Memos"`
}

type xrplAccountTxResponse struct {
	Result struct {
		Status       string               `json:"status"`
		Error        string               `json:"error"`
		Transactions []xrplAccountTxEntry `json:"transactions"`
		Marker       json.RawMessage      `json:"marker"`
	} `json:"result"`
}

// AccountTransactions pages through account_tx (oldest first). The node must
// hold the account's full history.
func (c *XRPLClient) AccountTransactions(ctx context.Context, account string) ([]XRPLAccountTx, error) {
	var out []XRPLAccountTx
	var marker json.RawMessage
	for page := 0; page < 1000; page++ {
		params := map[string]any{
			"account": account, "ledger_index_min": -1, "ledger_index_max": -1,
			"forward": true, "limit": 200, "binary": false,
		}
		if len(marker) > 0 && string(marker) != "null" {
			params["marker"] = marker
		}
		var r xrplAccountTxResponse
		if err := c.rpc(ctx, "account_tx", params, &r); err != nil {
			return nil, err
		}
		if r.Result.Status != "success" {
			return nil, fmt.Errorf("xrpl account_tx: status=%q error=%q", r.Result.Status, r.Result.Error)
		}
		for _, e := range r.Result.Transactions {
			tx, err := accountTxFromEntry(e)
			if err != nil {
				return nil, err
			}
			out = append(out, tx)
		}
		marker = r.Result.Marker
		if len(marker) == 0 || string(marker) == "null" {
			return out, nil
		}
	}
	return nil, errors.New("xrpl account_tx: too many pages")
}

func accountTxFromEntry(e xrplAccountTxEntry) (XRPLAccountTx, error) {
	var tx XRPLAccountTx
	f := e.TxJSON
	if f == nil {
		f = e.Tx
	}
	if f == nil {
		return tx, errors.New("xrpl account_tx: entry without transaction (request binary=false)")
	}
	hashHex, idx := e.Hash, e.LedgerIndex
	if hashHex == "" {
		hashHex = f.Hash
	}
	if idx == 0 {
		idx = f.LedgerIndex
	}
	h, err := hex.DecodeString(hashHex)
	if err != nil || len(h) != 32 {
		return tx, errors.New("xrpl account_tx: invalid transaction hash")
	}
	copy(tx.Hash[:], h)
	tx.Account, tx.LedgerIndex, tx.Validated = f.Account, idx, e.Validated
	if len(e.Meta) > 0 {
		var meta struct {
			TransactionResult string `json:"TransactionResult"`
		}
		if json.Unmarshal(e.Meta, &meta) != nil {
			return tx, errors.New("xrpl account_tx: unsupported metadata (request binary=false)")
		}
		tx.Result = meta.TransactionResult
	}
	tx.Memos = decodeMemos(f.Memos)
	return tx, nil
}

func decodeMemos(ms []xrplMemoWrapper) []XRPLMemo {
	var out []XRPLMemo
	for _, m := range ms {
		typ, err1 := hex.DecodeString(m.Memo.MemoType)
		data, err2 := hex.DecodeString(m.Memo.MemoData)
		if err1 == nil && err2 == nil {
			out = append(out, XRPLMemo{Type: typ, Data: data})
		}
	}
	return out
}

// RegistryEventsFromHistory extracts registry events from an account history.
// Only validated, successful transactions SENT BY the governance account
// count: anyone can send a transaction with a memo TO that account.
func RegistryEventsFromHistory(account string, txs []XRPLAccountTx) ([]RegistryEvent, error) {
	var events []RegistryEvent
	for _, tx := range txs {
		if tx.Account != account || !tx.Validated || tx.Result != "tesSUCCESS" {
			continue
		}
		for _, m := range tx.Memos {
			if string(m.Type) != RegistryMemoType {
				continue
			}
			e, err := DecodeRegistryEvent(m.Data)
			if err != nil {
				return nil, fmt.Errorf("registry tx %X: %w", tx.Hash, err)
			}
			e.Ledger, e.TxHash = tx.LedgerIndex, tx.Hash
			events = append(events, e)
		}
	}
	return events, nil
}

// FetchCARegistry reads and rebuilds the registry of a governance account.
func FetchCARegistry(ctx context.Context, src AccountHistorySource, account string, networkID uint32) (*CARegistry, error) {
	if src == nil || account == "" {
		return nil, errors.New("missing registry source or account")
	}
	txs, err := src.AccountTransactions(ctx, account)
	if err != nil {
		return nil, err
	}
	events, err := RegistryEventsFromHistory(account, txs)
	if err != nil {
		return nil, err
	}
	return BuildCARegistry(account, networkID, events)
}

// ---- full PCC verification -------------------------------------------------

// CaptureVerifyWithRegistry is the PCC entry point when CA keys are managed
// by the XRPL registry. The CA keys and CRS come with the artifact and are
// accepted only if the registry vouches for them for this capture's window:
// full XRPL T0/T1 + NIZK verification, then the registry rule per key.
func CaptureVerifyWithRegistry(
	ctx context.Context,
	src LedgerSource,
	reg *CARegistry,
	crs CaptureCRS,
	raw []byte, bitCount int,
	manifest, t0, t1 []byte,
	maxWindow time.Duration,
	ca3sig *ManifestCASignature, ca3VK *ManifestCAPublicKey,
	st *CaptureStatement,
	proofBytes []byte,
) (bool, CaptureWindow, error) {
	if reg == nil || st == nil {
		return false, CaptureWindow{}, errors.New("missing registry or statement")
	}
	if src == nil || reg.NetworkID != src.NetworkID() {
		return false, CaptureWindow{}, errors.New("registry and ledger source are on different XRPL networks")
	}
	// Keys come from the artifact; the registry (checked below) authenticates them.
	anchor, err := NewCaptureTrustAnchor(&st.VK1, &st.VK2, ca3VK, crs)
	if err != nil {
		return false, CaptureWindow{}, err
	}
	ok, w, err := CaptureVerifyAnchoredTrusted(ctx, src, anchor, crs, raw, bitCount, manifest, t0, t1,
		maxWindow, ca3sig, ca3VK, st, proofBytes)
	if err != nil || !ok {
		return false, CaptureWindow{}, err
	}
	id1, err := KeyIDJR(RoleCA1, &st.VK1)
	if err != nil {
		return false, CaptureWindow{}, err
	}
	id2, err := KeyIDJR(RoleCA2, &st.VK2)
	if err != nil {
		return false, CaptureWindow{}, err
	}
	id3, err := KeyIDCA3(ca3VK)
	if err != nil {
		return false, CaptureWindow{}, err
	}
	idCRS, err := KeyIDCRS(crs)
	if err != nil {
		return false, CaptureWindow{}, err
	}
	t0L, t1L := w.T0.LedgerIndex, w.T1Ledger.LedgerIndex
	for _, k := range []struct {
		role RegistryRole
		id   [32]byte
	}{{RoleCA1, id1}, {RoleCA2, id2}, {RoleCA3, id3}, {RoleCRS, idCRS}} {
		if err := reg.CheckKey(k.role, k.id, t0L, t1L); err != nil {
			return false, CaptureWindow{}, err
		}
	}
	return true, w, nil
}
