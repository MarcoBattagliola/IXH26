package capture

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// publishT1 simulates the device publishing commitment d in a transaction
// validated in a ledger `gap` ledgers and `delay` seconds after base.
func publishT1(src *fakeLedgerSource, base LedgerAnchor, d [32]byte, gap, delay uint32) (T1Anchor, LedgerAnchor) {
	l := LedgerAnchor{NetworkID: base.NetworkID, LedgerIndex: base.LedgerIndex + gap, CloseTime: base.CloseTime + delay}
	l.LedgerHash = sha256.Sum256(append([]byte("ledger"), l.Encode()...))
	src.addLedger(l)
	txHash := sha256.Sum256(append([]byte("tx"), d[:]...))
	src.txs[txHash] = XRPLTransaction{
		Hash: txHash, LedgerIndex: l.LedgerIndex, Validated: true, Result: "tesSUCCESS",
		Memos: []XRPLMemo{{Type: []byte("unrelated"), Data: []byte{1}}, {Type: []byte(T1MemoType), Data: d[:]}},
	}
	return T1Anchor{NetworkID: base.NetworkID, TxHash: txHash, LedgerIndex: l.LedgerIndex}, l
}

func TestT1AnchorEncodeDecode(t *testing.T) {
	a := T1Anchor{NetworkID: XRPLNetworkTestnet, LedgerIndex: 77}
	a.TxHash[3] = 9
	enc := a.Encode()
	if len(enc) != T1AnchorEncodedSize {
		t.Fatalf("size %d", len(enc))
	}
	got, err := DecodeT1Anchor(enc)
	if err != nil || got != a {
		t.Fatalf("roundtrip %v", err)
	}
	for i, b := range [][]byte{nil, enc[:len(enc)-1], append(append([]byte(nil), enc...), 0), testLedgerAnchor().Encode()} {
		if _, err := DecodeT1Anchor(b); err == nil {
			t.Fatalf("case %d accepted", i)
		}
	}
}

func TestCaptureCommitmentBindsEverything(t *testing.T) {
	f := makeCaptureFixture(t)
	p := mustProve(t, f)
	data, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	base, err := CaptureCommitment(&f.Statement, data)
	if err != nil {
		t.Fatal(err)
	}
	mods := map[string]func(*CaptureStatement, []byte) []byte{
		"M":     func(st *CaptureStatement, d []byte) []byte { st.M = differentG1Point(st.M); return d },
		"R_s":   func(st *CaptureStatement, d []byte) []byte { st.SensorR = differentG1Point(st.SensorR); return d },
		"R_e":   func(st *CaptureStatement, d []byte) []byte { st.EnclaveR = differentG1Point(st.EnclaveR); return d },
		"proof": func(st *CaptureStatement, d []byte) []byte { d = append([]byte(nil), d...); d[10] ^= 1; return d },
	}
	for name, mod := range mods {
		st := f.Statement
		d := mod(&st, data)
		c, err := CaptureCommitment(&st, d)
		if err != nil || c == base {
			t.Fatalf("commitment does not bind %s", name)
		}
	}
}

func TestVerifyT1Anchor(t *testing.T) {
	t0 := testLedgerAnchor()
	var d [32]byte
	d[0] = 0x42
	ctx := context.Background()

	src := newFakeLedgerSource(XRPLNetworkTestnet, t0)
	t1, _ := publishT1(src, t0, d, 3, 10)
	w, err := VerifyT1Anchor(ctx, src, t0, t1.Encode(), d, DefaultCaptureMaxWindow)
	if err != nil || w.Width() != 10*time.Second || w.T1 != t1 {
		t.Fatalf("valid T1 rejected: %v %v", err, w)
	}

	t.Run("backdated_T0", func(t *testing.T) {
		// Attacker anchors M to a 1-hour-old ledger; T1 can only be "now".
		s := newFakeLedgerSource(XRPLNetworkTestnet, t0)
		late, _ := publishT1(s, t0, d, 900, 3600)
		if _, err := VerifyT1Anchor(ctx, s, t0, late.Encode(), d, DefaultCaptureMaxWindow); err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("backdated capture not rejected by the window check: %v", err)
		}
	})
	t.Run("wrong_commitment", func(t *testing.T) {
		other := d
		other[31] ^= 1
		if _, err := VerifyT1Anchor(ctx, src, t0, t1.Encode(), other, DefaultCaptureMaxWindow); err == nil || !strings.Contains(err.Error(), "commitment") {
			t.Fatalf("foreign commitment not rejected by the memo check: %v", err)
		}
	})
	t.Run("T1_not_after_T0", func(t *testing.T) {
		s := newFakeLedgerSource(XRPLNetworkTestnet, t0)
		before := LedgerAnchor{NetworkID: t0.NetworkID, LedgerIndex: t0.LedgerIndex - 5, CloseTime: t0.CloseTime - 20}
		early, _ := publishT1(s, before, d, 0, 0)
		if _, err := VerifyT1Anchor(ctx, s, t0, early.Encode(), d, DefaultCaptureMaxWindow); err == nil {
			t.Fatal("T1 before T0 accepted")
		}
	})
	txCases := map[string]func(*XRPLTransaction){
		"not_validated": func(tx *XRPLTransaction) { tx.Validated = false },
		"failed_tx":     func(tx *XRPLTransaction) { tx.Result = "tecNO_DST" },
		"other_ledger":  func(tx *XRPLTransaction) { tx.LedgerIndex++ },
		"wrong_memo":    func(tx *XRPLTransaction) { tx.Memos = []XRPLMemo{{Type: []byte("x"), Data: d[:]}} },
		"other_tx_hash": func(tx *XRPLTransaction) { tx.Hash[0] ^= 1 },
	}
	for name, mod := range txCases {
		t.Run(name, func(t *testing.T) {
			s := newFakeLedgerSource(XRPLNetworkTestnet, t0)
			a, _ := publishT1(s, t0, d, 3, 10)
			tx := s.txs[a.TxHash]
			mod(&tx)
			s.txs[a.TxHash] = tx
			if _, err := VerifyT1Anchor(ctx, s, t0, a.Encode(), d, DefaultCaptureMaxWindow); err == nil {
				t.Fatal("bad T1 transaction accepted")
			}
		})
	}
	t.Run("network", func(t *testing.T) {
		wrong := t1
		wrong.NetworkID = XRPLNetworkMainnet
		if _, err := VerifyT1Anchor(ctx, src, t0, wrong.Encode(), d, DefaultCaptureMaxWindow); err == nil {
			t.Fatal("cross-network T1 accepted")
		}
	})
}

// rippled-shaped `tx` replies, API v1 (top-level fields) and v2 (tx_json).
func TestXRPLClientParsesTxResponse(t *testing.T) {
	var h [32]byte
	h[0] = 0xEE
	hashHex := strings.ToUpper(hex.EncodeToString(h[:]))
	memo := `[{"Memo":{"MemoType":"` + strings.ToUpper(hex.EncodeToString([]byte(T1MemoType))) + `","MemoData":"` + strings.Repeat("AB", 32) + `"}}]`
	v1 := `{"result":{"Account":"rTest","TransactionType":"AccountSet","Memos":` + memo +
		`,"hash":"` + hashHex + `","ledger_index":5123459,"meta":{"TransactionResult":"tesSUCCESS"},"validated":true,"status":"success"}}`
	v2 := `{"result":{"tx_json":{"Account":"rTest","TransactionType":"AccountSet","Memos":` + memo +
		`},"hash":"` + hashHex + `","ledger_index":5123459,"meta":{"TransactionResult":"tesSUCCESS"},"validated":true,"status":"success"}}`
	reply := v1
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"method":"tx"`) || !strings.Contains(string(body), hashHex) {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		io.WriteString(w, reply)
	}))
	defer srv.Close()
	c := NewXRPLClient(srv.URL, XRPLNetworkTestnet)
	for name, body := range map[string]string{"api_v1": v1, "api_v2": v2} {
		reply = body
		tx, err := c.TransactionByHash(context.Background(), h)
		if err != nil || tx.Hash != h || !tx.Validated || tx.Result != "tesSUCCESS" || tx.LedgerIndex != 5123459 {
			t.Fatalf("%s: %v %+v", name, err, tx)
		}
		if len(tx.Memos) != 1 || string(tx.Memos[0].Type) != T1MemoType || len(tx.Memos[0].Data) != 32 {
			t.Fatalf("%s: memos %+v", name, tx.Memos)
		}
	}
	reply = `{"result":{"error":"txnNotFound","status":"error"}}`
	if _, err := c.TransactionByHash(context.Background(), h); err == nil {
		t.Fatal("txnNotFound accepted")
	}
}

func TestCaptureVerifyAnchoredTrusted(t *testing.T) {
	f := makeCaptureFixture(t)
	p := mustProve(t, f)
	data, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	d, err := CaptureCommitment(&f.Statement, data)
	if err != nil {
		t.Fatal(err)
	}
	t1, _ := publishT1(f.LedgerSource, f.Ledger, d, 4, 12)
	verify := func(src LedgerSource, t0, t1 []byte, proof []byte) (bool, CaptureWindow, error) {
		return CaptureVerifyAnchoredTrusted(context.Background(), src, f.Anchor, f.CRS,
			f.Bits, f.BitCount, f.Manifest, t0, t1, DefaultCaptureMaxWindow,
			&f.CA3Certificate, &f.CA3VK, &f.Statement, proof)
	}
	ok, w, err := verify(f.LedgerSource, f.Timestamp, t1.Encode(), data)
	if err != nil || !ok || w.T0 != f.Ledger || w.Width() != 12*time.Second {
		t.Fatalf("valid capture rejected: %v %v %v", ok, err, w)
	}
	t.Run("backdated_capture", func(t *testing.T) {
		// Same photo and proof, but T1 published an hour after the (old) T0.
		src := newFakeLedgerSource(XRPLNetworkTestnet, f.Ledger)
		late, _ := publishT1(src, f.Ledger, d, 900, 3600)
		if ok, _, err := verify(src, f.Timestamp, late.Encode(), data); ok || err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("backdated capture not rejected by the window check: %v %v", ok, err)
		}
	})
	t.Run("missing_T1", func(t *testing.T) {
		src := newFakeLedgerSource(XRPLNetworkTestnet, f.Ledger)
		if ok, _, _ := verify(src, f.Timestamp, t1.Encode(), data); ok {
			t.Fatal("capture without published T1 accepted")
		}
	})
	t.Run("T1_of_another_capture", func(t *testing.T) {
		var other [32]byte
		other[0] = 1
		src := newFakeLedgerSource(XRPLNetworkTestnet, f.Ledger)
		foreign, _ := publishT1(src, f.Ledger, other, 4, 12)
		if ok, _, _ := verify(src, f.Timestamp, foreign.Encode(), data); ok {
			t.Fatal("foreign T1 accepted")
		}
	})
	t.Run("ledger_unknown_to_pcc_node", func(t *testing.T) {
		if ok, _, _ := verify(newFakeLedgerSource(XRPLNetworkTestnet), f.Timestamp, t1.Encode(), data); ok {
			t.Fatal("unknown T0 ledger accepted")
		}
	})
	t.Run("pcc_pins_other_network", func(t *testing.T) {
		if ok, _, _ := verify(newFakeLedgerSource(XRPLNetworkMainnet, f.Ledger), f.Timestamp, t1.Encode(), data); ok {
			t.Fatal("cross-network anchor accepted")
		}
	})
	t.Run("swapped_T0", func(t *testing.T) {
		older := f.Ledger
		older.LedgerIndex -= 100
		older.CloseTime -= 400
		older.LedgerHash[31] ^= 0xFF
		src := newFakeLedgerSource(XRPLNetworkTestnet, older, f.Ledger)
		a, _ := publishT1(src, f.Ledger, d, 4, 12)
		if ok, _, _ := verify(src, older.Encode(), a.Encode(), data); ok {
			t.Fatal("swapped T0 accepted")
		}
	})
	t.Run("free_form_timestamp", func(t *testing.T) {
		if ok, _, _ := verify(f.LedgerSource, []byte("2026-11-21T00:00:00Z"), t1.Encode(), data); ok {
			t.Fatal("non-ledger timestamp accepted")
		}
	})
}
