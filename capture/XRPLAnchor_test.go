package capture

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeLedgerSource is an offline XRPL stand-in: tests never touch the network.
type fakeLedgerSource struct {
	network uint32
	latest  LedgerAnchor
	byHash  map[[32]byte]LedgerAnchor
	byIndex map[uint32]LedgerAnchor
	txs     map[[32]byte]XRPLTransaction
}

func newFakeLedgerSource(network uint32, ledgers ...LedgerAnchor) *fakeLedgerSource {
	s := &fakeLedgerSource{network: network, byHash: map[[32]byte]LedgerAnchor{},
		byIndex: map[uint32]LedgerAnchor{}, txs: map[[32]byte]XRPLTransaction{}}
	for _, l := range ledgers {
		s.addLedger(l)
	}
	return s
}

func (s *fakeLedgerSource) addLedger(l LedgerAnchor) {
	s.byHash[l.LedgerHash] = l
	s.byIndex[l.LedgerIndex] = l
	s.latest = l
}

func (s *fakeLedgerSource) NetworkID() uint32 { return s.network }
func (s *fakeLedgerSource) LatestValidatedLedger(context.Context) (LedgerAnchor, error) {
	return s.latest, nil
}
func (s *fakeLedgerSource) LedgerByHash(_ context.Context, h [32]byte) (LedgerAnchor, error) {
	l, ok := s.byHash[h]
	if !ok {
		return LedgerAnchor{}, errors.New("lgrNotFound")
	}
	return l, nil
}
func (s *fakeLedgerSource) LedgerByIndex(_ context.Context, i uint32) (LedgerAnchor, error) {
	l, ok := s.byIndex[i]
	if !ok {
		return LedgerAnchor{}, errors.New("lgrNotFound")
	}
	return l, nil
}
func (s *fakeLedgerSource) TransactionByHash(_ context.Context, h [32]byte) (XRPLTransaction, error) {
	tx, ok := s.txs[h]
	if !ok {
		return XRPLTransaction{}, errors.New("txnNotFound")
	}
	return tx, nil
}

func testLedgerAnchor() LedgerAnchor {
	a := LedgerAnchor{NetworkID: XRPLNetworkTestnet, LedgerIndex: 5_123_456, CloseTime: 848_538_780}
	for i := range a.LedgerHash {
		a.LedgerHash[i] = byte(0xA0 + i)
	}
	return a
}

func TestLedgerAnchorEncodeDecode(t *testing.T) {
	a := testLedgerAnchor()
	enc := a.Encode()
	if len(enc) != LedgerAnchorEncodedSize {
		t.Fatalf("size %d", len(enc))
	}
	got, err := DecodeLedgerAnchor(enc)
	if err != nil || got != a {
		t.Fatalf("roundtrip %v %+v", err, got)
	}
	if !a.Time().Equal(time.Unix(int64(a.CloseTime)+946684800, 0)) {
		t.Fatal("ripple epoch conversion")
	}
	bad := [][]byte{nil, enc[:len(enc)-1], append(append([]byte(nil), enc...), 0),
		append([]byte("HACKATON2026_XRPL_LEDGER_ANCHOR_V2"), enc[len(LedgerAnchorVersion):]...)}
	for i, b := range bad {
		if _, err := DecodeLedgerAnchor(b); err == nil {
			t.Fatalf("case %d accepted", i)
		}
	}
	zero := a
	zero.LedgerHash = [32]byte{}
	if _, err := DecodeLedgerAnchor(zero.Encode()); err == nil {
		t.Fatal("zero hash accepted")
	}
}

func TestCaptureTimestampFreshness(t *testing.T) {
	a := testLedgerAnchor()
	src := newFakeLedgerSource(XRPLNetworkTestnet, a)
	ts, got, err := newCaptureTimestampAt(context.Background(), src, DefaultLedgerMaxAge, a.Time().Add(5*time.Second))
	if err != nil || got != a || !bytes.Equal(ts, a.Encode()) {
		t.Fatalf("fresh ledger rejected: %v", err)
	}
	if _, _, err = newCaptureTimestampAt(context.Background(), src, DefaultLedgerMaxAge, a.Time().Add(time.Minute)); err == nil {
		t.Fatal("stale ledger accepted")
	}
	if _, _, err = newCaptureTimestampAt(context.Background(), src, DefaultLedgerMaxAge, a.Time().Add(-time.Minute)); err == nil {
		t.Fatal("future ledger accepted")
	}
	wrongNet := newFakeLedgerSource(XRPLNetworkMainnet, a)
	if _, _, err = newCaptureTimestampAt(context.Background(), wrongNet, DefaultLedgerMaxAge, a.Time()); err == nil {
		t.Fatal("cross-network ledger accepted")
	}
}

func TestVerifyLedgerAnchor(t *testing.T) {
	a := testLedgerAnchor()
	src := newFakeLedgerSource(XRPLNetworkTestnet, a)
	if _, err := VerifyLedgerAnchor(context.Background(), src, a.Encode()); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*LedgerAnchor){
		"close_time": func(x *LedgerAnchor) { x.CloseTime += 10 },
		"index":      func(x *LedgerAnchor) { x.LedgerIndex++ },
		"hash":       func(x *LedgerAnchor) { x.LedgerHash[0] ^= 1 },
		"network":    func(x *LedgerAnchor) { x.NetworkID = XRPLNetworkMainnet },
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			b := a
			mod(&b)
			if _, err := VerifyLedgerAnchor(context.Background(), src, b.Encode()); err == nil {
				t.Fatal("tampered anchor accepted")
			}
		})
	}
}

// rippled-shaped JSON-RPC responses served locally (no Internet access).
func TestXRPLClientParsesLedgerResponse(t *testing.T) {
	a := testLedgerAnchor()
	hashHex := strings.ToUpper(hex.EncodeToString(a.LedgerHash[:]))
	valid := `{"result":{"ledger":{"close_time":848538780,"close_time_resolution":10,"closed":true,` +
		`"ledger_hash":"` + hashHex + `","ledger_index":"5123456"},` +
		`"ledger_hash":"` + hashHex + `","ledger_index":5123456,"status":"success","validated":true}}`
	var lastParams map[string]any
	reply := valid
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Method string           `json:"method"`
			Params []map[string]any `json:"params"`
		}
		if json.Unmarshal(body, &req) != nil || req.Method != "ledger" || len(req.Params) != 1 {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		lastParams = req.Params[0]
		io.WriteString(w, reply)
	}))
	defer srv.Close()
	c := NewXRPLClient(srv.URL, XRPLNetworkTestnet)

	got, err := c.LatestValidatedLedger(context.Background())
	if err != nil || got != a {
		t.Fatalf("latest: %v %+v", err, got)
	}
	if lastParams["ledger_index"] != "validated" {
		t.Fatalf("must request the validated ledger, got %v", lastParams)
	}
	got, err = c.LedgerByHash(context.Background(), a.LedgerHash)
	if err != nil || got != a {
		t.Fatalf("by hash: %v %+v", err, got)
	}
	if lastParams["ledger_hash"] != hex.EncodeToString(a.LedgerHash[:]) {
		t.Fatalf("ledger_hash param %v", lastParams)
	}

	bad := map[string]string{
		"not_validated": strings.Replace(valid, `"validated":true`, `"validated":false`, 1),
		"not_closed":    strings.Replace(valid, `"closed":true`, `"closed":false`, 1),
		"hash_mismatch": strings.Replace(valid, `"ledger_hash":"`+hashHex+`","ledger_index":"`, `"ledger_hash":"`+strings.Repeat("00", 32)+`","ledger_index":"`, 1),
		"error":         `{"result":{"error":"lgrNotFound","status":"error"}}`,
		"short_hash":    strings.ReplaceAll(valid, hashHex, "ABCD"),
		"garbage":       `not json`,
	}
	for name, body := range bad {
		t.Run(name, func(t *testing.T) {
			reply = body
			if _, err := c.LatestValidatedLedger(context.Background()); err == nil {
				t.Fatal("bad response accepted")
			}
		})
	}
}
