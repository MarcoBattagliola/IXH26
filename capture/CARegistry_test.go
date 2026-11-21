package capture

import (
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func regID(b byte) [32]byte {
	var id [32]byte
	id[0], id[31] = b, 0x55
	return id
}

func TestRegistryEventEncodeDecode(t *testing.T) {
	for _, e := range []RegistryEvent{
		{Op: OpActivate, Role: RoleCA3, KeyID: regID(1)},
		{Op: OpRevoke, Role: RoleCRS, KeyID: regID(2), CompromisedSince: 99},
	} {
		got, err := DecodeRegistryEvent(e.Encode())
		if err != nil || got != e {
			t.Fatalf("roundtrip %v %+v", err, got)
		}
	}
	bad := []RegistryEvent{
		{Op: OpActivate, Role: RoleCA1, KeyID: regID(1), CompromisedSince: 5}, // activate with date
		{Op: OpRevoke, Role: RoleCA1, KeyID: regID(1)},                        // revoke without date
		{Op: 9, Role: RoleCA1, KeyID: regID(1)},
		{Op: OpActivate, Role: 0, KeyID: regID(1)},
		{Op: OpActivate, Role: RoleCA1},
	}
	for i, e := range bad {
		if _, err := DecodeRegistryEvent(e.Encode()); err == nil {
			t.Fatalf("case %d accepted", i)
		}
	}
	if _, err := DecodeRegistryEvent([]byte("short")); err == nil {
		t.Fatal("short event accepted")
	}
}

func TestBuildCARegistryAndCheckKey(t *testing.T) {
	a, b := regID(1), regID(2)
	reg, err := BuildCARegistry("rGov", XRPLNetworkTestnet, []RegistryEvent{
		{Op: OpActivate, Role: RoleCA3, KeyID: a, Ledger: 100},
		{Op: OpActivate, Role: RoleCA1, KeyID: b, Ledger: 100},
		{Op: OpRevoke, Role: RoleCA3, KeyID: a, CompromisedSince: 500, Ledger: 600},
		{Op: OpRevoke, Role: RoleCA3, KeyID: a, CompromisedSince: 450, Ledger: 700}, // earlier estimate wins
		{Op: OpActivate, Role: RoleCA3, KeyID: a, Ledger: 800},                      // no re-activation
	})
	if err != nil {
		t.Fatal(err)
	}
	if st := reg.Keys[a]; st.ActivatedLedger != 100 || st.CompromisedSince != 450 || st.RevokedLedger != 600 {
		t.Fatalf("status %+v", st)
	}
	cases := []struct {
		name     string
		role     RegistryRole
		id       [32]byte
		t0, t1   uint32
		accepted bool
	}{
		{"valid_unrevoked", RoleCA1, b, 200, 203, true},
		{"before_compromise", RoleCA3, a, 200, 449, true},
		{"after_compromise", RoleCA3, a, 440, 450, false},
		{"after_reactivation_attempt", RoleCA3, a, 900, 903, false},
		{"activated_in_T0_ledger", RoleCA1, b, 100, 103, true},
		{"activated_after_T0", RoleCA1, b, 99, 103, false},
		{"wrong_role", RoleCA2, b, 200, 203, false},
		{"unregistered", RoleCA1, regID(9), 200, 203, false},
	}
	for _, c := range cases {
		err := reg.CheckKey(c.role, c.id, c.t0, c.t1)
		if (err == nil) != c.accepted {
			t.Fatalf("%s: accepted=%v err=%v", c.name, err == nil, err)
		}
	}
	// compromisedSince later than the revocation itself is clamped.
	reg2, _ := BuildCARegistry("rGov", 1, []RegistryEvent{
		{Op: OpActivate, Role: RoleCA1, KeyID: b, Ledger: 10},
		{Op: OpRevoke, Role: RoleCA1, KeyID: b, CompromisedSince: 9999, Ledger: 50},
	})
	if reg2.Keys[b].CompromisedSince != 50 {
		t.Fatal("compromisedSince not clamped to revocation ledger")
	}
	if _, err := BuildCARegistry("rGov", 1, []RegistryEvent{
		{Op: OpActivate, Role: RoleCA1, KeyID: b, Ledger: 10},
		{Op: OpActivate, Role: RoleCA1, KeyID: a, Ledger: 5},
	}); err == nil {
		t.Fatal("out-of-order events accepted")
	}
	if _, err := BuildCARegistry("rGov", 1, []RegistryEvent{
		{Op: OpActivate, Role: RoleCA1, KeyID: b, Ledger: 10},
		{Op: OpActivate, Role: RoleCA2, KeyID: b, Ledger: 11},
	}); err == nil {
		t.Fatal("key under two roles accepted")
	}
}

func TestRegistryEventsOnlyFromGovernanceAccount(t *testing.T) {
	ev := RegistryEvent{Op: OpActivate, Role: RoleCA3, KeyID: regID(7)}
	memo := []XRPLMemo{{Type: []byte(RegistryMemoType), Data: ev.Encode()}}
	txs := []XRPLAccountTx{
		{Hash: regID(1), Account: "rGov", LedgerIndex: 10, Validated: true, Result: "tesSUCCESS", Memos: memo},
		{Hash: regID(2), Account: "rAttacker", LedgerIndex: 11, Validated: true, Result: "tesSUCCESS", Memos: memo},
		{Hash: regID(3), Account: "rGov", LedgerIndex: 12, Validated: false, Result: "tesSUCCESS", Memos: memo},
		{Hash: regID(4), Account: "rGov", LedgerIndex: 13, Validated: true, Result: "tecFAILED", Memos: memo},
		{Hash: regID(5), Account: "rGov", LedgerIndex: 14, Validated: true, Result: "tesSUCCESS",
			Memos: []XRPLMemo{{Type: []byte("other"), Data: []byte("x")}}},
	}
	events, err := RegistryEventsFromHistory("rGov", txs)
	if err != nil || len(events) != 1 || events[0].Ledger != 10 || events[0].TxHash != regID(1) {
		t.Fatalf("events %v %+v", err, events)
	}
	txs = append(txs, XRPLAccountTx{Hash: regID(6), Account: "rGov", LedgerIndex: 15, Validated: true,
		Result: "tesSUCCESS", Memos: []XRPLMemo{{Type: []byte(RegistryMemoType), Data: []byte("garbage")}}})
	if _, err := RegistryEventsFromHistory("rGov", txs); err == nil {
		t.Fatal("malformed governance event accepted")
	}
}

// rippled-shaped account_tx replies (API v1 page, then API v2 page via marker).
func TestXRPLClientAccountTransactions(t *testing.T) {
	ev := RegistryEvent{Op: OpActivate, Role: RoleCA1, KeyID: regID(3)}
	memo := `[{"Memo":{"MemoType":"` + strings.ToUpper(hex.EncodeToString([]byte(RegistryMemoType))) +
		`","MemoData":"` + strings.ToUpper(hex.EncodeToString(ev.Encode())) + `"}}]`
	h1 := strings.Repeat("11", 32)
	h2 := strings.Repeat("22", 32)
	page1 := `{"result":{"status":"success","marker":{"ledger":20,"seq":1},"transactions":[` +
		`{"meta":{"TransactionResult":"tesSUCCESS"},"validated":true,"tx":{"Account":"rGov","hash":"` + h1 + `","ledger_index":10,"Memos":` + memo + `}}]}}`
	page2 := `{"result":{"status":"success","transactions":[` +
		`{"meta":{"TransactionResult":"tesSUCCESS"},"validated":true,"hash":"` + h2 + `","ledger_index":20,"tx_json":{"Account":"rGov","Memos":` + memo + `}}]}}`
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"method":"account_tx"`) || !strings.Contains(string(body), `"forward":true`) {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		calls++
		if strings.Contains(string(body), `"marker"`) {
			io.WriteString(w, page2)
		} else {
			io.WriteString(w, page1)
		}
	}))
	defer srv.Close()
	c := NewXRPLClient(srv.URL, XRPLNetworkTestnet)
	txs, err := c.AccountTransactions(context.Background(), "rGov")
	if err != nil || len(txs) != 2 || calls != 2 {
		t.Fatalf("%v %d %d", err, len(txs), calls)
	}
	if txs[0].LedgerIndex != 10 || txs[1].LedgerIndex != 20 || txs[1].Account != "rGov" || len(txs[1].Memos) != 1 {
		t.Fatalf("parsed %+v", txs)
	}
	reg, err := FetchCARegistry(context.Background(), c, "rGov", XRPLNetworkTestnet)
	if err != nil || reg.Keys[regID(3)].ActivatedLedger != 10 {
		t.Fatalf("registry %v %+v", err, reg)
	}
}

// fixtureRegistry activates every key of the fixture before T0.
func fixtureRegistryEvents(t *testing.T, f *captureFixture) ([]RegistryEvent, [32]byte) {
	t.Helper()
	id1, err := KeyIDJR(RoleCA1, &f.Statement.VK1)
	if err != nil {
		t.Fatal(err)
	}
	id2, _ := KeyIDJR(RoleCA2, &f.Statement.VK2)
	id3, _ := KeyIDCA3(&f.CA3VK)
	idCRS, _ := KeyIDCRS(f.CRS)
	act := f.Ledger.LedgerIndex - 1000
	return []RegistryEvent{
		{Op: OpActivate, Role: RoleCA1, KeyID: id1, Ledger: act},
		{Op: OpActivate, Role: RoleCA2, KeyID: id2, Ledger: act},
		{Op: OpActivate, Role: RoleCA3, KeyID: id3, Ledger: act},
		{Op: OpActivate, Role: RoleCRS, KeyID: idCRS, Ledger: act},
	}, id3
}

func TestCaptureVerifyWithRegistry(t *testing.T) {
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
	t1, t1Ledger := publishT1(f.LedgerSource, f.Ledger, d, 4, 12)
	base, id3 := fixtureRegistryEvents(t, f)
	verify := func(events []RegistryEvent, net uint32, st CaptureStatement) error {
		reg, err := BuildCARegistry("rGov", net, events)
		if err != nil {
			return err
		}
		ok, _, err := CaptureVerifyWithRegistry(context.Background(), f.LedgerSource, reg, f.CRS,
			f.Bits, f.BitCount, f.Manifest, f.Timestamp, t1.Encode(), DefaultCaptureMaxWindow,
			&f.CA3Certificate, &f.CA3VK, &st, data)
		if err == nil && !ok {
			return errNotOK
		}
		return err
	}
	if err := verify(base, XRPLNetworkTestnet, f.Statement); err != nil {
		t.Fatalf("valid capture rejected: %v", err)
	}
	revoke := func(since uint32) []RegistryEvent {
		return append(append([]RegistryEvent(nil), base...), RegistryEvent{
			Op: OpRevoke, Role: RoleCA3, KeyID: id3, CompromisedSince: since, Ledger: t1Ledger.LedgerIndex + 5000})
	}
	t.Run("older_capture_survives_later_compromise", func(t *testing.T) {
		if err := verify(revoke(t1Ledger.LedgerIndex+1), XRPLNetworkTestnet, f.Statement); err != nil {
			t.Fatalf("capture published before the compromise rejected: %v", err)
		}
	})
	t.Run("capture_after_compromise_rejected", func(t *testing.T) {
		err := verify(revoke(t1Ledger.LedgerIndex), XRPLNetworkTestnet, f.Statement)
		if err == nil || !strings.Contains(err.Error(), "revoked") {
			t.Fatalf("capture published after the compromise accepted: %v", err)
		}
	})
	t.Run("unregistered_key", func(t *testing.T) {
		if err := verify(base[1:], XRPLNetworkTestnet, f.Statement); err == nil {
			t.Fatal("capture with an unregistered CA1 accepted")
		}
	})
	t.Run("key_activated_after_T0", func(t *testing.T) {
		late := append([]RegistryEvent(nil), base...)
		for i := range late {
			late[i].Ledger = f.Ledger.LedgerIndex + 1
		}
		if err := verify(late, XRPLNetworkTestnet, f.Statement); err == nil {
			t.Fatal("key activated after T0 accepted")
		}
	})
	t.Run("crs_revoked", func(t *testing.T) {
		idCRS, _ := KeyIDCRS(f.CRS)
		ev := append(append([]RegistryEvent(nil), base...), RegistryEvent{
			Op: OpRevoke, Role: RoleCRS, KeyID: idCRS, CompromisedSince: f.Ledger.LedgerIndex - 1, Ledger: t1Ledger.LedgerIndex + 1})
		if err := verify(ev, XRPLNetworkTestnet, f.Statement); err == nil {
			t.Fatal("revoked CRS accepted")
		}
	})
	t.Run("registry_on_other_network", func(t *testing.T) {
		if err := verify(base, XRPLNetworkMainnet, f.Statement); err == nil {
			t.Fatal("cross-network registry accepted")
		}
	})
	t.Run("swapped_CA_keys", func(t *testing.T) {
		st := f.Statement
		st.VK1, st.VK2 = st.VK2, st.VK1
		if err := verify(base, XRPLNetworkTestnet, st); err == nil {
			t.Fatal("swapped CA keys accepted")
		}
	})
}

type notOKError struct{}

func (notOKError) Error() string { return "verification returned false" }

var errNotOK = notOKError{}
