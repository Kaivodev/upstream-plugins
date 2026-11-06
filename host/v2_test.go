package host

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Kaivodev/upstream-plugins/abi"
)

func newEmptyPaymentHost(t *testing.T) *Host {
	t.Helper()
	h, err := New(context.Background(), Options{PluginType: "payment", TestOnlyAllowUncommitted: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close(context.Background()) })
	return h
}

func TestRouteCallbackIsolation(t *testing.T) {
	h, l := newTestHost(t, false)
	l.manifest.PublicKeys = []string{"upstream_public"}
	env := testEnv()
	env.ResolveSecret = func(context.Context, string) ([]byte, error) { t.Fatal("routing resolved a secret"); return nil, nil }
	env.ResolvePublicKey = func(context.Context, string) (*rsa.PublicKey, error) {
		t.Fatal("routing resolved a public key")
		return nil, nil
	}
	env.HTTP = roundTripFunc(func(_ *http.Request) (*http.Response, error) { t.Fatal("routing sent HTTP"); return nil, nil })
	for mode, code := range map[string]string{"http": "callback_network_forbidden", "sign": "route_crypto_forbidden", "verify": "route_crypto_forbidden", "secret": "undeclared_config", "public": "undeclared_config", "allowed": ""} {
		t.Run(mode, func(t *testing.T) {
			input, _ := json.Marshal(abi.RouteCallbackInput{Method: "POST", Headers: map[string][]string{"Content-Type": {"application/json"}}, Body: []byte(mode)})
			result := h.Execute(context.Background(), l, abi.RouteCallback, input, env)
			want := NotSent
			if code == "" {
				want = Completed
			}
			if result.Category != want || result.ErrorCode != code || result.Requests != 0 {
				t.Fatal(result)
			}
		})
	}
}

func TestPaymentExpiryBoundaries(t *testing.T) {
	h := newEmptyPaymentHost(t)
	m := testManifest()
	m.Capabilities = append(m.Capabilities, abi.CreatePayment)
	raw, _ := json.Marshal(m)
	l, err := h.Load(context.Background(), Package{ManifestJSON: raw, Wasm: malicious})
	if err != nil {
		t.Fatal(err)
	}
	env := testEnv()
	now := time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)
	env.Clock = func() time.Time { return now }
	for _, mode := range []string{"expiry_past", "expiry_now", "expiry_day", "expiry_over", "expiry_status", "expiry_no_instruction", "expiry_offset", "expiry_bad", "expiry_absent", "expiry_valid", "expiry_before"} {
		t.Run(mode, func(t *testing.T) {
			input, _ := json.Marshal(abi.CreatePaymentInput{OrderID: mode, Money: abi.Money{Amount: "12345", Currency: "CNY"}, Method: "alipay", CallbackURL: "https://allowed.example/callback"})
			r := h.Execute(context.Background(), l, abi.CreatePayment, input, env)
			want := Unknown
			if mode == "expiry_day" || mode == "expiry_absent" || mode == "expiry_valid" {
				want = Completed
			}
			if mode == "expiry_before" {
				want = NotSent
			}
			if r.Category != want {
				t.Fatal(r)
			}
			if want != Completed && r.ErrorCode != "output_time" && !(mode == "expiry_no_instruction" && r.ErrorCode == "output_instruction") {
				t.Fatal(r)
			}
		})
	}
	r := h.Execute(context.Background(), l, abi.QueryPayment, testInput("expiry_valid"), env)
	if r.Category != Unknown || r.ErrorCode != "output_time" {
		t.Fatal(r)
	}
}

func TestVerificationAdmissionAndExecution(t *testing.T) {
	m := testManifest()
	m.Type = "verification"
	m.Callback = nil
	m.Capabilities = []abi.Operation{abi.QueryPayment, abi.QueryRefund}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Manifest){
		func(m *Manifest) { m.Capabilities = []abi.Operation{abi.QueryPayment} },
		func(m *Manifest) { m.Capabilities = append(m.Capabilities, abi.CreatePayment) },
		func(m *Manifest) { m.Callback = testManifest().Callback },
	} {
		copy := m
		mutate(&copy)
		if copy.Validate() == nil {
			t.Fatal("invalid verification accepted")
		}
	}
	p := pluginPackages[2]
	h, err := New(context.Background(), Options{PluginType: "verification", TestOnlyAllowUncommitted: true})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close(context.Background())
	l, err := h.Load(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range []abi.Operation{abi.CreatePayment, abi.ClosePayment, abi.Refund, abi.RouteCallback, abi.VerifyCallback, abi.FetchStatement, abi.ParseStatement} {
		r := h.Execute(context.Background(), l, op, []byte(`{}`), testEnv())
		if r.Category != NotSent || r.ErrorCode != "unsupported_operation" || r.Steps != 0 {
			t.Fatal(op, r)
		}
	}
	// Even a corrupted Loaded cannot bypass the type gate using SDK exports.
	l.manifest.Capabilities = append(l.manifest.Capabilities, abi.CreatePayment)
	r := h.Execute(context.Background(), l, abi.CreatePayment, nil, testEnv())
	if r.ErrorCode != "unsupported_operation" {
		t.Fatal(r)
	}
}

func TestABIV1Rejected(t *testing.T) {
	h := newEmptyPaymentHost(t)
	m := testManifest()
	m.ABIVersion = 1
	raw, _ := json.Marshal(m)
	if _, err := h.Load(context.Background(), Package{ManifestJSON: raw, Wasm: legacy}); err == nil {
		t.Fatal("v1 manifest accepted")
	}
	// A v2 manifest cannot disguise a v1 reactor.
	l, err := h.Load(context.Background(), testPackage(legacy))
	if err != nil {
		t.Fatal(err)
	}
	r := h.Execute(context.Background(), l, abi.QueryPayment, testInput("test"), testEnv())
	if r.Category != NotSent || r.ErrorCode != "abi_version" {
		t.Fatal(r)
	}
	m = testManifest()
	m.Capabilities = []abi.Operation{abi.VerifyCallback}
	if m.Validate() == nil {
		t.Fatal("callback without routing accepted")
	}
}

func TestCallbackRoutingOrderIDs(t *testing.T) {
	h := &Host{}
	for _, order := range []string{"", "space id", "a/b", strings.Repeat("a", 101), "test_order-1"} {
		result := &abi.Result{Outcome: "completed", Route: &abi.RouteCallbackOutput{OrderID: order}}
		code := h.validateResult(testManifest(), abi.RouteCallback, result, "", "", abi.Money{}, time.Now())
		if (code == "") != (order == "test_order-1") {
			t.Fatal("invalid routing identity validation")
		}
	}
	m := testManifest()
	m.Capabilities = []abi.Operation{abi.RouteCallback}
	if err := m.Validate(); err != nil {
		t.Fatal("route-only capability rejected", err)
	}
}

func TestCallbackRoutingExportRequired(t *testing.T) {
	h := newEmptyPaymentHost(t)
	// Rename the export without changing the WASM section lengths.
	noRoute := bytes.ReplaceAll(malicious, []byte("route_callback"), []byte("other_callback"))
	if bytes.Equal(noRoute, malicious) {
		t.Fatal("route export not found in test reactor")
	}
	if _, err := h.Load(context.Background(), testPackage(noRoute)); err == nil {
		t.Fatal("declared routing capability without export accepted")
	}
}
