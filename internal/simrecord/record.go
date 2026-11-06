// Package simrecord records test-only upstream-sim exchanges. It never persists credentials.
package simrecord

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Kaivodev/upstream-plugins/abi"
	"github.com/Kaivodev/upstream-plugins/host"
)

type credentials struct {
	Style          string `json:"style"`
	RequestPrivate string `json:"generated_platform_private_key_pem"`
	CallbackPublic string `json:"callback_public_key_pem"`
	Shared         string `json:"shared_secret"`
}
type recorder struct {
	base      http.RoundTripper
	exchanges []host.Exchange
	fault     string
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	body, e := io.ReadAll(req.Body)
	if e != nil {
		return nil, e
	}
	x := host.Exchange{Request: host.NormalizeTestRequest(abi.Request{Method: req.Method, URL: req.URL.String(), Headers: req.Header, Body: body})}
	req = req.Clone(req.Context())
	req.Body = io.NopCloser(bytes.NewReader(body))
	if r.fault == "synthetic_timeout" {
		x.Error = "timeout"
		r.exchanges = append(r.exchanges, x)
		return nil, context.DeadlineExceeded
	}
	if r.fault == "signature_error" {
		if req.Header.Get("X-Signature") != "" {
			req.Header.Set("X-Signature", "invalid-signature")
		} else {
			v, _ := url.ParseQuery(string(body))
			v.Set("sign", strings.Repeat("0", 32))
			req.Body = io.NopCloser(strings.NewReader(v.Encode()))
			req.ContentLength = int64(len(v.Encode()))
		}
	}
	res, e := r.base.RoundTrip(req)
	if e != nil {
		x.Error = "transport_error"
		if errors.Is(e, context.DeadlineExceeded) {
			x.Error = "timeout"
		}
		r.exchanges = append(r.exchanges, x)
		return nil, e
	}
	raw, e := io.ReadAll(io.LimitReader(res.Body, host.MaxBody+1))
	res.Body.Close()
	if e != nil {
		return nil, e
	}
	if r.fault == "synthetic_amount_mismatch" {
		var v map[string]json.RawMessage
		_ = json.Unmarshal(raw, &v)
		for _, name := range []string{"order", "refund"} {
			if b := v[name]; b != nil {
				var o map[string]json.RawMessage
				_ = json.Unmarshal(b, &o)
				var n int64
				_ = json.Unmarshal(o["amount"], &n)
				o["amount"], _ = json.Marshal(n + 1)
				v[name], _ = json.Marshal(o)
			}
		}
		raw, _ = json.Marshal(v)
	}
	headers := http.Header{}
	headers.Set("Content-Type", res.Header.Get("Content-Type"))
	x.Response = &abi.Response{Status: res.StatusCode, Headers: headers, Body: raw}
	r.exchanges = append(r.exchanges, x)
	res.Header = headers
	res.Body = io.NopCloser(bytes.NewReader(raw))
	return res, nil
}

// Record requires a test-environment simulator exposing its authenticated control API.
func Record(ctx context.Context, p host.Package, base, token, out string) error {
	u, e := url.Parse(base)
	if e != nil || u.Scheme != "http" || net.ParseIP(u.Hostname()) == nil || !net.ParseIP(u.Hostname()).IsLoopback() || u.User != nil || u.RawQuery != "" || u.Path != "" || u.Fragment != "" {
		return errors.New("record requires explicit loopback HTTP simulator origin")
	}
	if len(token) < 16 {
		return errors.New("test control token required")
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	control := func(method, path string, v any, dst any) error {
		var body []byte
		if v != nil {
			body, _ = json.Marshal(v)
		}
		r, e := http.NewRequestWithContext(ctx, method, base+path, bytes.NewReader(body))
		if e != nil {
			return e
		}
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		res, e := client.Do(r)
		if e != nil {
			return errors.New("simulator control transport unavailable")
		}
		defer res.Body.Close()
		b, e := io.ReadAll(io.LimitReader(res.Body, abi.MaxJSON))
		if e != nil || res.StatusCode != 200 {
			return errors.New("simulator test control rejected request")
		}
		if dst != nil {
			return json.Unmarshal(b, dst)
		}
		return nil
	}
	var creds map[string]credentials
	if e = control("GET", "/__test/credentials", nil, &creds); e != nil {
		return e
	}
	m, _, e := p.Manifest()
	if e != nil {
		return e
	}
	account := "md5-demo"
	style := "form-md5"
	if m.Code == "sim_json_rsa" {
		account, style = "rsa-demo", "json-rsa"
	} else if m.Code != "sim_form_md5" {
		return errors.New("recorder recipes support only simulator plugins")
	}
	cred, ok := creds[account]
	if !ok {
		return errors.New("simulator test account unavailable")
	}
	var pub *rsa.PublicKey
	if style == "json-rsa" {
		block, _ := pem.Decode([]byte(cred.CallbackPublic))
		if block == nil {
			return errors.New("missing simulator test public key")
		}
		v, e := x509.ParsePKIXPublicKey(block.Bytes)
		if e != nil {
			return e
		}
		pub, ok = v.(*rsa.PublicKey)
		if !ok {
			return errors.New("invalid simulator key")
		}
	}
	h, e := host.New(ctx, host.Options{PluginType: "payment", TestOnlyAllowHTTP: true, TestOnlyAllowUncommitted: true})
	if e != nil {
		return e
	}
	defer h.Close(ctx)
	l, e := h.Load(ctx, p)
	if e != nil {
		return e
	}
	callbacks := make(chan abi.CallbackInput, 16)
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return fmt.Errorf("test callback listener unavailable: %w", e)
	}
	server := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		headers := http.Header{"Content-Type": {r.Header.Get("Content-Type")}}
		if sig := r.Header.Get("X-Signature"); sig != "" {
			headers.Set("X-Signature", sig)
		}
		select {
		case callbacks <- abi.CallbackInput{Method: r.Method, Headers: headers, Body: b}:
		default:
		}
		_, _ = w.Write([]byte("success"))
	})}
	go server.Serve(listener)
	defer server.Close()
	callbackURL := "http://" + listener.Addr().String() + "/callback"
	if e = os.MkdirAll(out, 0755); e != nil {
		return e
	}
	run := func(op abi.Operation, input []byte, f host.Fixture, record *recorder) host.Execution {
		clock, _ := time.Parse(time.RFC3339Nano, f.Time)
		env := host.Services{ConfigValues: f.Config, ResolveSecret: func(_ context.Context, n string) ([]byte, error) {
			switch n {
			case "platform_private":
				return []byte(cred.RequestPrivate), nil
			case "shared":
				return []byte(cred.Shared), nil
			}
			return nil, errors.New("unknown credential")
		}, ResolvePublicKey: func(context.Context, string) (*rsa.PublicKey, error) { return pub, nil }, Clock: func() time.Time { return clock }, RandomSource: host.SeedReader(f.RandomSeed), HTTP: record}
		return h.Execute(ctx, l, op, input, env)
	}
	encode := func(v any) []byte { b, _ := json.Marshal(v); return b }
	recordID := time.Now().UTC().Format("20060102150405.000000000")
	recordID = strings.ReplaceAll(recordID, ".", "")
	for _, op := range abi.PaymentOperations {
		scenarios := []string{"success", "rejected", "timeout", "signature_error", "amount_mismatch"}
		if op == abi.VerifyCallback {
			scenarios = []string{"success", "signature_error", "amount_mismatch"}
		}
		for _, scenario := range scenarios {
			id := "test_" + recordID + "_" + string(op) + "_" + scenario
			money := abi.Money{Amount: "12345", Currency: "CNY"}
			f := host.Fixture{Name: string(op) + "/" + scenario, Source: "recorded_upstream_sim_loopback", Operation: op, Config: map[string]string{"gateway": base, "account_id": account}, Time: time.Now().UTC().Format(time.RFC3339Nano), RandomSeed: make([]byte, 32), Exchanges: []host.Exchange{}}
			// Recorded fixture entropy is explicitly test-only and independent of keys.
			seed := []byte("only-test-recorded-entropy-32bytes")
			copy(f.RandomSeed, seed)
			scenarioConfig := map[string]any{"callback_disabled": true}
			needOrder := op != abi.CreatePayment && scenario != "rejected"
			if op == abi.ClosePayment && scenario == "rejected" {
				needOrder = true
				scenarioConfig["close_unsupported"] = true
			}
			if op == abi.Refund && scenario == "rejected" {
				needOrder = true
				scenarioConfig["refund_result"] = "failed"
			}
			if op == abi.CreatePayment && scenario == "rejected" {
				scenarioConfig["create_fault"] = "reject"
			}
			if op == abi.CreatePayment && scenario == "timeout" {
				scenarioConfig["create_fault"] = "timeout"
				scenarioConfig["fault_delay_ms"] = 3000
			}
			if op == abi.VerifyCallback {
				scenarioConfig["callback_disabled"] = false
				if scenario == "signature_error" {
					scenarioConfig["callback_invalid_signature"] = true
				}
				if scenario == "amount_mismatch" {
					scenarioConfig["callback_amount"] = 12346
				}
			}
			if e = control("PUT", "/__test/scenarios/"+account+"/"+id, scenarioConfig, nil); e != nil {
				return e
			}
			create := abi.CreatePaymentInput{OrderID: id, Money: money, Method: "alipay", Instruction: "url", CallbackURL: callbackURL}
			if needOrder {
				result := run(abi.CreatePayment, encode(create), f, &recorder{base: tr})
				if result.Category != host.Completed {
					return fmt.Errorf("record setup create failed: %s", result.ErrorCode)
				}
				if op == abi.Refund || op == abi.QueryRefund || op == abi.VerifyCallback {
					link := result.Result.Payment.URL
					r, e := http.NewRequestWithContext(ctx, "POST", link, nil)
					if e != nil {
						return e
					}
					res, e := client.Do(r)
					if e != nil {
						return e
					}
					io.Copy(io.Discard, res.Body)
					res.Body.Close()
					if res.StatusCode != 200 {
						return errors.New("record setup cashier failed")
					}
				}
				if op == abi.QueryRefund {
					refund := abi.RefundInput{OrderID: id, RefundID: id + "_refund", Money: money}
					result := run(abi.Refund, encode(refund), f, &recorder{base: tr})
					if result.Category != host.Completed {
						return fmt.Errorf("record setup refund failed: %s", result.ErrorCode)
					}
				}
			}
			var input any
			switch op {
			case abi.CreatePayment:
				input = create
			case abi.QueryPayment, abi.ClosePayment:
				input = abi.PaymentInput{OrderID: id, Money: money}
			case abi.Refund, abi.QueryRefund:
				input = abi.RefundInput{OrderID: id, RefundID: id + "_refund", Money: money}
			case abi.VerifyCallback:
				select {
				case v := <-callbacks:
					v.OrderID, v.Money = id, money
					input = v
				case <-time.After(4 * time.Second):
					return errors.New("simulator callback not received")
				}
			}
			f.Input = encode(input)
			r := &recorder{base: tr}
			if op != abi.VerifyCallback {
				if scenario == "signature_error" {
					r.fault = "signature_error"
				}
				if scenario == "amount_mismatch" {
					r.fault = "synthetic_amount_mismatch"
					f.Source = "recorded_response_with_constructed_amount_fault"
				}
				if scenario == "timeout" && op != abi.CreatePayment {
					r.fault = "synthetic_timeout"
					f.Source = "constructed_transport_timeout_from_recorded_protocol"
				}
			}
			f.Expected = run(op, f.Input, f, r)
			f.Exchanges = r.exchanges
			if f.Exchanges == nil {
				f.Exchanges = []host.Exchange{}
			}
			if op == abi.VerifyCallback && scenario != "signature_error" {
				var v abi.CallbackInput
				_ = abi.Decode(f.Input, &v)
				if style == "json-rsa" {
					http.Header(v.Headers).Set("X-Signature", host.TestSignature)
				} else {
					values, _ := url.ParseQuery(string(v.Body))
					values.Set("sign", host.TestSignature)
					v.Body = []byte(values.Encode())
				}
				f.Input = encode(v)
				f.TestOnlyResignCallback = true
			}
			if e = validateExpectation(scenario, op, f.Expected); e != nil {
				return e
			}
			b, e := json.MarshalIndent(f, "", "  ")
			if e != nil {
				return e
			}
			b = append(b, '\n')
			if bytes.Contains(b, []byte(cred.Shared)) && cred.Shared != "" || bytes.Contains(b, []byte(cred.RequestPrivate)) && cred.RequestPrivate != "" {
				return errors.New("recording contains credential")
			}
			if e = os.WriteFile(filepath.Join(out, string(op)+"_"+scenario+".json"), b, 0644); e != nil {
				return e
			}
		}
	}
	return nil
}
func validateExpectation(scenario string, op abi.Operation, r host.Execution) error {
	want := host.Completed
	if scenario == "timeout" || scenario == "amount_mismatch" {
		want = host.Unknown
	}
	if scenario == "rejected" || scenario == "signature_error" {
		want = host.Rejected
	}
	if op == abi.VerifyCallback && (scenario == "signature_error" || scenario == "amount_mismatch") {
		want = host.NotSent
	}
	if r.Category != want {
		return fmt.Errorf("recorded %s/%s got %s (%s), want %s", op, scenario, r.Category, r.ErrorCode, want)
	}
	return nil
}
