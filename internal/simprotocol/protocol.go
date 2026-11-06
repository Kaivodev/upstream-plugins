// Package simprotocol translates the two test-only upstream-sim protocols.
package simprotocol

import (
	"encoding/json"
	"errors"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/Kaivodev/upstream-plugins/abi"
	"github.com/Kaivodev/upstream-plugins/sdk"
)

// CanonicalForm follows upstream-sim: single values, sorted raw keys, escaped
// keys AND values, empty values retained, only sign excluded.
func CanonicalForm(v url.Values) (string, error) {
	keys := make([]string, 0, len(v))
	for k, x := range v {
		if k == "" || len(x) != 1 {
			return "", errors.New("invalid form")
		}
		if k != "sign" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v.Get(k)))
	}
	return strings.Join(parts, "&"), nil
}

type wireRequest struct {
	AccountID   string `json:"account_id"`
	Operation   string `json:"operation"`
	OrderID     string `json:"order_id"`
	Amount      int64  `json:"amount,omitempty"`
	Currency    string `json:"currency,omitempty"`
	Method      string `json:"method,omitempty"`
	BankMode    string `json:"bank_mode,omitempty"`
	Instruction string `json:"instruction,omitempty"`
	CallbackURL string `json:"callback_url,omitempty"`
	RefundID    string `json:"refund_id,omitempty"`
}
type wireOrder struct {
	AccountID  string `json:"account_id"`
	OrderID    string `json:"order_id"`
	UpstreamID string `json:"upstream_id"`
	Amount     int64  `json:"amount"`
	Currency   string `json:"currency"`
	Method     string `json:"method"`
	BankMode   string `json:"bank_mode,omitempty"`
	Status     string `json:"status"`
	URL        string `json:"url,omitempty"`
	QRCode     string `json:"qrcode,omitempty"`
	PaidAt     string `json:"paid_at,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"`
	ExpireTime string `json:"expire_time,omitempty"`
}
type wireRefund struct {
	AccountID string `json:"account_id"`
	OrderID   string `json:"order_id"`
	RefundID  string `json:"refund_id"`
	Amount    int64  `json:"amount"`
	Currency  string `json:"currency"`
	Status    string `json:"status"`
}
type wireResponse struct {
	Result string      `json:"result"`
	Code   string      `json:"code"`
	Order  *wireOrder  `json:"order,omitempty"`
	Refund *wireRefund `json:"refund,omitempty"`
}
type Event struct {
	EventID    string `json:"event_id"`
	AccountID  string `json:"account_id"`
	OrderID    string `json:"order_id"`
	UpstreamID string `json:"upstream_id"`
	Amount     int64  `json:"amount"`
	Currency   string `json:"currency"`
	Status     string `json:"status"`
	Sequence   int    `json:"sequence"`
	PaidAt     string `json:"paid_at,omitempty"`
}

func Register(style string) {
	register(style, false)
}
func RegisterVerification(style string) { register(style, true) }
func register(style string, verification bool) {
	ops := abi.PaymentOperations
	if verification {
		ops = []abi.Operation{abi.QueryPayment, abi.QueryRefund}
	}
	for _, op := range ops {
		op := op
		sdk.Register(op, func(c sdk.Call) sdk.Step {
			if op == abi.RouteCallback {
				return route(style, c)
			}
			if op == abi.VerifyCallback {
				return callback(style, c)
			}
			return payment(style, verification, op, c)
		})
	}
}
func payment(style string, verification bool, op abi.Operation, c sdk.Call) sdk.Step {
	account, err := sdk.Config("account_id")
	if err != nil {
		return sdk.Fail("config")
	}
	if len(c.Responses) > 0 {
		if len(c.Responses) != 1 {
			return sdk.Fail("response_count")
		}
		var res wireResponse
		if abi.Decode(c.Responses[0].Body, &res) != nil {
			return sdk.Fail("response_json")
		}
		if res.Result == "rejected" {
			return sdk.Reject(res.Code)
		}
		if res.Result == "unknown" {
			return sdk.Result(abi.Result{Outcome: "unknown", Code: res.Code})
		}
		if res.Result != "accepted" || c.Responses[0].Status != 200 {
			return sdk.Fail("response_status")
		}
		if op == abi.Refund || op == abi.QueryRefund {
			f := res.Refund
			if f == nil || res.Order != nil || f.AccountID != account || f.Amount <= 0 {
				return sdk.Fail("refund_response")
			}
			status := f.Status
			if status == "success" {
				status = "succeeded"
			}
			return sdk.Result(abi.Result{Outcome: "completed", Refund: &abi.RefundOutput{OrderID: f.OrderID, RefundID: f.RefundID, UpstreamRefundID: f.RefundID, Money: abi.Money{Amount: strconv.FormatInt(f.Amount, 10), Currency: f.Currency}, Status: status}})
		}
		o := res.Order
		if o == nil || res.Refund != nil || o.AccountID != account || o.Amount <= 0 {
			return sdk.Fail("payment_response")
		}
		expires := ""
		if op == abi.CreatePayment && o.Status == "pending" {
			if style == "json-rsa" {
				expires = o.ExpiresAt
			} else {
				expires = o.ExpireTime
			}
		}
		return sdk.Result(abi.Result{Outcome: "completed", Payment: &abi.PaymentOutput{OrderID: o.OrderID, UpstreamID: o.UpstreamID, Money: abi.Money{Amount: strconv.FormatInt(o.Amount, 10), Currency: o.Currency}, Status: o.Status, URL: o.URL, QRCode: o.QRCode, PaidAt: o.PaidAt, ExpiresAt: expires}})
	}
	gateway, err := sdk.Config("gateway")
	if err != nil {
		return sdk.Fail("config")
	}
	r := wireRequest{AccountID: account}
	switch op {
	case abi.CreatePayment:
		v, e := sdk.Input[abi.CreatePaymentInput](c)
		if e != nil {
			return sdk.Fail("input")
		}
		n, e := minor(v.Money)
		if e != nil {
			return sdk.Fail("amount")
		}
		r.Operation, r.OrderID, r.Amount, r.Currency, r.Method, r.BankMode, r.Instruction, r.CallbackURL = "create", v.OrderID, n, v.Money.Currency, v.Method, v.BankMode, v.Instruction, v.CallbackURL
	case abi.QueryPayment, abi.ClosePayment:
		v, e := sdk.Input[abi.PaymentInput](c)
		if e != nil {
			return sdk.Fail("input")
		}
		r.OrderID = v.OrderID
		r.Operation = "query"
		if op == abi.ClosePayment {
			r.Operation = "close"
		}
	case abi.Refund, abi.QueryRefund:
		v, e := sdk.Input[abi.RefundInput](c)
		if e != nil {
			return sdk.Fail("input")
		}
		r.Operation, r.OrderID, r.RefundID = "refund-query", v.OrderID, v.RefundID
		if op == abi.Refund {
			n, e := minor(v.Money)
			if e != nil {
				return sdk.Fail("amount")
			}
			r.Operation, r.Amount, r.Currency = "refund", n, v.Money.Currency
		}
	default:
		return sdk.Fail("operation")
	}
	privateRef, sharedRef := "platform_private", "shared"
	if verification {
		privateRef, sharedRef = "query_private_key", "query_key"
	}
	headers := map[string][]string{}
	var body []byte
	if style == "json-rsa" {
		body, err = json.Marshal(r)
		if err != nil {
			return sdk.Fail("encode")
		}
		sig, e := sdk.Sign("rsa-sha256", privateRef, sdk.Bytes(body))
		if e != nil {
			return sdk.Fail("sign")
		}
		headers["Content-Type"] = []string{"application/json"}
		headers["X-Signature"] = []string{sig}
	} else {
		raw, _ := json.Marshal(r)
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(raw, &fields)
		v := url.Values{}
		for k, b := range fields {
			var s string
			if k == "amount" {
				s = string(b)
			} else {
				_ = json.Unmarshal(b, &s)
			}
			v.Set(k, s)
		}
		canonical, e := CanonicalForm(v)
		if e != nil {
			return sdk.Fail("canonical")
		}
		sig, e := sdk.Sign("md5", "", sdk.Bytes([]byte(canonical+"&key=")), sdk.Secret(sharedRef))
		if e != nil {
			return sdk.Fail("sign")
		}
		v.Set("sign", sig)
		body = []byte(v.Encode())
		headers["Content-Type"] = []string{"application/x-www-form-urlencoded"}
	}
	return sdk.Request("POST", strings.TrimRight(gateway, "/")+"/api/"+url.PathEscape(account)+"/"+r.Operation, headers, body)
}
func minor(m abi.Money) (int64, error) {
	n, e := abi.ParseAmount(m)
	if e != nil || !n.IsInt64() || n.Sign() <= 0 || m.Currency != "CNY" {
		return 0, errors.New("unsupported money")
	}
	return n.Int64(), nil
}
func callback(style string, c sdk.Call) sdk.Step {
	v, err := sdk.Input[abi.CallbackInput](c)
	if err != nil || len(c.Responses) != 0 || v.Method != "POST" || len(v.RawQuery) != 0 {
		return sdk.Fail("callback_input")
	}
	account, err := sdk.Config("account_id")
	if err != nil {
		return sdk.Fail("config")
	}
	headers := v.Headers
	var event Event
	if style == "json-rsa" {
		if len(headerValues(headers, "X-Signature")) != 1 {
			return sdk.Fail("callback_signature")
		}
		valid, e := sdk.Verify("rsa-sha256", "upstream_public", firstHeader(headers, "X-Signature"), sdk.Bytes(v.Body))
		if e != nil || !valid {
			return sdk.Fail("callback_signature")
		}
		if abi.Decode(v.Body, &event) != nil {
			return sdk.Fail("callback_json")
		}
	} else {
		values, e := url.ParseQuery(string(v.Body))
		if e != nil {
			return sdk.Fail("callback_form")
		}
		canonical, e := CanonicalForm(values)
		if e != nil {
			return sdk.Fail("callback_form")
		}
		sig, e := sdk.Sign("md5", "", sdk.Bytes([]byte(canonical+"&key=")), sdk.Secret("shared"))
		if e != nil {
			return sdk.Fail("callback_signature")
		}
		valid, e := sdk.Equal(sig, values.Get("sign"))
		if e != nil || !valid {
			return sdk.Fail("callback_signature")
		}
		// Reject fields outside the exact upstream callback schema and parse integers exactly.
		for k := range values {
			if !strings.Contains("|event_id|account_id|order_id|upstream_id|amount|currency|status|sequence|paid_at|sign|", "|"+k+"|") {
				return sdk.Fail("callback_field")
			}
		}
		event = Event{EventID: values.Get("event_id"), AccountID: values.Get("account_id"), OrderID: values.Get("order_id"), UpstreamID: values.Get("upstream_id"), Currency: values.Get("currency"), Status: values.Get("status"), PaidAt: values.Get("paid_at")}
		event.Amount, e = strconv.ParseInt(values.Get("amount"), 10, 64)
		if e != nil || strconv.FormatInt(event.Amount, 10) != values.Get("amount") {
			return sdk.Fail("callback_amount")
		}
		event.Sequence, e = strconv.Atoi(values.Get("sequence"))
		if e != nil || strconv.Itoa(event.Sequence) != values.Get("sequence") {
			return sdk.Fail("callback_sequence")
		}
	}
	if event.AccountID != account || event.Amount <= 0 || event.Sequence <= 0 || event.EventID == "" || event.Currency != "CNY" {
		return sdk.Fail("callback_identity")
	}
	return sdk.Result(abi.Result{Outcome: "completed", Callback: &abi.CallbackOutput{EventID: event.EventID, OrderID: event.OrderID, UpstreamID: event.UpstreamID, Money: abi.Money{Amount: strconv.FormatInt(event.Amount, 10), Currency: event.Currency}, Status: event.Status, Ack: abi.Response{Status: 200, Headers: map[string][]string{"Content-Type": {"text/plain"}}, Body: []byte("success")}}})
}

func headerValues(h map[string][]string, name string) []string {
	for k, v := range h {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return nil
}
func firstHeader(h map[string][]string, name string) string {
	v := headerValues(h, name)
	if len(v) > 0 {
		return v[0]
	}
	return ""
}

// Routing returns only an untrusted clue; authentication follows with a snapshot.
func route(style string, c sdk.Call) sdk.Step {
	v, err := sdk.Input[abi.RouteCallbackInput](c)
	if err != nil || len(c.Responses) != 0 || v.Method != "POST" || len(v.RawQuery) != 0 {
		return sdk.Fail("route_input")
	}
	var order string
	if style == "json-rsa" {
		var event Event
		if abi.Decode(v.Body, &event) != nil {
			return sdk.Fail("route_json")
		}
		order = event.OrderID
	} else {
		values, e := url.ParseQuery(string(v.Body))
		if e != nil {
			return sdk.Fail("route_form")
		}
		if _, e = CanonicalForm(values); e != nil {
			return sdk.Fail("route_form")
		}
		order = values.Get("order_id")
	}
	return sdk.Result(abi.Result{Outcome: "completed", Route: &abi.RouteCallbackOutput{OrderID: order}})
}
