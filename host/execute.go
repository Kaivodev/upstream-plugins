package host

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/Kaivodev/upstream-plugins/abi"
)

const MaxSteps = 5
const MaxBody = 256 << 10

// Upstream payment gateways commonly answer in several seconds; a timeout that
// is too short turns ordinary latency into "unknown" results.
const DefaultRequestTimeout = 10 * time.Second
const MaxRequestTimeout = 30 * time.Second

type Category string

const (
	Completed Category = "completed"
	Rejected  Category = "rejected"
	Unknown   Category = "unknown"
	NotSent   Category = "not_sent"
)

type Execution struct {
	Category        Category    `json:"category"`
	ErrorCode       string      `json:"error_code,omitempty"`
	Result          *abi.Result `json:"result,omitempty"`
	Requests        int         `json:"requests"`
	Responses       int         `json:"responses"`
	Steps           int         `json:"steps"`
	PeakMemoryBytes uint32      `json:"-"`
}

var idRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,100}$`)

func inputIdentity(op abi.Operation, b []byte) (order, refund string, money abi.Money, err error) {
	switch op {
	case abi.CreatePayment:
		var v abi.CreatePaymentInput
		err = abi.Decode(b, &v)
		order, money = v.OrderID, v.Money
		if err == nil && (v.Method == "" || v.CallbackURL == "") {
			err = errors.New("missing create fields")
		}
	case abi.QueryPayment, abi.ClosePayment:
		var v abi.PaymentInput
		err = abi.Decode(b, &v)
		order, money = v.OrderID, v.Money
	case abi.Refund, abi.QueryRefund:
		var v abi.RefundInput
		err = abi.Decode(b, &v)
		order, refund, money = v.OrderID, v.RefundID, v.Money
		if err == nil && !idRE.MatchString(refund) {
			err = errors.New("invalid refund ID")
		}
	case abi.VerifyCallback:
		var v abi.CallbackInput
		err = abi.Decode(b, &v)
		order, money = v.OrderID, v.Money
		if err == nil && (v.Method == "" || len(v.Body) > 64<<10 || len(v.RawQuery) > 16<<10) {
			err = errors.New("invalid callback request")
		}
	default:
		err = errors.New("unsupported operation")
	}
	if err == nil && !idRE.MatchString(order) {
		err = errors.New("invalid order ID")
	}
	if err == nil {
		n, e := abi.ParseAmount(money)
		err = e
		if e == nil && n.Sign() <= 0 {
			err = errors.New("positive amount required")
		}
	}
	return
}
func (h *Host) Execute(ctx context.Context, l *Loaded, op abi.Operation, input []byte, env Environment) (out Execution) {
	out.Category = NotSent
	if l == nil || env == nil || !slices.Contains(l.manifest.Capabilities, op) || !op.Payment() {
		out.ErrorCode = "unsupported_operation"
		return
	}
	order, refund, money, err := inputIdentity(op, input)
	if err != nil {
		out.ErrorCode = "input_json"
		return
	}
	s := &invocation{manifest: l.manifest, env: env, secrets: map[string][]byte{}, config: map[string]string{}, remaining: SandboxTimeout}
	defer func() {
		out.PeakMemoryBytes = s.peak
		if s.fault == "secret_leak" || out.ErrorCode == "secret_leak" {
			out.Result = nil
			out.ErrorCode = "secret_leak"
			s.alert(ctx)
		} else {
			for _, entry := range s.messages {
				env.Log(ctx, entry)
			}
			if s.stdout.Len() > 0 {
				env.Log(ctx, abi.LogRequest{Level: "info", Message: "sandbox output", Fields: map[string]string{"output": s.stdout.String()}})
			}
		}
		for _, b := range s.secrets {
			clear(b)
		}
	}()
	fail := func(code string) Execution {
		out.ErrorCode = code
		if out.Requests > 0 {
			out.Category = Unknown
		}
		return out
	}
	for n := range l.manifest.Secrets {
		v, e := env.Secret(ctx, n)
		if e != nil || len(v) < 16 || len(v) > 16<<10 {
			return fail("credential_unavailable")
		}
		s.secrets[n] = bytes.Clone(v)
	}
	for n, f := range l.manifest.Config {
		v, e := env.Config(ctx, n)
		if e != nil {
			if f.Required {
				return fail("config_unavailable")
			}
			continue
		}
		if len(v) > 8192 {
			return fail("config_limit")
		}
		s.config[n] = v
	}
	configJSON, _ := json.Marshal(s.config)
	if s.jsonLeak(configJSON) || s.jsonLeak(input) {
		return fail("secret_leak")
	}
	if op == abi.VerifyCallback {
		var v abi.CallbackInput
		_ = abi.Decode(input, &v)
		if l.manifest.Callback == nil || !slices.Contains(l.manifest.Callback.Methods, v.Method) || !l.manifest.Callback.AllowQuery && len(v.RawQuery) > 0 {
			return fail("callback_request")
		}
		headers, e := normalizeHeaders(v.Headers)
		if e != nil {
			return fail("callback_headers")
		}
		v.Headers = headers
		input, _ = json.Marshal(v)
		ct, _, e := mime.ParseMediaType(headers.Get("Content-Type"))
		if e != nil || l.manifest.Callback == nil || !slices.Contains(l.manifest.Callback.ContentTypes, ct) {
			return fail("callback_content_type")
		}
	}
	c := context.WithValue(ctx, operationKey{}, op)
	call := abi.Call{Input: bytes.Clone(input), Responses: []abi.Response{}}
	for step := 1; step <= MaxSteps; step++ {
		out.Steps = step
		next, code := h.step(c, l, s, call)
		if code != "" {
			return fail(code)
		}
		if next.Request != nil {
			if op == abi.VerifyCallback {
				return fail("callback_network_forbidden")
			}
			if step == MaxSteps {
				return fail("step_limit")
			}
			req, code := h.request(ctx, s, *next.Request)
			if code != "" {
				return fail(code)
			}
			transport := env.Transport()
			if transport == nil {
				return fail("transport_unavailable")
			}
			rctx, cancel := context.WithTimeout(ctx, h.options.RequestTimeout)
			req = req.WithContext(rctx)
			out.Requests++ // Conservative dispatch boundary: transport may send before returning an error.
			res, e := transport.RoundTrip(req)
			if e != nil {
				if res != nil && res.Body != nil {
					res.Body.Close()
				}
				cancel()
				return fail("transport_error")
			}
			if res == nil || res.Body == nil {
				cancel()
				return fail("transport_response")
			}
			body, e := io.ReadAll(io.LimitReader(res.Body, MaxBody+1))
			res.Body.Close()
			cancel()
			if e != nil {
				return fail("transport_error")
			}
			if len(body) > MaxBody {
				return fail("response_limit")
			}
			if res.StatusCode < 100 || res.StatusCode > 599 {
				return fail("response_status")
			}
			if res.StatusCode >= 300 && res.StatusCode <= 399 {
				return fail("redirect_forbidden")
			}
			headers, e := normalizeHeaders(res.Header)
			if e != nil {
				return fail("response_headers")
			}
			response := abi.Response{Status: res.StatusCode, Headers: headers, Body: body}
			b, _ := json.Marshal(response)
			if s.jsonLeak(b) || s.leak(body) {
				return fail("secret_leak")
			}
			out.Responses++
			call.Responses = append(call.Responses, response)
			continue
		}
		r := next.Result
		if len(r.Code) > 128 {
			return fail("output_structure")
		}
		if r.Outcome == "error" {
			return fail("plugin_error")
		}
		if r.Outcome == "unknown" {
			return fail("upstream_unknown")
		}
		if r.Outcome == "rejected" {
			if out.Responses == 0 {
				return fail("unsubstantiated_rejection")
			}
			if r.Code == "" || r.Payment != nil || r.Refund != nil || r.Callback != nil {
				return fail("output_structure")
			}
			out.Category = Rejected
			out.Result = r
			return out
		}
		if r.Outcome != "completed" {
			return fail("output_outcome")
		}
		if code := h.validateResult(l.manifest, op, r, order, refund, money); code != "" {
			return fail(code)
		}
		if op != abi.VerifyCallback && out.Responses == 0 {
			return fail("unsubstantiated_result")
		}
		out.Category = Completed
		out.Result = r
		return out
	}
	return fail("step_limit")
}
func (h *Host) validateResult(m Manifest, op abi.Operation, r *abi.Result, order, refund string, money abi.Money) string {
	count := 0
	if r.Payment != nil {
		count++
	}
	if r.Refund != nil {
		count++
	}
	if r.Callback != nil {
		count++
	}
	if count != 1 {
		return "output_structure"
	}
	switch op {
	case abi.CreatePayment, abi.QueryPayment, abi.ClosePayment:
		p := r.Payment
		if p == nil || p.OrderID != order || p.UpstreamID == "" || !slices.Contains([]string{"pending", "paid", "closed", "failed", "unknown"}, p.Status) {
			return "output_identity"
		}
		if !abi.EqualMoney(p.Money, money) {
			return "amount_mismatch"
		}
		if p.URL != "" && p.QRCode != "" {
			return "output_instruction"
		}
		if op == abi.CreatePayment && p.Status == "pending" && p.URL == "" && p.QRCode == "" {
			return "output_instruction"
		}
		if p.URL != "" {
			u, e := url.Parse(p.URL)
			if e != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "https" && !(h.options.TestOnlyAllowHTTP && u.Scheme == "http")) {
				return "output_instruction"
			}
		}
		if p.PaidAt != "" {
			if _, e := time.Parse(time.RFC3339Nano, p.PaidAt); e != nil {
				return "output_time"
			}
		}
	case abi.Refund, abi.QueryRefund:
		p := r.Refund
		if p == nil || p.OrderID != order || p.RefundID != refund || p.UpstreamRefundID == "" || !slices.Contains([]string{"pending", "succeeded", "failed", "unknown"}, p.Status) {
			return "output_identity"
		}
		if !abi.EqualMoney(p.Money, money) {
			return "amount_mismatch"
		}
	case abi.VerifyCallback:
		p := r.Callback
		if p == nil || p.OrderID != order || p.UpstreamID == "" || p.EventID == "" || !slices.Contains([]string{"pending", "paid", "closed", "failed", "unknown"}, p.Status) {
			return "output_identity"
		}
		if !abi.EqualMoney(p.Money, money) {
			return "amount_mismatch"
		}
		if m.Callback == nil || p.Ack.Status != m.Callback.AckStatus || string(p.Ack.Body) != m.Callback.AckBody {
			return "callback_ack"
		}
		if headers, e := normalizeHeaders(p.Ack.Headers); e != nil || len(headers.Values("Content-Type")) != 1 || headers.Get("Content-Type") != m.Callback.AckContentType {
			return "callback_ack"
		}
	default:
		return "unsupported_operation"
	}
	return ""
}
func normalizeHeaders(in map[string][]string) (http.Header, error) {
	out := http.Header{}
	total := 0
	for name, values := range in {
		if name == "" || http.CanonicalHeaderKey(name) == "" || len(values) == 0 {
			return nil, errors.New("invalid header")
		}
		for _, c := range name {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", c)) {
				return nil, errors.New("invalid header")
			}
		}
		key := http.CanonicalHeaderKey(name)
		if _, ok := out[key]; ok {
			return nil, errors.New("duplicate header spelling")
		}
		for _, v := range values {
			if strings.ContainsAny(v, "\r\n\x00") {
				return nil, errors.New("invalid header value")
			}
			total += len(name) + len(v)
			if total > 16<<10 {
				return nil, errors.New("header limit")
			}
		}
		out[key] = slices.Clone(values)
	}
	return out, nil
}
func (h *Host) request(ctx context.Context, s *invocation, r abi.Request) (*http.Request, string) {
	if len(r.Body) > MaxBody {
		return nil, "request_limit"
	}
	if r.Method == "" || strings.ToUpper(r.Method) != r.Method {
		return nil, "request_method"
	}
	u, err := url.Parse(r.URL)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return nil, "request_url"
	}
	if u.Scheme != "https" && !(h.options.TestOnlyAllowHTTP && u.Scheme == "http") {
		return nil, "https_required"
	}
	if !slices.Contains(s.manifest.Domains, u.Hostname()) || strings.ToLower(u.Hostname()) != u.Hostname() {
		return nil, "domain_forbidden"
	}
	rawHeaders, _ := json.Marshal(r.Headers)
	if s.jsonLeak(rawHeaders) {
		return nil, "secret_leak"
	}
	headers, err := normalizeHeaders(r.Headers)
	if err != nil {
		return nil, "request_headers"
	}
	for name, values := range headers {
		if slices.Contains([]string{"Host", "Content-Length", "Transfer-Encoding", "Connection", "Proxy-Authorization", "Proxy-Connection", "Upgrade", "Trailer", "Te"}, name) {
			return nil, "request_headers"
		}
		for i, v := range values {
			if start := strings.Index(v, "{{secret:"); start >= 0 {
				tail := v[start+9:]
				end := strings.Index(tail, "}}")
				if end < 0 {
					return nil, "secret_placeholder"
				}
				ref := tail[:end]
				if s.manifest.Secrets[ref] != "shared" || strings.Contains(tail[end+2:], "{{") || strings.Contains(v[:start], "{{") {
					return nil, "secret_placeholder"
				}
				value := string(s.secrets[ref])
				if strings.ContainsAny(value, "\r\n\x00") {
					return nil, "secret_placeholder"
				}
				values[i] = v[:start] + value + tail[end+2:]
			}
		}
		headers[name] = values
	}
	if s.leak([]byte(r.URL)) || s.leak(r.Body) {
		return nil, "secret_leak"
	}
	req, err := http.NewRequestWithContext(ctx, r.Method, r.URL, bytes.NewReader(r.Body))
	if err != nil {
		return nil, "request_url"
	}
	req.Header = headers
	return req, ""
}
