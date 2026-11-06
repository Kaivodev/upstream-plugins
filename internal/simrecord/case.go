package simrecord

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Kaivodev/upstream-plugins/abi"
	"github.com/Kaivodev/upstream-plugins/host"
)

// Credentials is only for explicitly test-only CLI recording/replay. Services
// can instead use host.Environment to resolve versioned credentials themselves.
// This value must never be serialized into fixtures or reports.
type Credentials struct {
	Secrets    map[string]string `json:"secrets"`
	PublicKeys map[string]string `json:"public_keys"`
}

func (c Credentials) Services() host.Services {
	return host.Services{
		ResolveSecret: func(_ context.Context, n string) ([]byte, error) {
			v, ok := c.Secrets[n]
			if !ok {
				return nil, errors.New("test credential unavailable")
			}
			return []byte(v), nil
		},
		ResolvePublicKey: func(_ context.Context, n string) (*rsa.PublicKey, error) {
			b, ok := c.PublicKeys[n]
			if !ok {
				return nil, errors.New("test public key unavailable")
			}
			block, _ := pem.Decode([]byte(b))
			if block == nil {
				return nil, errors.New("invalid test public key")
			}
			v, e := x509.ParsePKIXPublicKey(block.Bytes)
			if e != nil {
				return nil, errors.New("invalid test public key")
			}
			key, ok := v.(*rsa.PublicKey)
			if !ok {
				return nil, errors.New("invalid test public key")
			}
			return key, nil
		},
	}
}

type caseTransport struct {
	base        http.RoundTripper
	credentials Credentials
	exchanges   []host.Exchange
}

func (t *caseTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	body, e := io.ReadAll(r.Body)
	if e != nil {
		return nil, e
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	request := abi.Request{Method: r.Method, URL: r.URL.String(), Headers: r.Header.Clone(), Body: body}
	// Preserve the credential reference for matching without storing resolved bytes.
	for name, values := range request.Headers {
		for i, v := range values {
			for ref, secret := range t.credentials.Secrets {
				if secret != "" {
					v = strings.ReplaceAll(v, secret, "{{secret:"+ref+"}}")
				}
			}
			values[i] = v
		}
		request.Headers[name] = values
	}
	x := host.Exchange{Request: host.NormalizeTestRequest(request)}
	res, e := t.base.RoundTrip(r)
	if e != nil {
		if res != nil && res.Body != nil {
			res.Body.Close()
		}
		x.Error = "transport_error"
		if errors.Is(e, context.DeadlineExceeded) {
			x.Error = "timeout"
		}
		t.exchanges = append(t.exchanges, x)
		return nil, errors.New("test transport failed")
	}
	if res == nil || res.Body == nil {
		x.Error = "transport_error"
		t.exchanges = append(t.exchanges, x)
		return nil, errors.New("test transport response missing")
	}
	raw, e := io.ReadAll(io.LimitReader(res.Body, host.MaxBody+1))
	res.Body.Close()
	if e != nil {
		x.Error = "transport_error"
		t.exchanges = append(t.exchanges, x)
		return nil, errors.New("test response read failed")
	}
	// Preserve all protocol bytes, including headers used by signed responses.
	headers := res.Header.Clone()
	x.Response = &abi.Response{Status: res.StatusCode, Headers: headers, Body: raw}
	t.exchanges = append(t.exchanges, x)
	res.Header = headers
	res.Body = io.NopCloser(bytes.NewReader(raw))
	return res, nil
}

// RecordCase records one caller-specified operation against an actual test
// upstream. No setup, fault injection, payment or refund is invented here.
func RecordCase(ctx context.Context, p host.Package, f host.Fixture, c Credentials, allowHTTP bool, out string) error {
	m, _, e := p.Manifest()
	if e != nil {
		return e
	}
	if !f.Operation.Payment() || !slices.Contains(m.Capabilities, f.Operation) {
		return errors.New("unsupported recording operation")
	}
	scenario, ok := strings.CutPrefix(f.Name, string(f.Operation)+"/")
	if !ok || strings.ContainsAny(scenario, "/\\") || !slices.Contains([]string{"success", "rejected", "timeout", "signature_error", "amount_mismatch"}, scenario) {
		return errors.New("case name must be operation/scenario")
	}
	if f.Time == "" {
		f.Time = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if len(f.RandomSeed) == 0 {
		f.RandomSeed = make([]byte, 32)
		if _, e = rand.Read(f.RandomSeed); e != nil {
			return e
		}
	}
	clock, e := time.Parse(time.RFC3339Nano, f.Time)
	if e != nil || len(f.RandomSeed) != 32 || f.TestOnlyResignCallback {
		return errors.New("invalid case clock, entropy or callback template")
	}
	h, e := host.New(ctx, host.Options{PluginType: m.Type, TestOnlyAllowHTTP: allowHTTP, TestOnlyAllowUncommitted: true})
	if e != nil {
		return e
	}
	defer h.Close(ctx)
	loaded, e := h.Load(ctx, p)
	if e != nil {
		return e
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	recording := &caseTransport{base: transport, credentials: c, exchanges: []host.Exchange{}}
	env := c.Services()
	env.ConfigValues = f.Config
	env.HTTP = recording
	env.Clock = func() time.Time { return clock }
	env.RandomSource = host.SeedReader(f.RandomSeed)
	result := h.Execute(ctx, loaded, f.Operation, f.Input, env)
	if result.ErrorCode == "secret_leak" {
		return errors.New("test credential detected in recording")
	}
	if scenario == "amount_mismatch" && result.ErrorCode != "amount_mismatch" {
		return errors.New("case did not observe an amount mismatch")
	}
	if e = validateExpectation(scenario, f.Operation, result); e != nil {
		return e
	}
	if f.Expected.Category != "" && (f.Expected.Category != result.Category || f.Expected.ErrorCode != "" && f.Expected.ErrorCode != result.ErrorCode) {
		return errors.New("case result differs from expected category or error")
	}
	f.Source = "recorded_test_upstream"
	f.Expected = result
	f.Exchanges = recording.exchanges
	b, e := json.MarshalIndent(f, "", "  ")
	if e != nil {
		return e
	}
	// Inspect decoded JSON and Base64 byte fields, not only the serialized text.
	var leaked bool
	var inspect func(any)
	inspect = func(v any) {
		switch v := v.(type) {
		case string:
			if credentialLeak([]byte(v), c) {
				leaked = true
			}
			if raw, e := base64.StdEncoding.DecodeString(v); e == nil && credentialLeak(raw, c) {
				leaked = true
			}
		case []any:
			for _, v := range v {
				inspect(v)
			}
		case map[string]any:
			for key, v := range v {
				inspect(key)
				inspect(v)
			}
		}
	}
	var value any
	_ = json.Unmarshal(b, &value)
	inspect(value)
	for _, x := range f.Exchanges {
		if credentialLeak(x.Request.Body, c) || x.Response != nil && credentialLeak(x.Response.Body, c) {
			leaked = true
		}
	}
	if leaked {
		return errors.New("test credential detected in recording")
	}
	if e = os.MkdirAll(out, 0755); e != nil {
		return e
	}
	return os.WriteFile(filepath.Join(out, string(f.Operation)+"_"+scenario+".json"), append(b, '\n'), 0644)
}

func credentialLeak(b []byte, c Credentials) bool {
	for _, s := range c.Secrets {
		if s == "" {
			continue
		}
		for _, v := range []string{s, hex.EncodeToString([]byte(s)), strings.ToUpper(hex.EncodeToString([]byte(s))), base64.StdEncoding.EncodeToString([]byte(s)), base64.RawStdEncoding.EncodeToString([]byte(s)), base64.URLEncoding.EncodeToString([]byte(s)), base64.RawURLEncoding.EncodeToString([]byte(s))} {
			if bytes.Contains(b, []byte(v)) {
				return true
			}
		}
	}
	return false
}
