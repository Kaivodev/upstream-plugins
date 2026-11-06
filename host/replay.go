package host

import (
	"bytes"
	"context"
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/Kaivodev/upstream-plugins/abi"
)

const TestSignature = "TEST_SIGNATURE_REGENERATED_AT_REPLAY"

type Exchange struct {
	Request  abi.Request   `json:"request"`
	Response *abi.Response `json:"response,omitempty"`
	Error    string        `json:"error,omitempty"`
}
type Fixture struct {
	Name                   string            `json:"name"`
	Source                 string            `json:"source"`
	Operation              abi.Operation     `json:"operation"`
	Input                  json.RawMessage   `json:"input"`
	Config                 map[string]string `json:"config"`
	Time                   string            `json:"time"`
	RandomSeed             []byte            `json:"random_seed"`
	TestOnlyResignCallback bool              `json:"test_only_resign_callback,omitempty"`
	Exchanges              []Exchange        `json:"exchanges"`
	Expected               Execution         `json:"expected"`
}
type CaseReport struct {
	Path          string    `json:"path"`
	FixtureSHA256 string    `json:"fixture_sha256"`
	Passed        bool      `json:"passed"`
	Actual        Execution `json:"actual"`
}
type Report struct {
	Version       int          `json:"version"`
	PackageSHA256 string       `json:"package_sha256"`
	Passed        bool         `json:"passed"`
	Cases         []CaseReport `json:"cases"`
}

// TestCredentials exists only for offline replay and the explicitly test-only recorder.
// It generates credentials in memory, never serializes or logs them.
type TestCredentials struct {
	Platform    *rsa.PrivateKey
	Callback    *rsa.PrivateKey
	Query       *rsa.PrivateKey
	QueryShared []byte
	Shared      []byte
}

func NewTestCredentials() (*TestCredentials, error) {
	a, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		return nil, e
	}
	b, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		return nil, e
	}
	shared := make([]byte, 32)
	if _, e = rand.Read(shared); e != nil {
		return nil, e
	}
	query, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		return nil, e
	}
	queryShared := make([]byte, 32)
	if _, e = rand.Read(queryShared); e != nil {
		return nil, e
	}
	return &TestCredentials{Platform: a, Callback: b, Query: query, QueryShared: []byte(hex.EncodeToString(queryShared)), Shared: []byte(hex.EncodeToString(shared))}, nil
}
func TestPrivatePEM(key *rsa.PrivateKey) []byte {
	b, _ := x509.MarshalPKCS8PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b})
}

// SeedReader produces an infinite SHA-256 counter stream from recorded test entropy.
// This is fixture entropy, never a live cryptographic randomness source.
func SeedReader(seed []byte) io.Reader { return &seedReader{seed: bytes.Clone(seed)} }

type seedReader struct {
	seed    []byte
	counter uint64
	buffer  []byte
}

func (s *seedReader) Read(b []byte) (int, error) {
	for i := range b {
		if len(s.buffer) == 0 {
			h := sha256.New()
			h.Write(s.seed)
			for shift := 56; shift >= 0; shift -= 8 {
				h.Write([]byte{byte(s.counter >> shift)})
			}
			s.counter++
			s.buffer = h.Sum(nil)
		}
		b[i] = s.buffer[0]
		s.buffer = s.buffer[1:]
	}
	return len(b), nil
}
func (t *TestCredentials) Services(f Fixture, transport http.RoundTripper) (Services, error) {
	now, e := time.Parse(time.RFC3339Nano, f.Time)
	if e != nil || len(f.RandomSeed) != 32 {
		return Services{}, errors.New("invalid recorded clock or entropy")
	}
	return Services{ConfigValues: f.Config, ResolveSecret: func(_ context.Context, n string) ([]byte, error) {
		switch n {
		case "query_private_key":
			return TestPrivatePEM(t.Query), nil
		case "query_key":
			return bytes.Clone(t.QueryShared), nil
		case "platform_private":
			return TestPrivatePEM(t.Platform), nil
		case "shared":
			return bytes.Clone(t.Shared), nil
		default:
			return nil, errors.New("unknown test credential")
		}
	}, ResolvePublicKey: func(_ context.Context, n string) (*rsa.PublicKey, error) {
		if n == "upstream_public" {
			return &t.Callback.PublicKey, nil
		}
		return nil, errors.New("unknown test key")
	}, Clock: func() time.Time { return now }, RandomSource: SeedReader(f.RandomSeed), HTTP: transport}, nil
}

// NormalizeTestRequest removes ephemeral test signatures, preserving all other
// bytes (including RSA-signed raw JSON). It is used only by fixture machinery.
func NormalizeTestRequest(r abi.Request) abi.Request {
	r.Body = bytes.Clone(r.Body)
	r.Headers = http.Header(r.Headers).Clone()
	for k := range r.Headers {
		if strings.EqualFold(k, "X-Signature") {
			r.Headers[k] = []string{TestSignature}
		}
	}
	ct := http.Header(r.Headers).Get("Content-Type")
	if strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		if v, e := url.ParseQuery(string(r.Body)); e == nil {
			if _, ok := v["sign"]; ok {
				v.Set("sign", TestSignature)
				r.Body = []byte(v.Encode())
			}
		}
	}
	return r
}
func (t *TestCredentials) SignCallback(f *Fixture) error {
	if !f.TestOnlyResignCallback {
		return nil
	}
	if f.Operation != abi.VerifyCallback {
		return errors.New("resigning only applies to callback fixtures")
	}
	var in abi.CallbackInput
	if e := abi.Decode(f.Input, &in); e != nil {
		return e
	}
	headers := http.Header(in.Headers)
	if headers.Get("Content-Type") == "application/json" {
		d := sha256.Sum256(in.Body)
		sig, e := rsa.SignPKCS1v15(rand.Reader, t.Callback, crypto.SHA256, d[:])
		if e != nil {
			return e
		}
		headers.Set("X-Signature", base64.StdEncoding.EncodeToString(sig))
	} else {
		v, e := url.ParseQuery(string(in.Body))
		if e != nil {
			return e
		}
		canonical, e := canonicalFixtureForm(v)
		if e != nil {
			return e
		}
		h := md5.Sum(append([]byte(canonical+"&key="), t.Shared...))
		v.Set("sign", hex.EncodeToString(h[:]))
		in.Body = []byte(v.Encode())
	}
	in.Headers = headers
	f.Input, _ = json.Marshal(in)
	return nil
}
func canonicalFixtureForm(v url.Values) (string, error) {
	keys := []string{}
	for k, x := range v {
		if k == "" || len(x) != 1 {
			return "", errors.New("invalid form")
		}
		if k != "sign" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	parts := []string{}
	for _, k := range keys {
		parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v.Get(k)))
	}
	return strings.Join(parts, "&"), nil
}

type fixtureTransport struct {
	exchanges []Exchange
	index     int
	mismatch  bool
	resolve   func(string) ([]byte, error)
}

func (t *fixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if t.index >= len(t.exchanges) {
		t.mismatch = true
		return nil, errors.New("unexpected fixture request")
	}
	x := t.exchanges[t.index]
	t.index++
	body, e := io.ReadAll(r.Body)
	if e != nil {
		return nil, e
	}
	actual := NormalizeTestRequest(abi.Request{Method: r.Method, URL: r.URL.String(), Headers: r.Header, Body: body})
	a, _ := json.Marshal(actual)
	expected := x.Request
	expected.Headers = http.Header(expected.Headers).Clone()
	for name, values := range expected.Headers {
		for i, v := range values {
			if start := strings.Index(v, "{{secret:"); start >= 0 {
				tail := v[start+9:]
				end := strings.Index(tail, "}}")
				if end < 0 || t.resolve == nil {
					t.mismatch = true
					return nil, errors.New("invalid fixture secret placeholder")
				}
				secret, e := t.resolve(tail[:end])
				if e != nil {
					t.mismatch = true
					return nil, errors.New("fixture test credential unavailable")
				}
				values[i] = v[:start] + string(secret) + tail[end+2:]
			}
		}
		expected.Headers[name] = values
	}
	b, _ := json.Marshal(expected)
	if !bytes.Equal(a, b) {
		t.mismatch = true
		return nil, errors.New("fixture request mismatch")
	}
	if x.Error != "" {
		if x.Error != "timeout" && x.Error != "transport_error" {
			t.mismatch = true
		}
		return nil, errors.New("recorded transport failure")
	}
	if x.Response == nil {
		t.mismatch = true
		return nil, errors.New("missing fixture response")
	}
	v := x.Response
	return &http.Response{StatusCode: v.Status, Header: http.Header(v.Headers).Clone(), Body: io.NopCloser(bytes.NewReader(v.Body))}, nil
}

// ReplayEnvironmentFactory supplies ephemeral test credential services for arbitrary
// protocols. prepare may re-sign a callback template in memory; it must preserve
// all business bytes. Transport, configuration, clocks and entropy are always
// replaced with recorded fixture values by ReplayWithEnvironment.
type ReplayEnvironmentFactory func(context.Context, Manifest, Fixture) (Environment, func(*Fixture) error, error)

func Replay(ctx context.Context, p Package) ([]byte, string, error) {
	return ReplayWithEnvironment(ctx, p, nil)
}
func ReplayWithEnvironment(ctx context.Context, p Package, factory ReplayEnvironmentFactory) ([]byte, string, error) {
	if e := ValidateFixtures(p.Fixtures); e != nil {
		return nil, "", e
	}
	m, _, e := p.Manifest()
	if e != nil {
		return nil, "", e
	}
	h, e := New(ctx, Options{PluginType: m.Type, TestOnlyAllowHTTP: true, TestOnlyAllowUncommitted: true})
	if e != nil {
		return nil, "", e
	}
	defer h.Close(ctx)
	l, e := h.Load(ctx, p)
	if e != nil {
		return nil, "", e
	}
	keys, e := NewTestCredentials()
	if e != nil {
		return nil, "", e
	}
	report := Report{Version: abi.Version, PackageSHA256: l.hash, Passed: true, Cases: []CaseReport{}}
	paths := make([]string, 0, len(p.Fixtures))
	for path := range p.Fixtures {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	coverage := map[abi.Operation]map[string]bool{}
	for _, path := range paths {
		b := p.Fixtures[path]
		var f Fixture
		if e := abi.Decode(b, &f); e != nil {
			return nil, "", errors.New("invalid fixture: " + path)
		}
		if !slices.Contains(m.Capabilities, f.Operation) || f.Name == "" || f.Source == "" {
			return nil, "", errors.New("invalid fixture identity")
		}
		scenario, ok := strings.CutPrefix(f.Name, string(f.Operation)+"/")
		if !ok {
			return nil, "", errors.New("fixture name must be operation/scenario")
		}
		if coverage[f.Operation] == nil {
			coverage[f.Operation] = map[string]bool{}
		}
		if coverage[f.Operation][scenario] {
			return nil, "", errors.New("duplicate fixture scenario")
		}
		coverage[f.Operation][scenario] = true
		if !validFixtureExpectation(f.Operation, scenario, f.Expected) {
			return nil, "", errors.New("invalid fixture expected category")
		}
		t := &fixtureTransport{exchanges: f.Exchanges}
		var env Environment
		if factory == nil {
			services, err := keys.Services(f, t)
			if err != nil {
				return nil, "", err
			}
			services.ResolveSecret = func(_ context.Context, n string) ([]byte, error) {
				if n == "query_key" {
					return bytes.Clone(keys.QueryShared), nil
				}
				if n == "query_private_key" {
					return TestPrivatePEM(keys.Query), nil
				}
				switch m.Secrets[n] {
				case "shared":
					return bytes.Clone(keys.Shared), nil
				case "rsa-private":
					return TestPrivatePEM(keys.Platform), nil
				}
				return nil, errors.New("undeclared test secret")
			}
			services.ResolvePublicKey = func(_ context.Context, n string) (*rsa.PublicKey, error) {
				if slices.Contains(m.PublicKeys, n) {
					return &keys.Callback.PublicKey, nil
				}
				return nil, errors.New("undeclared test public key")
			}
			env = services
			if err = keys.SignCallback(&f); err != nil {
				return nil, "", err
			}
		} else {
			supplied, prepare, err := factory(ctx, m, f)
			if err != nil {
				return nil, "", err
			}
			if supplied == nil {
				return nil, "", errors.New("nil replay environment")
			}
			if prepare != nil {
				if err = prepare(&f); err != nil {
					return nil, "", err
				}
			} else if f.TestOnlyResignCallback {
				return nil, "", errors.New("callback template requires test signing")
			}
			now, err := time.Parse(time.RFC3339Nano, f.Time)
			if err != nil || len(f.RandomSeed) != 32 {
				return nil, "", errors.New("invalid recorded clock or entropy")
			}
			env = recordedEnvironment{Environment: supplied, config: f.Config, now: now, random: SeedReader(f.RandomSeed), transport: t}
		}
		t.resolve = func(n string) ([]byte, error) {
			if m.Secrets[n] != "shared" {
				return nil, errors.New("undeclared fixture secret")
			}
			return env.Secret(ctx, n)
		}
		actual := h.Execute(ctx, l, f.Operation, f.Input, env)
		a, _ := json.Marshal(actual)
		expected, _ := json.Marshal(f.Expected)
		passed := bytes.Equal(a, expected) && t.index == len(t.exchanges) && !t.mismatch
		sum := sha256.Sum256(b)
		report.Cases = append(report.Cases, CaseReport{Path: path, FixtureSHA256: hex.EncodeToString(sum[:]), Passed: passed, Actual: actual})
		report.Passed = report.Passed && passed
	}
	for _, op := range m.Capabilities {
		scenarios := []string{"success", "rejected", "timeout", "signature_error", "amount_mismatch"}
		if op == abi.VerifyCallback {
			scenarios = []string{"success", "signature_error", "amount_mismatch"}
		} else if op == abi.RouteCallback {
			scenarios = []string{"success", "malformed"}
		}
		for _, scenario := range scenarios {
			if !coverage[op][scenario] {
				return nil, "", errors.New("missing required operation/scenario fixture")
			}
		}
	}
	b, e := json.Marshal(report)
	if e != nil {
		return nil, "", e
	}
	b, e = abi.Canonical(b)
	if e != nil {
		return nil, "", e
	}
	sum := sha256.Sum256(b)
	digest := hex.EncodeToString(sum[:])
	if !report.Passed {
		return b, digest, errors.New("fixture regression failed")
	}
	return b, digest, nil
}

type recordedEnvironment struct {
	Environment
	config    map[string]string
	now       time.Time
	random    io.Reader
	transport http.RoundTripper
}

func (r recordedEnvironment) Config(_ context.Context, n string) (string, error) {
	v, ok := r.config[n]
	if !ok {
		return "", errors.New("missing recorded configuration")
	}
	return v, nil
}
func (r recordedEnvironment) Now() time.Time               { return r.now }
func (r recordedEnvironment) Random() io.Reader            { return r.random }
func (r recordedEnvironment) Transport() http.RoundTripper { return r.transport }
func validFixtureExpectation(op abi.Operation, scenario string, e Execution) bool {
	if op == abi.RouteCallback {
		return scenario == "success" && e.Category == Completed && e.Result != nil || scenario == "malformed" && e.Category == NotSent && e.Requests == 0
	}
	switch scenario {
	case "success":
		return e.Category == Completed && e.Result != nil
	case "rejected":
		return op != abi.VerifyCallback && e.Category == Rejected && e.Responses > 0
	case "timeout":
		return op != abi.VerifyCallback && e.Category == Unknown && e.Requests > 0
	case "signature_error":
		return (op == abi.VerifyCallback && e.Category == NotSent) || (op != abi.VerifyCallback && e.Category == Rejected && e.Responses > 0)
	case "amount_mismatch":
		return e.ErrorCode == "amount_mismatch" && ((op == abi.VerifyCallback && e.Category == NotSent) || (op != abi.VerifyCallback && e.Category == Unknown))
	}
	return false
}
