package host

import (
	"bytes"
	"context"
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Kaivodev/upstream-plugins/abi"
	"github.com/tetratelabs/wazero"
)

var malicious, unknown, network, legacy []byte
var onlyTestSecret string
var pluginPackages []Package

func TestMain(m *testing.M) {
	tmp, e := os.MkdirTemp("", "upstream-host-tests-")
	if e != nil {
		panic(e)
	}
	secret := make([]byte, 32)
	if _, e = rand.Read(secret); e != nil {
		panic(e)
	}
	onlyTestSecret = hex.EncodeToString(secret)
	for _, name := range []string{"malicious", "unknown", "network", "legacy"} {
		out := filepath.Join(tmp, name+".wasm")
		source := name
		flags := "-buildid= -X main.testSecret=" + onlyTestSecret
		if name == "legacy" {
			source = "malicious"
			flags += " -X main.forceV1=yes"
		}
		c := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-buildmode=c-shared", "-ldflags="+flags, "-o", out, "./testdata/"+source)
		c.Env = wasmEnv()
		if b, e := c.CombinedOutput(); e != nil {
			panic(string(b))
		}
		b, e := os.ReadFile(out)
		if e != nil {
			panic(e)
		}
		switch name {
		case "legacy":
			legacy = b
		case "malicious":
			malicious = b
		case "unknown":
			unknown = b
		case "network":
			network = b
		}
	}
	for _, name := range []string{"sim_json_rsa", "sim_form_md5", "sim_json_rsa_verify", "sim_form_md5_verify"} {
		dir := filepath.Join(tmp, name)
		if e = os.MkdirAll(dir, 0755); e != nil {
			panic(e)
		}
		out := filepath.Join(dir, "plugin.wasm")
		c := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-buildmode=c-shared", "-ldflags=-buildid=", "-o", out, "../plugins/"+name)
		c.Env = wasmEnv()
		if b, e := c.CombinedOutput(); e != nil {
			panic(string(b))
		}
		p := Package{Fixtures: map[string][]byte{}}
		p.Wasm, _ = os.ReadFile(out)
		p.ManifestJSON, e = os.ReadFile("../plugins/" + name + "/manifest.json")
		if e != nil {
			panic(e)
		}
		files, e := filepath.Glob("../plugins/" + name + "/fixtures/*.json")
		if e != nil {
			panic(e)
		}
		for _, path := range files {
			b, e := os.ReadFile(path)
			if e != nil {
				panic(e)
			}
			p.Fixtures["fixtures/"+filepath.Base(path)] = b
		}
		pluginPackages = append(pluginPackages, p)
	}
	code := m.Run()
	os.RemoveAll(tmp)
	os.Exit(code)
}
func wasmEnv() []string {
	keys := map[string]string{"GOWORK": "off", "GOOS": "wasip1", "GOARCH": "wasm", "CGO_ENABLED": "0", "GOPROXY": "off", "GOTOOLCHAIN": "local", "GOFLAGS": ""}
	env := []string{}
	for _, v := range os.Environ() {
		k, _, _ := strings.Cut(v, "=")
		if _, ok := keys[k]; !ok {
			env = append(env, v)
		}
	}
	for k, v := range keys {
		env = append(env, k+"="+v)
	}
	return env
}
func testManifest() Manifest {
	return Manifest{Type: "payment", Code: "test_plugin", Version: "1.0.0", ABIVersion: abi.Version, Domains: []string{"allowed.example"}, Secrets: map[string]string{"shared": "shared"}, PublicKeys: []string{}, Config: map[string]Field{"mode": {Type: "string", Required: true}}, Capabilities: []abi.Operation{abi.QueryPayment, abi.RouteCallback, abi.VerifyCallback}, Callback: &CallbackRules{Methods: []string{"POST"}, ContentTypes: []string{"application/json"}, AckContentType: "text/plain", AckStatus: 200, AckBody: "success"}, Build: BuildInfo{GoVersion: "go1.27.3", SourceCommit: "uncommitted", SourceTreeSHA256: strings.Repeat("0", 64)}}
}
func testPackage(w []byte) Package {
	b, _ := json.Marshal(testManifest())
	return Package{ManifestJSON: b, Wasm: w}
}
func newTestHost(t testing.TB, allowHTTP bool) (*Host, *Loaded) {
	t.Helper()
	h, e := New(context.Background(), Options{PluginType: "payment", TestOnlyAllowHTTP: allowHTTP, TestOnlyAllowUncommitted: true})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { h.Close(context.Background()) })
	l, e := h.Load(context.Background(), testPackage(malicious))
	if e != nil {
		t.Fatal(e)
	}
	return h, l
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func testEnv() Services {
	return Services{ConfigValues: map[string]string{"mode": "test"}, ResolveSecret: func(context.Context, string) ([]byte, error) { return []byte(onlyTestSecret), nil }, HTTP: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("{}"))}, nil
	})}
}
func testInput(mode string) []byte {
	b, _ := json.Marshal(abi.PaymentInput{OrderID: mode, Money: abi.Money{Amount: "12345", Currency: "CNY"}})
	return b
}
func TestSandboxBoundaries(t *testing.T) {
	h, l := newTestHost(t, false)
	for _, tc := range []struct {
		mode     string
		category Category
		code     string
	}{
		{"loop", NotSent, "sandbox_timeout"}, {"memory", NotSent, "memory_limit"}, {"random_limit", NotSent, "random_limit"}, {"file_env", NotSent, "unsubstantiated_rejection"}, {"exit", NotSent, "proc_exit"}, {"huge", NotSent, "output_limit"}, {"unknown", NotSent, "output_json"}, {"duplicate", NotSent, "output_json"},
		{"request_http", NotSent, "https_required"}, {"request_foreign", NotSent, "domain_forbidden"}, {"after_error", Unknown, "plugin_error"}, {"after_loop", Unknown, "sandbox_timeout"}, {"before_reject", NotSent, "unsubstantiated_rejection"}, {"always_request", Unknown, "step_limit"}, {"host_calls", NotSent, "host_call_limit"}, {"wasi_calls", NotSent, "host_call_limit"}, {"log_rate", NotSent, "log_rate_limit"}, {"bad_identity", Unknown, "output_identity"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			start := time.Now()
			r := h.Execute(context.Background(), l, abi.QueryPayment, testInput(tc.mode), testEnv())
			// Under the race detector a slow runner can exhaust the step budget
			// before a call-count limit trips. Both refuse the step without
			// dispatching, so only the error code may differ.
			limit := tc.code == "host_call_limit" || tc.code == "log_rate_limit"
			if raceEnabled && limit && r.Category == tc.category && r.ErrorCode == "sandbox_timeout" {
				return
			}
			if r.Category != tc.category || r.ErrorCode != tc.code {
				t.Fatalf("got %+v, want %s/%s", r, tc.category, tc.code)
			}
			if (tc.mode == "loop" || tc.mode == "after_loop") && time.Since(start) > time.Second {
				t.Fatal("termination too slow")
			}
			if tc.mode == "always_request" && r.Requests != 4 {
				t.Fatal("step bound", r)
			}
		})
	}
}
func TestSecretLeaksAndHeaderReplacement(t *testing.T) {
	h, l := newTestHost(t, false)
	for _, mode := range []string{"secret_plain", "secret_hex", "secret_base64", "secret_escaped", "log_secret"} {
		t.Run(mode, func(t *testing.T) {
			e := testEnv()
			alerts, logs := 0, 0
			e.Alerter = func(_ context.Context, code string) {
				if code != "secret_leak" {
					t.Fatal(code)
				}
				alerts++
			}
			e.Logger = func(context.Context, abi.LogRequest) { logs++ }
			r := h.Execute(context.Background(), l, abi.QueryPayment, testInput(mode), e)
			if r.ErrorCode != "secret_leak" || alerts != 1 || logs != 0 || r.Result != nil {
				t.Fatalf("leak escaped %+v alerts=%d logs=%d", r, alerts, logs)
			}
		})
	}
	e := testEnv()
	seen := false
	e.HTTP = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		seen = true
		if r.Header.Get("Authorization") != "Bearer "+onlyTestSecret {
			t.Fatal("secret header was not resolved")
		}
		return nil, errors.New("test transport failure")
	})
	r := h.Execute(context.Background(), l, abi.QueryPayment, testInput("request_header"), e)
	if !seen || r.Category != Unknown {
		t.Fatal(r)
	}
}
func TestTransportAndCallbackBoundaries(t *testing.T) {
	h, l := newTestHost(t, false)
	for _, tc := range []struct {
		name      string
		transport http.RoundTripper
		code      string
	}{
		{"redirect", roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 302, Header: http.Header{"Location": {"https://foreign.example"}}, Body: io.NopCloser(strings.NewReader(""))}, nil
		}), "redirect_forbidden"},
		{"transport", roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("test transport failed") }), "transport_error"},
		{"response_limit", roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", MaxBody+1)))}, nil
		}), "response_limit"},
		{"response_secret", roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(onlyTestSecret))}, nil
		}), "secret_leak"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := testEnv()
			e.HTTP = tc.transport
			calls := 0
			e.HTTP = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if _, ok := r.Context().Deadline(); !ok {
					t.Fatal("missing HTTP deadline")
				}
				return tc.transport.RoundTrip(r)
			})
			r := h.Execute(context.Background(), l, abi.QueryPayment, testInput("always_request"), e)
			if r.Category != Unknown || r.ErrorCode != tc.code || calls != 1 {
				t.Fatal(r, calls)
			}
		})
	}
	v := abi.CallbackInput{OrderID: "always_request", Money: abi.Money{Amount: "12345", Currency: "CNY"}, Method: "POST", Headers: map[string][]string{"Content-Type": {"application/json"}}, Body: []byte("{}")}
	b, _ := json.Marshal(v)
	r := h.Execute(context.Background(), l, abi.VerifyCallback, b, testEnv())
	if r.Category != NotSent || r.ErrorCode != "callback_network_forbidden" || r.Requests != 0 {
		t.Fatal(r)
	}
	r = h.Execute(context.Background(), l, abi.QueryPayment, bytes.Repeat([]byte("x"), abi.MaxJSON+1), testEnv())
	if r.Category != NotSent || r.ErrorCode != "input_json" {
		t.Fatal(r)
	}
}
func TestImportsExportsManifestAndCache(t *testing.T) {
	h, l := newTestHost(t, false)
	again, e := h.Load(context.Background(), testPackage(malicious))
	if e != nil || again != l {
		t.Fatal("cache not used", e)
	}
	if _, e = h.Load(context.Background(), testPackage(unknown)); e == nil {
		t.Fatal("unknown import loaded")
	}
	if guest, err := h.Load(context.Background(), testPackage(network)); err == nil {
		r := h.Execute(context.Background(), guest, abi.QueryPayment, testInput("network"), testEnv())
		if r.ErrorCode != "unsubstantiated_rejection" {
			t.Fatal("network denial did not execute", r)
		}
	} else {
		c, err := h.runtime.CompileModule(context.Background(), network)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close(context.Background())
		unsafeImport := false
		for _, f := range c.ImportedFunctions() {
			module, name, _ := f.Import()
			if module != "kaivo" && (module != "wasi_snapshot_preview1" || !allowedWASI[name]) {
				unsafeImport = true
			}
		}
		if !unsafeImport {
			t.Fatal("valid network reactor rejected for unexpected reason")
		}
	}

	bad := testManifest()
	bad.Type = "statement"
	bad.Capabilities = []abi.Operation{abi.FetchStatement}
	bad.Callback = nil
	b, _ := json.Marshal(bad)
	if _, e = h.Load(context.Background(), Package{ManifestJSON: b, Wasm: malicious}); e == nil {
		t.Fatal("statement accepted")
	}
	for _, mutate := range []func(*Manifest){func(m *Manifest) { m.Domains = []string{"*.example"} }, func(m *Manifest) { m.Version = "1.0.0-01" }, func(m *Manifest) { m.ABIVersion = 1 }, func(m *Manifest) { m.Secrets["bad-name"] = "shared" }, func(m *Manifest) { m.Build.SourceTreeSHA256 = "x" }, func(m *Manifest) { m.Capabilities = append(m.Capabilities, abi.QueryPayment) }} {
		m := testManifest()
		mutate(&m)
		if m.Validate() == nil {
			t.Fatal("invalid manifest accepted")
		}
	}
	p := testPackage(malicious)
	hash, _ := p.Hash()
	var object map[string]json.RawMessage
	_ = json.Unmarshal(p.ManifestJSON, &object)
	p.ManifestJSON, _ = json.MarshalIndent(object, "", "  ")
	hash2, _ := p.Hash()
	if hash != hash2 {
		t.Fatal("manifest not normalized")
	}
	p.Fixtures = map[string][]byte{"fixtures/test.json": []byte("test")}
	hash2, _ = p.Hash()
	if hash != hash2 {
		t.Fatal("fixture belongs in report, not package hash")
	}
}
func TestSecretNeverEntersGuestMemory(t *testing.T) {
	h, l := newTestHost(t, false)
	env := testEnv()
	secret := make([]byte, 32)
	rand.Read(secret)
	secret = []byte(hex.EncodeToString(secret))
	env.ResolveSecret = func(context.Context, string) ([]byte, error) { return secret, nil }
	s := &invocation{manifest: l.manifest, env: env, secrets: map[string][]byte{"shared": secret}, config: map[string]string{"mode": "test"}}
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), invocationKey{}, s), SandboxTimeout)
	defer cancel()
	m, e := h.runtime.InstantiateModule(ctx, l.compiled, wazero.NewModuleConfig().WithName("").WithStartFunctions("_initialize"))
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close(context.Background())
	call, _ := json.Marshal(abi.Call{Input: testInput("secret_probe"), Responses: []abi.Response{}})
	a, e := m.ExportedFunction("alloc").Call(ctx, uint64(len(call)))
	if e != nil {
		t.Fatal(e)
	}
	if !m.Memory().Write(uint32(a[0]), call) {
		t.Fatal("write")
	}
	if _, e = m.ExportedFunction("query_payment").Call(ctx, a[0], uint64(len(call))); e != nil {
		t.Fatal(e)
	}
	memory, _ := m.Memory().Read(0, m.Memory().Size())
	for _, v := range [][]byte{secret, []byte(hex.EncodeToString(secret)), []byte(base64.StdEncoding.EncodeToString(secret))} {
		if bytes.Contains(memory, v) {
			t.Fatal("host secret found in guest memory")
		}
	}
}
func TestPluginReplayDeterminism(t *testing.T) {
	for _, p := range pluginPackages {
		m, _, _ := p.Manifest()
		t.Run(m.Code, func(t *testing.T) {
			a, x, e := Replay(context.Background(), p)
			if e != nil {
				t.Fatalf("%s: %v\n%s", m.Code, e, a)
			}
			b, y, e := Replay(context.Background(), p)
			if e != nil || x != y || !bytes.Equal(a, b) {
				t.Fatal("nondeterministic replay", e)
			}
			var r Report
			_ = abi.Decode(a, &r)
			want := 30
			if m.Type == "verification" {
				want = 10
			}
			if len(r.Cases) != want {
				t.Fatal("missing scenarios", len(r.Cases))
			}
			for _, c := range r.Cases {
				if !c.Passed {
					t.Fatal(c.Path)
				}
			}
		})
	}
}
func TestPluginSignaturesAgainstPeerAlgorithms(t *testing.T) {
	keys, e := NewTestCredentials()
	if e != nil {
		t.Fatal(e)
	}
	for _, p := range pluginPackages {
		m, _, _ := p.Manifest()
		h, e := New(context.Background(), Options{PluginType: m.Type, TestOnlyAllowHTTP: true, TestOnlyAllowUncommitted: true})
		if e != nil {
			t.Fatal(e)
		}
		l, e := h.Load(context.Background(), p)
		if e != nil {
			t.Fatal(e)
		}
		for path, b := range p.Fixtures {
			if !strings.HasSuffix(path, "_success.json") {
				continue
			}
			var f Fixture
			if e = abi.Decode(b, &f); e != nil {
				t.Fatal(e)
			}
			transport := &fixtureTransport{exchanges: f.Exchanges}
			count := 0
			verified := roundTripFunc(func(r *http.Request) (*http.Response, error) {
				body, _ := io.ReadAll(r.Body)
				r.Body = io.NopCloser(bytes.NewReader(body))
				count++
				if strings.HasPrefix(m.Code, "sim_json_rsa") {
					requestKey := &keys.Platform.PublicKey
					if m.Type == "verification" {
						requestKey = &keys.Query.PublicKey
					}
					sig, e := base64.StdEncoding.DecodeString(r.Header.Get("X-Signature"))
					d := sha256.Sum256(body)
					if e != nil || rsa.VerifyPKCS1v15(requestKey, crypto.SHA256, d[:], sig) != nil {
						t.Fatal("RSA request differs from upstream algorithm")
					}
				} else {
					v, e := url.ParseQuery(string(body))
					if e != nil {
						t.Fatal(e)
					}
					canonical, e := canonicalFixtureForm(v)
					if e != nil {
						t.Fatal(e)
					}
					shared := keys.Shared
					if m.Type == "verification" {
						shared = keys.QueryShared
					}
					d := md5.Sum(append([]byte(canonical+"&key="), shared...))
					if v.Get("sign") != hex.EncodeToString(d[:]) {
						t.Fatal("MD5 request differs from upstream algorithm")
					}
				}
				return transport.RoundTrip(r)
			})
			env, e := keys.Services(f, verified)
			if e != nil {
				t.Fatal(e)
			}
			if e = keys.SignCallback(&f); e != nil {
				t.Fatal(e)
			}
			r := h.Execute(context.Background(), l, f.Operation, f.Input, env)
			if r.Category != Completed {
				t.Fatal(m.Code, path, r)
			}
			if f.Operation != abi.VerifyCallback && f.Operation != abi.RouteCallback && count != 1 {
				t.Fatal("request not verified")
			}
		}
		h.Close(context.Background())
	}
}
func BenchmarkFresh(b *testing.B) {
	for _, p := range pluginPackages {
		m, _, _ := p.Manifest()
		b.Run(m.Code, func(b *testing.B) {
			var fixture Fixture
			path := "fixtures/verify_callback_success.json"
			if m.Type == "verification" {
				path = "fixtures/query_payment_success.json"
			}
			_ = abi.Decode(p.Fixtures[path], &fixture)
			keys, e := NewTestCredentials()
			if e != nil {
				b.Fatal(e)
			}
			if e = keys.SignCallback(&fixture); e != nil {
				b.Fatal(e)
			}
			h, e := New(context.Background(), Options{PluginType: m.Type, TestOnlyAllowHTTP: true, TestOnlyAllowUncommitted: true})
			if e != nil {
				b.Fatal(e)
			}
			defer h.Close(context.Background())
			l, e := h.Load(context.Background(), p)
			if e != nil {
				b.Fatal(e)
			}
			env, e := keys.Services(fixture, nil)
			if e != nil {
				b.Fatal(e)
			}
			samples := make([]time.Duration, 0, b.N)
			var peak uint32
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				env.HTTP = &fixtureTransport{exchanges: fixture.Exchanges}
				started := time.Now()
				r := h.Execute(context.Background(), l, fixture.Operation, fixture.Input, env)
				samples = append(samples, time.Since(started))
				if r.Category != Completed {
					b.Fatal(r)
				}
				peak = max(peak, r.PeakMemoryBytes)
			}
			b.StopTimer()
			slices.Sort(samples)
			b.ReportMetric(float64(samples[len(samples)/2].Nanoseconds()), "p50-ns")
			b.ReportMetric(float64(samples[(len(samples)-1)*99/100].Nanoseconds()), "p99-ns")
			b.ReportMetric(float64(peak), "wasm-bytes")
		})
	}
}

func TestReplayAdmission(t *testing.T) {
	p := pluginPackages[0]
	files := map[string][]byte{}
	for path, b := range p.Fixtures {
		files[path] = b
	}
	p.Fixtures = files
	delete(p.Fixtures, "fixtures/query_payment_timeout.json")
	if _, _, e := Replay(context.Background(), p); e == nil {
		t.Fatal("missing negative fixture admitted")
	}
	original := pluginPackages[0].Fixtures["fixtures/query_payment_timeout.json"]
	var f Fixture
	_ = abi.Decode(original, &f)
	f.Expected.Category = Completed
	data, _ := json.Marshal(f)
	p.Fixtures["fixtures/query_payment_timeout.json"] = data
	if _, _, e := Replay(context.Background(), p); e == nil {
		t.Fatal("fabricated success expectation admitted")
	}
}
func TestFreshInstances(t *testing.T) {
	h, l := newTestHost(t, false)
	env := testEnv()
	s := &invocation{manifest: l.manifest, env: env, secrets: map[string][]byte{"shared": []byte(onlyTestSecret)}, config: map[string]string{"mode": "test"}}
	ctx := context.WithValue(context.Background(), operationKey{}, abi.QueryPayment)
	for range 2 {
		step, code := h.step(ctx, l, s, abi.Call{Input: testInput("state"), Responses: []abi.Response{}})
		if code != "" || step.Result == nil || step.Result.Code != "1" {
			t.Fatal("guest state survived", step, code)
		}
	}
}

func TestFixtureSecretHeader(t *testing.T) {
	request := abi.Request{Method: "POST", URL: "https://allowed.example/api", Headers: map[string][]string{"Authorization": {"Bearer {{secret:shared}}"}}, Body: []byte("test")}
	transport := &fixtureTransport{exchanges: []Exchange{{Request: request, Response: &abi.Response{Status: 200, Headers: map[string][]string{}, Body: []byte("ok")}}}, resolve: func(n string) ([]byte, error) {
		if n != "shared" {
			t.Fatal(n)
		}
		return []byte(onlyTestSecret), nil
	}}
	req, _ := http.NewRequest("POST", request.URL, strings.NewReader("test"))
	req.Header.Set("Authorization", "Bearer "+onlyTestSecret)
	res, e := transport.RoundTrip(req)
	if e != nil || transport.mismatch {
		t.Fatal("fixture secret placeholder mismatch", e)
	}
	res.Body.Close()
}
func TestReplayEnvironmentOverridesLiveServices(t *testing.T) {
	p := pluginPackages[1]
	keys, e := NewTestCredentials()
	if e != nil {
		t.Fatal(e)
	}
	a, x, e := Replay(context.Background(), p)
	if e != nil {
		t.Fatal(e)
	}
	b, y, e := ReplayWithEnvironment(context.Background(), p, func(_ context.Context, _ Manifest, f Fixture) (Environment, func(*Fixture) error, error) {
		env, e := keys.Services(f, nil)
		env.ConfigValues = nil
		env.Clock = func() time.Time { panic("live clock used") }
		env.HTTP = roundTripFunc(func(*http.Request) (*http.Response, error) { panic("live network used") })
		return env, keys.SignCallback, e
	})
	if e != nil || x != y || !bytes.Equal(a, b) {
		t.Fatal("replay used live environment", e)
	}
}

func TestStructuredLog(t *testing.T) {
	h, l := newTestHost(t, false)
	env := testEnv()
	var logs []abi.LogRequest
	env.Logger = func(_ context.Context, v abi.LogRequest) { logs = append(logs, v) }
	r := h.Execute(context.Background(), l, abi.QueryPayment, testInput("log"), env)
	if r.ErrorCode != "plugin_error" || len(logs) != 1 || logs[0].Level != "warn" || logs[0].Fields["source"] != "test" {
		t.Fatal(r, logs)
	}
}

func TestProductionHostRejectsUncommittedPackagesAndBoundsTimeout(t *testing.T) {
	ctx := context.Background()
	w := malicious // the shared test module; its manifest declares source_commit=uncommitted
	h, e := New(ctx, Options{PluginType: "payment"})
	if e != nil {
		t.Fatal(e)
	}
	defer h.Close(ctx)
	if h.options.RequestTimeout != DefaultRequestTimeout {
		t.Fatal("default request timeout", h.options.RequestTimeout)
	}
	if _, e = h.Load(ctx, testPackage(w)); e == nil {
		t.Fatal("production host loaded an uncommitted package")
	}
	m := testManifest()
	m.Build.SourceCommit = strings.Repeat("a", 40)
	b, _ := json.Marshal(m)
	if _, e = h.Load(ctx, Package{ManifestJSON: b, Wasm: w}); e != nil {
		t.Fatal("committed package rejected", e)
	}
	for _, d := range []time.Duration{-time.Second, MaxRequestTimeout + time.Second} {
		if _, e := New(ctx, Options{PluginType: "payment", RequestTimeout: d}); e == nil {
			t.Fatal("request timeout accepted", d)
		}
	}
}
