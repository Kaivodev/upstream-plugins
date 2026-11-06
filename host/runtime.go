package host

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Kaivodev/upstream-plugins/abi"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/tetratelabs/wazero/sys"
)

const MaxHostCalls = 4096 // Includes WASI runtime initialization and all kaivo calls.
const MaxLogs = 8192
const MaxLogMessages = 32
const SandboxTimeout = 200 * time.Millisecond

type Options struct {
	PluginType        string
	TestOnlyAllowHTTP bool
	// TestOnlyAllowUncommitted lets local builds (source_commit=uncommitted)
	// load. Production hosts must leave it false: approved packages are bound
	// to a source commit that approvers can rebuild byte for byte.
	TestOnlyAllowUncommitted bool
	// RequestTimeout bounds each upstream HTTP exchange; zero means
	// DefaultRequestTimeout and it may not exceed MaxRequestTimeout.
	RequestTimeout time.Duration
}
type Host struct {
	runtime wazero.Runtime
	options Options
	mu      sync.Mutex
	cache   map[string]*Loaded
}
type Loaded struct {
	manifest Manifest
	compiled wazero.CompiledModule
	hash     string
}

func (l *Loaded) Hash() string { return l.hash }
func New(ctx context.Context, o Options) (*Host, error) {
	if o.PluginType != "payment" && o.PluginType != "statement" {
		return nil, errors.New("explicit plugin type required")
	}
	if o.RequestTimeout == 0 {
		o.RequestTimeout = DefaultRequestTimeout
	}
	if o.RequestTimeout < 0 || o.RequestTimeout > MaxRequestTimeout {
		return nil, errors.New("request timeout out of range")
	}
	r := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithMemoryLimitPages(512).WithCloseOnContextDone(true))
	h := &Host{runtime: r, options: o, cache: map[string]*Loaded{}}
	listener := experimental.FunctionListenerFactoryFunc(func(api.FunctionDefinition) experimental.FunctionListener {
		return experimental.FunctionListenerFunc(func(ctx context.Context, _ api.Module, def api.FunctionDefinition, params []uint64, _ experimental.StackIterator) {
			s, _ := ctx.Value(invocationKey{}).(*invocation)
			if s != nil {
				s.calls++
				// WASI parameters are i32. wazero does not guarantee zeroed upper
				// bits in the uint64 slots (they are not on amd64), so decode them.
				if slices.Contains(def.ExportNames(), "random_get") && len(params) == 2 {
					n := uint64(api.DecodeU32(params[1]))
					if n > 64<<10 {
						s.fail("random_limit")
					}
					s.randomBytes += n
					if s.randomBytes > 256<<10 {
						s.fail("random_limit")
					}
				}
				if slices.Contains(def.ExportNames(), "fd_write") && len(params) == 4 && api.DecodeU32(params[2]) > 64 {
					s.fail("log_limit")
				}
				if s.calls > MaxHostCalls {
					s.fail("host_call_limit")
				}
			}
		})
	})
	c := experimental.WithFunctionListenerFactory(ctx, listener)
	if _, err := wasi_snapshot_preview1.Instantiate(c, r); err != nil {
		r.Close(ctx)
		return nil, err
	}
	b := r.NewHostModuleBuilder("kaivo")
	for _, name := range []string{"config", "sign", "verify", "equal", "log"} {
		name := name
		b.NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, p, n, out, cap uint32) uint32 {
			return h.hostFunction(ctx, m, name, p, n, out, cap)
		}).Export(name)
	}
	if _, err := b.Instantiate(c); err != nil {
		r.Close(ctx)
		return nil, err
	}
	return h, nil
}
func (h *Host) Close(ctx context.Context) error { return h.runtime.Close(ctx) }

var allowedWASI = map[string]bool{
	"args_get": true, "args_sizes_get": true, "environ_get": true, "environ_sizes_get": true,
	"clock_time_get": true, "random_get": true, "sched_yield": true, "poll_oneoff": true, "proc_exit": true,
	"fd_write": true, "fd_read": true, "fd_close": true, "fd_seek": true, "fd_fdstat_get": true,
	"fd_fdstat_set_flags": true, "path_filestat_get": true, "fd_prestat_get": true, "fd_prestat_dir_name": true, "path_open": true, "fd_filestat_get": true,
}

func (h *Host) Load(ctx context.Context, p Package) (*Loaded, error) {
	m, _, err := p.Manifest()
	if err != nil {
		return nil, err
	}
	if m.Type != h.options.PluginType {
		return nil, errors.New("plugin type mismatch")
	}
	if m.Type == "statement" {
		return nil, errors.New("statement plugins reserved for M4")
	}
	if !m.Committed() && !h.options.TestOnlyAllowUncommitted {
		return nil, errors.New("package must be built from a committed source")
	}
	hash, err := p.Hash()
	if err != nil {
		return nil, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if l := h.cache[hash]; l != nil {
		return l, nil
	}
	if err := checkImportKinds(p.Wasm); err != nil {
		return nil, err
	}
	c, err := h.runtime.CompileModule(ctx, p.Wasm)
	if err != nil {
		return nil, errors.New("invalid wasm module")
	}
	fail := func() (*Loaded, error) { c.Close(ctx); return nil, errors.New("invalid module imports or exports") }
	if len(c.ImportedMemories()) != 0 {
		return fail()
	}
	for _, f := range c.ImportedFunctions() {
		module, name, _ := f.Import()
		if (module != "kaivo" && module != "wasi_snapshot_preview1") || (module == "wasi_snapshot_preview1" && !allowedWASI[name]) {
			return fail()
		}
		provider := h.runtime.Module(module)
		if provider == nil {
			return fail()
		}
		def := provider.ExportedFunctionDefinitions()[name]
		if def == nil || !slices.Equal(def.ParamTypes(), f.ParamTypes()) || !slices.Equal(def.ResultTypes(), f.ResultTypes()) {
			return fail()
		}
	}
	exports := c.ExportedFunctions()
	check := func(name string, p, r []api.ValueType) bool {
		d := exports[name]
		return d != nil && slices.Equal(d.ParamTypes(), p) && slices.Equal(d.ResultTypes(), r)
	}
	if len(c.ExportedMemories()) != 1 || c.ExportedMemories()["memory"] == nil || !check("_initialize", nil, nil) || !check("abi_version", nil, []api.ValueType{api.ValueTypeI32}) || !check("alloc", []api.ValueType{api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}) || !check("dealloc", []api.ValueType{api.ValueTypeI32, api.ValueTypeI32}, nil) {
		return fail()
	}
	for _, op := range m.Capabilities {
		if !check(string(op), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI64}) {
			return fail()
		}
	}
	l := &Loaded{manifest: m, compiled: c, hash: hash}
	h.cache[hash] = l
	return l, nil
}

type invocationKey struct{}
type invocation struct {
	manifest    Manifest
	env         Environment
	secrets     map[string][]byte
	config      map[string]string
	calls       int
	kaivoCalls  int
	randomBytes uint64
	fault       string
	logs        bytes.Buffer
	stdout      bytes.Buffer
	messages    []abi.LogRequest
	logEvents   int
	monotonic   int64
	peak        uint32
	alerted     bool
}

func (s *invocation) fail(code string) { s.fault = code; panic("sandbox host rejected call") }
func (s *invocation) leak(b []byte) bool {
	for _, v := range s.secrets {
		if len(v) > 0 && (bytes.Contains(b, v) || bytes.Contains(b, []byte(hex.EncodeToString(v))) || bytes.Contains(b, []byte(strings.ToUpper(hex.EncodeToString(v))))) || len(v) > 0 && (bytes.Contains(b, []byte(base64.StdEncoding.EncodeToString(v))) || bytes.Contains(b, []byte(base64.RawStdEncoding.EncodeToString(v))) || bytes.Contains(b, []byte(base64.URLEncoding.EncodeToString(v))) || bytes.Contains(b, []byte(base64.RawURLEncoding.EncodeToString(v)))) {
			return true
		}
	}
	return false
}
func (s *invocation) jsonLeak(b []byte) bool {
	if s.leak(b) {
		return true
	}
	var v any
	if json.Unmarshal(b, &v) != nil {
		return false
	}
	var visit func(any) bool
	visit = func(v any) bool {
		switch t := v.(type) {
		case string:
			return s.leak([]byte(t))
		case []any:
			for _, x := range t {
				if visit(x) {
					return true
				}
			}
		case map[string]any:
			for k, x := range t {
				if s.leak([]byte(k)) || visit(x) {
					return true
				}
			}
		}
		return false
	}
	return visit(v)
}
func (s *invocation) alert(ctx context.Context) {
	if !s.alerted {
		s.alerted = true
		s.env.Alert(context.WithoutCancel(ctx), "secret_leak")
	}
}
func (h *Host) hostFunction(ctx context.Context, m api.Module, name string, p, n, out, cap uint32) uint32 {
	s, ok := ctx.Value(invocationKey{}).(*invocation)
	if !ok {
		panic("missing invocation")
	}
	s.kaivoCalls++
	if s.kaivoCalls > 128 {
		s.fail("host_call_limit")
	}
	if n > abi.MaxJSON || cap > abi.MaxJSON {
		s.fail("host_io_limit")
	}
	raw, ok := m.Memory().Read(p, n)
	if !ok {
		s.fail("invalid_memory")
	}
	decode := func(v any) {
		if abi.Decode(raw, v) != nil {
			s.fail("host_json")
		}
	}
	var v any
	var err error
	switch name {
	case "config":
		var r abi.ConfigRequest
		decode(&r)
		value, exists := s.config[r.Name]
		if !exists {
			s.fail("undeclared_config")
		}
		v = value
	case "sign":
		var r abi.SignRequest
		decode(&r)
		v, err = s.sign(r)
	case "verify":
		var r abi.VerifyRequest
		decode(&r)
		if r.Algorithm != "rsa-sha256" || !slices.Contains(s.manifest.PublicKeys, r.Key) {
			s.fail("undeclared_public_key")
		}
		var k *rsa.PublicKey
		k, err = s.env.PublicKey(ctx, r.Key)
		if err == nil && k != nil && k.N.BitLen() >= 2048 {
			var b, sig []byte
			b, err = s.parts(r.Parts)
			if err == nil {
				sig, err = base64.StdEncoding.DecodeString(r.Signature)
				if err == nil {
					d := sha256.Sum256(b)
					v = rsa.VerifyPKCS1v15(k, crypto.SHA256, d[:], sig) == nil
				} else {
					err = nil
					v = false
				}
			}
		} else {
			err = errors.New("key unavailable")
		}
	case "equal":
		var r abi.EqualRequest
		decode(&r)
		v = subtle.ConstantTimeCompare([]byte(r.A), []byte(r.B)) == 1
	case "log":
		var r abi.LogRequest
		decode(&r)
		if r.Level != "debug" && r.Level != "info" && r.Level != "warn" && r.Level != "error" {
			s.fail("log_level")
		}
		b, _ := json.Marshal(r)
		s.appendLog(b)
		if len(s.messages) >= MaxLogMessages {
			s.fail("log_rate_limit")
		}
		s.messages = append(s.messages, r)
		v = true
	}
	if err != nil {
		s.fail("host_service")
	}
	b, _ := json.Marshal(v)
	reply, _ := json.Marshal(abi.HostReply{Value: b})
	if s.jsonLeak(reply) {
		s.fail("secret_leak")
	}
	if uint32(len(reply)) > cap || !m.Memory().Write(out, reply) {
		s.fail("host_io_limit")
	}
	return uint32(len(reply))
}
func (s *invocation) appendLog(b []byte) {
	s.logEvents++
	if s.logEvents > MaxLogMessages {
		s.fail("log_rate_limit")
	}
	if s.logs.Len()+len(b) > MaxLogs {
		s.fail("log_limit")
	}
	s.logs.Write(b)
	if s.leak(s.logs.Bytes()) || s.jsonLeak(b) {
		s.fail("secret_leak")
	}
}
func (s *invocation) Write(b []byte) (int, error) {
	s.appendLog(b)
	s.stdout.Write(b)
	if s.leak(s.stdout.Bytes()) {
		s.fail("secret_leak")
	}
	return len(b), nil
}
func (h *Host) step(ctx context.Context, l *Loaded, s *invocation, call abi.Call) (abi.Step, string) {
	var step abi.Step
	b, err := json.Marshal(call)
	if err != nil || len(b) > abi.MaxJSON {
		return step, "input_limit"
	}
	// Each step (fresh instance plus one call) gets its own budget, so at most
	// MaxSteps*SandboxTimeout of guest time per operation. A shared budget let
	// load on early steps time out a later step after a request was sent.
	c, cancel := context.WithTimeout(context.WithValue(ctx, invocationKey{}, s), SandboxTimeout)
	defer cancel()
	cfg := wazero.NewModuleConfig().WithName("").WithStartFunctions("_initialize").WithStdout(s).WithStderr(s).
		WithWalltime(func() (int64, int32) { n := s.env.Now(); return n.Unix(), int32(n.Nanosecond()) }, 1).
		WithNanotime(func() int64 { s.monotonic++; return s.monotonic }, 1).WithRandSource(s.env.Random())
	m, err := h.runtime.InstantiateModule(c, l.compiled, cfg)
	if m != nil {
		defer m.Close(context.Background())
		defer func() {
			if m.Memory().Size() > s.peak {
				s.peak = m.Memory().Size()
			}
		}()
	}
	classify := func(err error) string {
		if strings.Contains(s.logs.String(), "out of memory") || strings.Contains(err.Error(), "out of bounds memory") {
			return "memory_limit"
		}
		if s.fault != "" {
			return s.fault
		}
		if errors.Is(err, context.DeadlineExceeded) || c.Err() == context.DeadlineExceeded {
			return "sandbox_timeout"
		}
		if errors.Is(err, context.Canceled) {
			return "cancelled"
		}

		var exit *sys.ExitError
		if errors.As(err, &exit) {
			return "proc_exit"
		}
		return "sandbox_trap"
	}
	if err != nil {
		return step, classify(err)
	}
	version, err := m.ExportedFunction("abi_version").Call(c)
	if err != nil {
		return step, classify(err)
	}
	if version[0] != abi.Version {
		return step, "abi_version"
	}
	alloc, err := m.ExportedFunction("alloc").Call(c, uint64(len(b)))
	if err != nil {
		return step, classify(err)
	}
	p := uint32(alloc[0])
	if p == 0 || !m.Memory().Write(p, b) {
		return step, "invalid_memory"
	}
	op := ctx.Value(operationKey{}).(abi.Operation)
	res, err := m.ExportedFunction(string(op)).Call(c, uint64(p), uint64(len(b)))
	if err != nil {
		return step, classify(err)
	}
	ptr, n := uint32(res[0]>>32), uint32(res[0])
	if n == 0 || n > abi.MaxJSON {
		return step, "output_limit"
	}
	out, ok := m.Memory().Read(ptr, n)
	if !ok {
		return step, "invalid_memory"
	}
	out = bytes.Clone(out)
	if s.jsonLeak(out) {
		return step, "secret_leak"
	}
	if err := abi.Decode(out, &step); err != nil {
		return step, "output_json"
	}
	if (step.Request == nil) == (step.Result == nil) {
		return step, "step_union"
	}
	if _, err := m.ExportedFunction("dealloc").Call(c, uint64(p), uint64(len(b))); err != nil {
		return step, classify(err)
	}
	return step, ""
}

type operationKey struct{}

// readULEB/checkImportKinds additionally rejects non-function imports, which
// CompiledModule's public import introspection does not enumerate.
func readULEB(r *bytes.Reader) (uint32, error) {
	var n uint32
	for i := 0; i < 5; i++ {
		b, e := r.ReadByte()
		if e != nil {
			return 0, e
		}
		if i == 4 && b > 15 {
			return 0, errors.New("LEB overflow")
		}
		n |= uint32(b&127) << uint(7*i)
		if b < 128 {
			return n, nil
		}
	}
	return 0, errors.New("invalid LEB")
}
func checkImportKinds(w []byte) error {
	if len(w) < 8 {
		return errors.New("invalid wasm")
	}
	r := bytes.NewReader(w[8:])
	for r.Len() > 0 {
		id, e := r.ReadByte()
		if e != nil {
			return e
		}
		n, e := readULEB(r)
		if e != nil || uint64(n) > uint64(r.Len()) {
			return errors.New("invalid section")
		}
		b := make([]byte, n)
		io.ReadFull(r, b)
		if id != 2 {
			continue
		}
		s := bytes.NewReader(b)
		count, e := readULEB(s)
		if e != nil {
			return e
		}
		for range count {
			for range 2 {
				size, e := readULEB(s)
				if e != nil || uint64(size) > uint64(s.Len()) {
					return errors.New("invalid import")
				}
				s.Seek(int64(size), io.SeekCurrent)
			}
			kind, e := s.ReadByte()
			if e != nil || kind != 0 {
				return errors.New("non-function import forbidden")
			}
			if _, e := readULEB(s); e != nil {
				return e
			}
		}
	}
	return nil
}
