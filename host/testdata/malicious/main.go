// Test-only adversarial reactor. testSecret is injected at TEST BUILD TIME from
// crypto/rand. It deliberately knows a test secret to exercise leak detection.
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/Kaivodev/upstream-plugins/abi"
	"os"
	"strconv"
	"strings"
	"time"
	"unsafe"
)

var testSecret string
var forceV1 string
var stateCounter int
var retained []byte
var allocations = map[uint32][]byte{}
var output []byte

//go:wasmimport kaivo config
func config(uint32, uint32, uint32, uint32) uint32

//go:wasmimport kaivo sign
func sign(uint32, uint32, uint32, uint32) uint32

//go:wasmimport kaivo verify
func verify(uint32, uint32, uint32, uint32) uint32

//go:wasmimport kaivo log
func logMessage(uint32, uint32, uint32, uint32) uint32
func pointer(b []byte) uint32 { return uint32(uintptr(unsafe.Pointer(unsafe.SliceData(b)))) }

//go:wasmexport alloc
func alloc(n uint32) uint32 { b := make([]byte, n); p := pointer(b); allocations[p] = b; return p }

//go:wasmexport dealloc
func dealloc(p, n uint32) { delete(allocations, p) }

//go:wasmexport abi_version
func version() uint32 {
	if forceV1 == "yes" {
		return 1
	}
	return abi.Version
}
func packed(b []byte) uint64 { output = b; return uint64(pointer(b))<<32 | uint64(len(b)) }
func invoke(f func(uint32, uint32, uint32, uint32) uint32, v any) []byte {
	b, _ := json.Marshal(v)
	out := make([]byte, 64<<10)
	n := f(pointer(b), uint32(len(b)), pointer(out), uint32(len(out)))
	return out[:n]
}

//go:wasmexport query_payment
func query(p, n uint32) uint64 {
	var c abi.Call
	_ = json.Unmarshal(allocations[p], &c)
	var in abi.PaymentInput
	_ = json.Unmarshal(c.Input, &in)
	mode := in.OrderID
	req := &abi.Request{Method: "POST", URL: "https://allowed.example/api", Headers: map[string][]string{}, Body: []byte("test")}
	result := &abi.Result{Outcome: "error", Code: "deliberate"}
	if strings.HasPrefix(mode, "expiry_") && (len(c.Responses) > 0 || mode == "expiry_before") {
		expiry := time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
		p := &abi.PaymentOutput{OrderID: mode, UpstreamID: "test", Money: in.Money, Status: "pending", URL: "https://allowed.example/pay", ExpiresAt: expiry}
		switch mode {
		case "expiry_past", "expiry_before":
			p.ExpiresAt = time.Now().UTC().Add(-time.Nanosecond).Format(time.RFC3339Nano)
		case "expiry_now":
			p.ExpiresAt = time.Now().UTC().Format(time.RFC3339Nano)
		case "expiry_day":
			p.ExpiresAt = time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339Nano)
		case "expiry_over":
			p.ExpiresAt = time.Now().UTC().Add(24*time.Hour + time.Nanosecond).Format(time.RFC3339Nano)
		case "expiry_status":
			p.Status = "paid"
		case "expiry_no_instruction":
			p.URL = ""
		case "expiry_offset":
			p.ExpiresAt = "2026-11-06T01:00:00+00:00"
		case "expiry_bad":
			p.ExpiresAt = "tomorrow"
		case "expiry_absent":
			p.ExpiresAt = ""
		}
		b, _ := json.Marshal(abi.Step{Result: &abi.Result{Outcome: "completed", Payment: p}})
		return packed(b)
	}

	switch mode {
	case "state":
		stateCounter++
		result.Code = strconv.Itoa(stateCounter)
	case "wasi_calls":
		for range 10000 {
			_ = time.Now()
		}
	case "loop":
		for {
		}
	case "random_limit":
		_, _ = rand.Read(make([]byte, 1<<20))
	case "memory":
		retained = make([]byte, 64<<20)
		retained[len(retained)-1] = 1
	case "file_env":
		_, err := os.ReadFile("/etc/passwd")
		if err == nil || os.Getenv("HOME") != "" || len(os.Environ()) != 0 || len(os.Args) != 0 {
			panic("sandbox ambient access")
		}
		result = &abi.Result{Outcome: "rejected", Code: "sandbox_denied"}
	case "exit":
		os.Exit(0)
	case "huge":
		return packed(bytes.Repeat([]byte("x"), abi.MaxJSON+1))
	case "unknown":
		return packed([]byte(`{"result":{"outcome":"rejected","alien":true}}`))
	case "duplicate":
		return packed([]byte(`{"result":{"outcome":"rejected","outcome":"completed"}}`))
	case "secret_plain", "secret_hex", "secret_base64", "secret_escaped":
		secret := testSecret
		if mode == "secret_hex" {
			secret = hex.EncodeToString([]byte(secret))
		}
		if mode == "secret_base64" {
			secret = base64.StdEncoding.EncodeToString([]byte(secret))
		}
		result.Code = secret
		if mode == "secret_escaped" {
			var b strings.Builder
			b.WriteString(`{"result":{"outcome":"error","code":"`)
			for _, c := range secret {
				fmt.Fprintf(&b, "\\u%04x", c)
			}
			b.WriteString(`"}}`)
			return packed([]byte(b.String()))
		}
	case "log_secret":
		for _, v := range []string{testSecret[:len(testSecret)/2], testSecret[len(testSecret)/2:]} {
			fmt.Print(v)
		}
	case "log":
		invoke(logMessage, abi.LogRequest{Level: "warn", Message: "test log", Fields: map[string]string{"source": "test"}})
	case "log_rate":
		for range 40 {
			invoke(logMessage, abi.LogRequest{Level: "info", Message: "test"})
		}
	case "host_calls":
		for range 5000 {
			invoke(config, abi.ConfigRequest{Name: "mode"})
		}
	case "secret_probe":
		invoke(sign, abi.SignRequest{Algorithm: "md5", Parts: []abi.Part{{Data: []byte("test&key=")}, {Secret: "shared"}}})
	case "before_reject":
		result = &abi.Result{Outcome: "rejected", Code: "no_response"}
	case "after_error", "after_loop":
		if len(c.Responses) > 0 {
			if mode == "after_loop" {
				for {
				}
			}
			break
		}
		fallthrough
	default:
		switch mode {
		case "request_http":
			req.URL = "http://allowed.example/api"
		case "request_foreign":
			req.URL = "https://foreign.example/api"
		case "request_header":
			req.Headers["Authorization"] = []string{"Bearer {{secret:shared}}"}
		case "bad_identity":
			if len(c.Responses) > 0 {
				result = &abi.Result{Outcome: "completed", Payment: &abi.PaymentOutput{OrderID: "other", UpstreamID: "test", Money: in.Money, Status: "paid"}}
				break
			}
		}
		if mode != "bad_identity" || len(c.Responses) == 0 {
			b, _ := json.Marshal(abi.Step{Request: req})
			return packed(b)
		}
	}
	b, _ := json.Marshal(abi.Step{Result: result})
	return packed(b)
}

//go:wasmexport verify_callback
func callback(p, n uint32) uint64 { return query(p, n) }
func main()                       {}

//go:wasmexport create_payment
func create(p, n uint32) uint64 { return query(p, n) }

//go:wasmexport route_callback
func route(p, n uint32) uint64 {
	var c abi.Call
	_ = json.Unmarshal(allocations[p], &c)
	var in abi.RouteCallbackInput
	_ = json.Unmarshal(c.Input, &in)
	switch string(in.Body) {
	case "http":
		b, _ := json.Marshal(abi.Step{Request: &abi.Request{Method: "POST", URL: "https://allowed.example/api"}})
		return packed(b)
	case "sign":
		invoke(sign, abi.SignRequest{Algorithm: "sha256", Parts: []abi.Part{{Data: []byte("test")}}})
	case "verify":
		invoke(verify, abi.VerifyRequest{Algorithm: "rsa-sha256", Key: "upstream_public"})
	case "secret":
		invoke(config, abi.ConfigRequest{Name: "shared"})
	case "public":
		invoke(config, abi.ConfigRequest{Name: "upstream_public"})
	case "allowed":
		invoke(config, abi.ConfigRequest{Name: "mode"})
		invoke(logMessage, abi.LogRequest{Level: "info", Message: "untrusted callback routed"})
	}
	b, _ := json.Marshal(abi.Step{Result: &abi.Result{Outcome: "completed", Route: &abi.RouteCallbackOutput{OrderID: "test_order"}}})
	return packed(b)
}
