//go:build wasip1 && wasm

package sdk

import (
	"encoding/json"
	"errors"
	"github.com/Kaivodev/upstream-plugins/abi"
	"unsafe"
)

//go:wasmimport kaivo config
func config(uint32, uint32, uint32, uint32) uint32

//go:wasmimport kaivo sign
func sign(uint32, uint32, uint32, uint32) uint32

//go:wasmimport kaivo verify
func verify(uint32, uint32, uint32, uint32) uint32

//go:wasmimport kaivo equal
func equal(uint32, uint32, uint32, uint32) uint32

//go:wasmimport kaivo log
func logMessage(uint32, uint32, uint32, uint32) uint32
func ptr(b []byte) uint32 { return uint32(uintptr(unsafe.Pointer(unsafe.SliceData(b)))) }
func hostCall(name string, b []byte) ([]byte, error) {
	out := make([]byte, 64<<10)
	f := map[string]func(uint32, uint32, uint32, uint32) uint32{"config": config, "sign": sign, "verify": verify, "equal": equal, "log": logMessage}[name]
	n := f(ptr(b), uint32(len(b)), ptr(out), uint32(len(out)))
	if n == 0 || n > uint32(len(out)) {
		return nil, errors.New("host call failed")
	}
	return out[:n], nil
}

var allocations = map[uint32][]byte{}
var output []byte

//go:wasmexport alloc
func alloc(n uint32) uint32 {
	if n == 0 || n > abi.MaxJSON {
		return 0
	}
	b := make([]byte, n)
	p := ptr(b)
	allocations[p] = b
	return p
}

//go:wasmexport dealloc
func dealloc(p, n uint32) {
	if b, ok := allocations[p]; ok && len(b) == int(n) {
		delete(allocations, p)
	}
}

//go:wasmexport abi_version
func version() uint32 { return abi.Version }
func dispatch(op abi.Operation, p, n uint32) uint64 {
	b, ok := allocations[p]
	if !ok || uint32(len(b)) != n {
		panic("invalid input allocation")
	}
	var c Call
	var step Step
	if err := abi.Decode(b, &c); err != nil {
		step = Fail("invalid_call")
	} else if h := handlers[op]; h != nil {
		step = h(c)
	} else {
		step = Fail("unsupported_operation")
	}
	output, _ = json.Marshal(step)
	return uint64(ptr(output))<<32 | uint64(len(output))
}

//go:wasmexport create_payment
func create(p, n uint32) uint64 { return dispatch(abi.CreatePayment, p, n) }

//go:wasmexport query_payment
func query(p, n uint32) uint64 { return dispatch(abi.QueryPayment, p, n) }

//go:wasmexport close_payment
func closePayment(p, n uint32) uint64 { return dispatch(abi.ClosePayment, p, n) }

//go:wasmexport refund
func refund(p, n uint32) uint64 { return dispatch(abi.Refund, p, n) }

//go:wasmexport query_refund
func queryRefund(p, n uint32) uint64 { return dispatch(abi.QueryRefund, p, n) }

//go:wasmexport verify_callback
func callback(p, n uint32) uint64 { return dispatch(abi.VerifyCallback, p, n) }

//go:wasmexport route_callback
func routeCallback(p, n uint32) uint64 { return dispatch(abi.RouteCallback, p, n) }
