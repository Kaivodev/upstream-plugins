// Package sdk lets plugins use ordinary Go handlers without linear-memory code.
package sdk

import (
	"encoding/json"
	"github.com/Kaivodev/upstream-plugins/abi"
)

type Call = abi.Call
type Step = abi.Step
type Handler func(Call) Step

var handlers = map[abi.Operation]Handler{}

func Register(op abi.Operation, h Handler) {
	if !op.Payment() || h == nil || handlers[op] != nil {
		panic("invalid handler registration")
	}
	handlers[op] = h
}
func Input[T any](c Call) (T, error) { var v T; err := abi.Decode(c.Input, &v); return v, err }
func Request(method, url string, headers map[string][]string, body []byte) Step {
	return Step{Request: &abi.Request{Method: method, URL: url, Headers: headers, Body: body}}
}
func Result(r abi.Result) Step    { return Step{Result: &r} }
func Reject(code string) Step     { return Result(abi.Result{Outcome: "rejected", Code: code}) }
func Fail(code string) Step       { return Result(abi.Result{Outcome: "error", Code: code}) }
func Bytes(data []byte) abi.Part  { return abi.Part{Data: data} }
func Secret(name string) abi.Part { return abi.Part{Secret: name} }
func invoke(name string, req any, dst any) error {
	b, err := json.Marshal(req)
	if err != nil {
		return err
	}
	r, err := hostCall(name, b)
	if err != nil {
		return err
	}
	var reply abi.HostReply
	if err = abi.Decode(r, &reply); err != nil {
		return err
	}
	return abi.Decode(reply.Value, dst)
}
func Config(name string) (string, error) {
	var v string
	err := invoke("config", abi.ConfigRequest{Name: name}, &v)
	return v, err
}
func Sign(alg, key string, parts ...abi.Part) (string, error) {
	var v string
	err := invoke("sign", abi.SignRequest{Algorithm: alg, Key: key, Parts: parts}, &v)
	return v, err
}
func Verify(alg, key, signature string, parts ...abi.Part) (bool, error) {
	var v bool
	err := invoke("verify", abi.VerifyRequest{Algorithm: alg, Key: key, Signature: signature, Parts: parts}, &v)
	return v, err
}
func Equal(a, b string) (bool, error) {
	var v bool
	err := invoke("equal", abi.EqualRequest{A: a, B: b}, &v)
	return v, err
}
func Log(level, message string, fields map[string]string) error {
	var v bool
	return invoke("log", abi.LogRequest{Level: level, Message: message, Fields: fields}, &v)
}
