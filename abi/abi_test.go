package abi

import (
	"encoding/json"
	"testing"
)

func TestStrictJSON(t *testing.T) {
	for _, s := range []string{`{"amount":"1","currency":"CNY","x":1}`, `{"amount":"1","amount":"2","currency":"CNY"}`, `{"Amount":"1","currency":"CNY"}`, `{"amount":"1","currency":"CNY"} {}`, `null`, "{\"amount\":\"\xff\"}"} {
		var v Money
		if Decode([]byte(s), &v) == nil {
			t.Fatalf("accepted %q", s)
		}
	}
	var v Call
	if Decode([]byte(`{"input":{"x":1,"x":2},"responses":[]}`), &v) == nil {
		t.Fatal("nested duplicate accepted")
	}
}
func TestMoney(t *testing.T) {
	for _, s := range []string{"1", "9223372036854775807", "123456789012345678901234567890"} {
		m := Money{Amount: s, Currency: "CNY"}
		n, e := ParseAmount(m)
		if e != nil || n.String() != s {
			t.Fatal(s, e)
		}
	}
	for _, s := range []string{"-1", "+1", "1.0", "1e2", "01", "NaN", ""} {
		if _, e := ParseAmount(Money{Amount: s, Currency: "CNY"}); e == nil {
			t.Fatal(s)
		}
	}
	if EqualMoney(Money{"1", "CNY"}, Money{"1", "USD"}) {
		t.Fatal("currency ignored")
	}
}
func TestCanonical(t *testing.T) {
	a, e := Canonical([]byte(`{"b":9223372036854775807,"a":1}`))
	if e != nil || string(a) != `{"a":1,"b":9223372036854775807}` {
		t.Fatal(string(a), e)
	}
	var v map[string]json.RawMessage
	if Decode(a, &v) != nil {
		t.Fatal("canonical invalid")
	}
}
