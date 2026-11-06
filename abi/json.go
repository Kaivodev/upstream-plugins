package abi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Decode rejects duplicate keys at every depth, unknown fields, null roots,
// invalid UTF-8, excessive nesting, and trailing JSON. No float conversion occurs.
func Decode(data []byte, dst any) error {
	if len(data) > MaxJSON || !utf8.Valid(data) {
		return errors.New("invalid JSON size or UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := scan(d, 0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return errors.New("null JSON")
	}
	if err := exactFields(data, reflect.TypeOf(dst)); err != nil {
		return err
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	d.UseNumber()
	return d.Decode(dst)
}
func scan(d *json.Decoder, depth int) error {
	if depth > 64 {
		return errors.New("JSON nesting limit")
	}
	t, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			k, err := d.Token()
			if err != nil {
				return err
			}
			s, ok := k.(string)
			if !ok || seen[s] {
				return errors.New("duplicate JSON key")
			}
			seen[s] = true
			if err := scan(d, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := scan(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("invalid JSON delimiter")
	}
	_, err = d.Token()
	return err
}

// Canonical normalizes JSON using encoding/json's sorted object keys and exact numbers.
func Canonical(data []byte) ([]byte, error) {
	var v any
	if err := Decode(data, &v); err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

var amountPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,77})$`)
var currencyPattern = regexp.MustCompile(`^[A-Z][A-Z0-9]{2,11}$`)

func ParseAmount(m Money) (*big.Int, error) {
	if !amountPattern.MatchString(m.Amount) || !currencyPattern.MatchString(m.Currency) {
		return nil, fmt.Errorf("invalid money")
	}
	n, ok := new(big.Int).SetString(m.Amount, 10)
	if !ok {
		return nil, errors.New("invalid amount")
	}
	return n, nil
}
func EqualMoney(a, b Money) bool {
	x, e := ParseAmount(a)
	y, f := ParseAmount(b)
	return e == nil && f == nil && a.Currency == b.Currency && x.Cmp(y) == 0
}

// encoding/json normally accepts case-insensitive field aliases; ABI v1 does not.
func exactFields(data []byte, typ reflect.Type) error {
	if typ == nil {
		return errors.New("nil JSON target")
	}
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ == reflect.TypeFor[json.RawMessage]() || typ.Kind() == reflect.Interface {
		return nil
	}
	switch typ.Kind() {
	case reflect.Struct:
		var object map[string]json.RawMessage
		if err := json.Unmarshal(data, &object); err != nil {
			return err
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = f.Name
			}
			fields[name] = f.Type
		}
		for key, raw := range object {
			t, ok := fields[key]
			if !ok {
				return errors.New("unknown JSON field")
			}
			if err := exactFields(raw, t); err != nil {
				return err
			}
		}
	case reflect.Map:
		var object map[string]json.RawMessage
		if err := json.Unmarshal(data, &object); err != nil {
			return err
		}
		for _, raw := range object {
			if err := exactFields(raw, typ.Elem()); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		if typ.Elem().Kind() == reflect.Uint8 {
			return nil
		}
		var items []json.RawMessage
		if err := json.Unmarshal(data, &items); err != nil {
			return err
		}
		for _, raw := range items {
			if err := exactFields(raw, typ.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}
