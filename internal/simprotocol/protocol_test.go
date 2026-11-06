package simprotocol

import (
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"testing"
)

func TestMD5CrossVector(t *testing.T) {
	v := url.Values{"b": {"中 文&x=y"}, "a": {""}, "sign": {"ignored"}}
	canonical, e := CanonicalForm(v)
	if e != nil || canonical != "a=&b=%E4%B8%AD+%E6%96%87%26x%3Dy" {
		t.Fatal(canonical, e)
	}
	secret := make([]byte, 32)
	rand.Read(secret)
	sum := md5.Sum(append([]byte(canonical+"&key="), secret...))
	if len(hex.EncodeToString(sum[:])) != 32 {
		t.Fatal("MD5 shape")
	}
	other, _ := CanonicalForm(url.Values{"b": {"中 文"}, "x": {"y"}, "a": {""}})
	if other == canonical {
		t.Fatal("delimiter collision")
	}
	if _, e := CanonicalForm(url.Values{"x": {"a", "b"}}); e == nil {
		t.Fatal("duplicate accepted")
	}
}
func TestRSACrossVector(t *testing.T) {
	k, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	body := []byte(`{"amount":9223372036854775807}`)
	digest := sha256.Sum256(body)
	sig, e := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, digest[:])
	if e != nil || rsa.VerifyPKCS1v15(&k.PublicKey, crypto.SHA256, digest[:], sig) != nil {
		t.Fatal(e)
	}
	altered := sha256.Sum256(append(body, ' '))
	if rsa.VerifyPKCS1v15(&k.PublicKey, crypto.SHA256, altered[:], sig) == nil {
		t.Fatal("raw byte signature ignored whitespace")
	}
}
