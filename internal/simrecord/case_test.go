package simrecord

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"testing"
)

type testTransport func(*http.Request) (*http.Response, error)

func (t testTransport) RoundTrip(r *http.Request) (*http.Response, error) { return t(r) }

type trackedBody struct{ closed bool }

func (*trackedBody) Read([]byte) (int, error) { return 0, io.EOF }
func (b *trackedBody) Close() error           { b.closed = true; return nil }
func TestAmbiguousTransportClosesResponse(t *testing.T) {
	body := &trackedBody{}
	r := &caseTransport{base: testTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{Body: body}, context.DeadlineExceeded
	})}
	request, _ := http.NewRequest("POST", "https://test.example", strings.NewReader("test"))
	response, e := r.RoundTrip(request)
	if e == nil || response != nil || !body.closed || len(r.exchanges) != 1 || r.exchanges[0].Error != "timeout" {
		t.Fatal("ambiguous response was not closed and classified")
	}
}
func TestRecordingCredentialEncodings(t *testing.T) {
	b := make([]byte, 32)
	rand.Read(b)
	secret := hex.EncodeToString(b)
	c := Credentials{Secrets: map[string]string{"only_test": secret}}
	for _, v := range []string{secret, hex.EncodeToString([]byte(secret)), strings.ToUpper(hex.EncodeToString([]byte(secret))), base64.StdEncoding.EncodeToString([]byte(secret)), base64.RawStdEncoding.EncodeToString([]byte(secret)), base64.URLEncoding.EncodeToString([]byte(secret)), base64.RawURLEncoding.EncodeToString([]byte(secret))} {
		if !credentialLeak([]byte(v), c) {
			t.Fatal("recording accepted a credential encoding")
		}
	}
	if credentialLeak([]byte("public test protocol data"), c) {
		t.Fatal("false credential detection")
	}
}
