package host

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/Kaivodev/upstream-plugins/abi"
)

// Environment is trusted host code. Methods must honor context deadlines.
// RoundTripper must perform ONE exchange, never retry or follow redirects.
// Consumers own DNS/IP/egress enforcement, credential versioning and approval.
type Environment interface {
	Config(context.Context, string) (string, error)
	Secret(context.Context, string) ([]byte, error)
	PublicKey(context.Context, string) (*rsa.PublicKey, error)
	Now() time.Time
	Random() io.Reader
	Log(context.Context, abi.LogRequest)
	Alert(context.Context, string)
	Transport() http.RoundTripper
}

// Services is a convenience implementation. Nil credential hooks fail closed.
type Services struct {
	ConfigValues     map[string]string
	ResolveSecret    func(context.Context, string) ([]byte, error)
	ResolvePublicKey func(context.Context, string) (*rsa.PublicKey, error)
	Clock            func() time.Time
	RandomSource     io.Reader
	Logger           func(context.Context, abi.LogRequest)
	Alerter          func(context.Context, string)
	HTTP             http.RoundTripper
}

func (s Services) Config(_ context.Context, n string) (string, error) {
	v, ok := s.ConfigValues[n]
	if !ok {
		return "", errors.New("configuration unavailable")
	}
	return v, nil
}
func (s Services) Secret(c context.Context, n string) ([]byte, error) {
	if s.ResolveSecret == nil {
		return nil, errors.New("secret unavailable")
	}
	return s.ResolveSecret(c, n)
}
func (s Services) PublicKey(c context.Context, n string) (*rsa.PublicKey, error) {
	if s.ResolvePublicKey == nil {
		return nil, errors.New("public key unavailable")
	}
	return s.ResolvePublicKey(c, n)
}
func (s Services) Now() time.Time {
	if s.Clock != nil {
		return s.Clock().UTC()
	}
	return time.Now().UTC()
}
func (s Services) Random() io.Reader {
	if s.RandomSource != nil {
		return s.RandomSource
	}
	return rand.Reader
}
func (s Services) Log(c context.Context, v abi.LogRequest) {
	if s.Logger != nil {
		s.Logger(c, v)
	}
}
func (s Services) Alert(c context.Context, v string) {
	if s.Alerter != nil {
		s.Alerter(c, v)
	}
}
func (s Services) Transport() http.RoundTripper { return s.HTTP }
