package host

import (
	"crypto"
	"crypto/hmac"
	"crypto/md5" // ABI includes legacy upstream algorithms; not for platform security.
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"hash"

	"github.com/Kaivodev/upstream-plugins/abi"
)

func privateKey(b []byte) (*rsa.PrivateKey, error) {
	p, _ := pem.Decode(b)
	if p == nil {
		return nil, errors.New("invalid key")
	}
	v, err := x509.ParsePKCS8PrivateKey(p.Bytes)
	if err != nil {
		return nil, errors.New("invalid key")
	}
	k, ok := v.(*rsa.PrivateKey)
	if !ok || k.N.BitLen() < 2048 {
		return nil, errors.New("invalid key")
	}
	if err := k.Validate(); err != nil {
		return nil, errors.New("invalid key")
	}
	return k, nil
}
func (s *invocation) parts(parts []abi.Part) ([]byte, error) {
	if len(parts) > 128 {
		return nil, errors.New("parts limit")
	}
	var b []byte
	for _, p := range parts {
		if p.Secret != "" {
			if len(p.Data) != 0 || s.manifest.Secrets[p.Secret] != "shared" {
				return nil, errors.New("invalid secret part")
			}
			b = append(b, s.secrets[p.Secret]...)
		} else {
			b = append(b, p.Data...)
		}
		if len(b) > abi.MaxJSON {
			return nil, errors.New("parts size limit")
		}
	}
	return b, nil
}
func (s *invocation) sign(r abi.SignRequest) (string, error) {
	b, err := s.parts(r.Parts)
	if err != nil {
		return "", err
	}
	if r.Algorithm == "rsa-sha256" {
		if s.manifest.Secrets[r.Key] != "rsa-private" {
			return "", errors.New("undeclared signing key")
		}
		k, err := privateKey(s.secrets[r.Key])
		if err != nil {
			return "", err
		}
		d := sha256.Sum256(b)
		sig, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, d[:])
		return base64.StdEncoding.EncodeToString(sig), err
	}
	var h hash.Hash
	switch r.Algorithm {
	case "md5":
		h = md5.New()
	case "sha1":
		h = sha1.New()
	case "sha256":
		h = sha256.New()
	case "hmac-sha256":
		if s.manifest.Secrets[r.Key] != "shared" {
			return "", errors.New("undeclared HMAC key")
		}
		h = hmac.New(sha256.New, s.secrets[r.Key])
	default:
		return "", errors.New("unsupported signing algorithm")
	}
	if r.Algorithm != "hmac-sha256" && r.Key != "" {
		return "", errors.New("unexpected key")
	}
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil)), nil
}
