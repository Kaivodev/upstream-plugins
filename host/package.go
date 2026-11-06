// Package host implements the shared, business-state-free WebAssembly sandbox.
package host

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"mime"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/Kaivodev/upstream-plugins/abi"
)

const MaxWasm = 16 << 20
const MaxManifest = 64 << 10
const MaxFixtures = 16 << 20

type Field struct {
	Type     string `json:"type"`
	Required bool   `json:"required"`
}
type CallbackRules struct {
	Methods        []string `json:"methods"`
	AllowQuery     bool     `json:"allow_query"`
	ContentTypes   []string `json:"content_types"`
	AckContentType string   `json:"ack_content_type"`
	AckStatus      int      `json:"ack_status"`
	AckBody        string   `json:"ack_body"`
}
type BuildInfo struct {
	GoVersion        string `json:"go_version"`
	SourceCommit     string `json:"source_commit"`
	SourceTreeSHA256 string `json:"source_tree_sha256"`
}
type Manifest struct {
	Type         string            `json:"type"`
	Code         string            `json:"code"`
	Version      string            `json:"version"`
	ABIVersion   int               `json:"abi_version"`
	Domains      []string          `json:"domains"`
	Secrets      map[string]string `json:"secrets"`
	PublicKeys   []string          `json:"public_keys"`
	Config       map[string]Field  `json:"config"`
	Capabilities []abi.Operation   `json:"capabilities"`
	Callback     *CallbackRules    `json:"callback,omitempty"`
	Build        BuildInfo         `json:"build"`
}
type Package struct {
	ManifestJSON []byte
	Wasm         []byte
	Fixtures     map[string][]byte
}

var codeRE = regexp.MustCompile(`^[a-z0-9_]{2,32}$`)
var nameRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
var semverRE = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)
var digestRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
var commitRE = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64}|uncommitted)$`)

func (m Manifest) Validate() error {
	if (m.Type != "payment" && m.Type != "statement") || !codeRE.MatchString(m.Code) || !semverRE.MatchString(m.Version) || m.ABIVersion != abi.Version {
		return errors.New("invalid manifest identity or ABI")
	}
	// Numeric prerelease components must not have leading zeros (SemVer 2).
	pre := strings.SplitN(strings.SplitN(m.Version, "+", 2)[0], "-", 2)
	if len(pre) == 2 {
		for _, p := range strings.Split(pre[1], ".") {
			if len(p) > 1 && p[0] == '0' && strings.Trim(p, "0123456789") == "" {
				return errors.New("invalid semver prerelease")
			}
		}
	}
	if len(m.Domains) == 0 || len(m.Domains) > 32 || len(m.Capabilities) == 0 {
		return errors.New("empty or excessive manifest permissions")
	}
	seen := map[string]bool{}
	for _, d := range m.Domains {
		if !validDomain(d) || seen[d] {
			return errors.New("invalid or duplicate domain")
		}
		seen[d] = true
	}
	seen = map[string]bool{}
	for _, op := range m.Capabilities {
		if seen[string(op)] || (m.Type == "payment" && !op.Payment()) || (m.Type == "statement" && op != abi.FetchStatement && op != abi.ParseStatement) {
			return errors.New("invalid capability")
		}
		seen[string(op)] = true
	}
	if len(m.Secrets) > 32 || len(m.Config) > 64 || len(m.PublicKeys) > 32 {
		return errors.New("too many manifest fields")
	}
	for n, t := range m.Secrets {
		if !nameRE.MatchString(n) || (t != "shared" && t != "rsa-private") {
			return errors.New("invalid secret definition")
		}
	}
	seen = map[string]bool{}
	for _, n := range m.PublicKeys {
		if !nameRE.MatchString(n) || seen[n] || m.Secrets[n] != "" {
			return errors.New("invalid public key reference")
		}
		seen[n] = true
	}
	for n, f := range m.Config {
		if !nameRE.MatchString(n) || f.Type != "string" || m.Secrets[n] != "" || slices.Contains(m.PublicKeys, n) {
			return errors.New("invalid nonsecret configuration definition")
		}
	}
	if slices.Contains(m.Capabilities, abi.VerifyCallback) {
		if m.Callback == nil || len(m.Callback.Methods) == 0 || len(m.Callback.ContentTypes) == 0 || !validMedia(m.Callback.AckContentType, false) || m.Callback.AckBody == "" || m.Callback.AckStatus < 200 || m.Callback.AckStatus > 299 || len(m.Callback.AckBody) > 1024 {
			return errors.New("invalid callback rules")
		}
		seenMethods := map[string]bool{}
		for _, method := range m.Callback.Methods {
			if !slices.Contains([]string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}, method) || seenMethods[method] {
				return errors.New("invalid callback method")
			}
			seenMethods[method] = true
		}
		for _, t := range m.Callback.ContentTypes {
			if !validMedia(t, true) {
				return errors.New("invalid callback content type")
			}
		}
	} else if m.Callback != nil {
		return errors.New("unexpected callback rules")
	}
	if m.Build.GoVersion != "go1.27.3" || !commitRE.MatchString(m.Build.SourceCommit) || !digestRE.MatchString(m.Build.SourceTreeSHA256) {
		return errors.New("invalid build provenance")
	}
	return nil
}
func validDomain(d string) bool {
	if d == "" || len(d) > 253 || strings.ToLower(d) != d || strings.HasSuffix(d, ".") {
		return false
	}
	for _, label := range strings.Split(d, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// Committed reports whether the package was built from a committed source
// tree. Approval and production loading require it.
func (m Manifest) Committed() bool { return m.Build.SourceCommit != "uncommitted" }

func (p Package) Manifest() (Manifest, []byte, error) {
	var m Manifest
	if len(p.ManifestJSON) > MaxManifest {
		return m, nil, errors.New("manifest size limit")
	}
	if err := abi.Decode(p.ManifestJSON, &m); err != nil {
		return m, nil, err
	}
	if err := m.Validate(); err != nil {
		return m, nil, err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return m, nil, err
	}
	b, err = abi.Canonical(b)
	return m, b, err
}
func (p Package) Hash() (string, error) {
	_, b, err := p.Manifest()
	if err != nil {
		return "", err
	}
	if len(p.Wasm) == 0 || len(p.Wasm) > MaxWasm {
		return "", errors.New("wasm size limit")
	}
	h := sha256.New()
	h.Write(b)
	h.Write(p.Wasm)
	return hex.EncodeToString(h.Sum(nil)), nil
}
func ReadPackage(dir string) (Package, error) {
	p := Package{Fixtures: map[string][]byte{}}
	if st, e := os.Lstat(dir); e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return p, errors.New("invalid package directory")
	}
	read := func(path string, max int) ([]byte, error) {
		s, e := os.Lstat(path)
		if e != nil {
			return nil, e
		}
		if !s.Mode().IsRegular() || s.Size() > int64(max) {
			return nil, errors.New("invalid package file or size")
		}
		return os.ReadFile(path)
	}
	var err error
	p.ManifestJSON, err = read(filepath.Join(dir, "manifest.json"), MaxManifest)
	if err != nil {
		return p, err
	}
	p.Wasm, err = read(filepath.Join(dir, "plugin.wasm"), MaxWasm)
	if err != nil {
		return p, err
	}
	total := 0
	err = filepath.WalkDir(filepath.Join(dir, "fixtures"), func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.Type()&os.ModeSymlink != 0 {
			return errors.New("fixture symlink")
		}
		if d.IsDir() {
			return nil
		}
		rel, e := filepath.Rel(dir, path)
		if e != nil {
			return e
		}
		rel = filepath.ToSlash(rel)
		if !ValidFixturePath(rel) || len(p.Fixtures) >= 256 {
			return errors.New("invalid fixture path/count")
		}
		b, e := read(path, abi.MaxJSON)
		if e != nil {
			return e
		}
		total += len(b)
		if total > MaxFixtures {
			return errors.New("fixture size limit")
		}
		p.Fixtures[rel] = b
		return nil
	})
	if err != nil {
		return p, err
	}
	_, err = p.Hash()
	return p, err
}
func ValidFixturePath(p string) bool {
	return strings.HasPrefix(p, "fixtures/") && strings.HasSuffix(p, ".json") && fs.ValidPath(p) && !strings.ContainsAny(p, "\\:")
}
func ValidateFixtures(files map[string][]byte) error {
	total := 0
	if len(files) == 0 || len(files) > 256 {
		return errors.New("invalid fixture count")
	}
	for path, b := range files {
		total += len(b)
		if !ValidFixturePath(path) || len(b) > abi.MaxJSON || total > MaxFixtures {
			return fmt.Errorf("invalid fixture material")
		}
	}
	return nil
}

func validMedia(v string, baseOnly bool) bool {
	if strings.ContainsAny(v, "\r\n\x00") {
		return false
	}
	t, params, e := mime.ParseMediaType(v)
	return e == nil && strings.Contains(t, "/") && (!baseOnly || t == v && len(params) == 0)
}
