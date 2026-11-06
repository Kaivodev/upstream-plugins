// Package buildtool owns reproducible, offline, fixed-toolchain reactor builds.
package buildtool

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Kaivodev/upstream-plugins/abi"
	"github.com/Kaivodev/upstream-plugins/host"
)

const Toolchain = "go1.27.3"

func GoEnv() []string {
	overrides := map[string]string{"GOWORK": "off", "GOOS": "wasip1", "GOARCH": "wasm", "CGO_ENABLED": "0", "GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off", "GOFLAGS": "", "GOEXPERIMENT": "", "GODEBUG": "", "GOWASM": ""}
	env := []string{}
	for _, v := range os.Environ() {
		k, _, _ := strings.Cut(v, "=")
		if _, ok := overrides[k]; !ok {
			env = append(env, v)
		}
	}
	keys := make([]string, 0, len(overrides))
	for k := range overrides {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		env = append(env, k+"="+overrides[k])
	}
	return env
}

// TreeDigest binds exactly the module-local WASI build closure, not host tools.
func TreeDigest(ctx context.Context, root, source string) (string, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, "go", "list", "-deps", "-json", "./"+filepath.ToSlash(source))
	cmd.Dir, cmd.Env = root, GoEnv()
	data, err := cmd.Output()
	if err != nil {
		return "", errors.New("cannot list plugin build closure")
	}
	paths := map[string]bool{"go.mod": true, "go.sum": true}
	decoder := json.NewDecoder(bytes.NewReader(data))
	for {
		var pkg struct {
			Standard                      bool
			Dir                           string
			GoFiles, CgoFiles, EmbedFiles []string
			Module                        *struct {
				Path, Dir string
				Main      bool
			}
		}
		if err := decoder.Decode(&pkg); err == io.EOF {
			break
		} else if err != nil {
			return "", err
		}
		if pkg.Standard {
			continue
		}
		if pkg.Module == nil || !pkg.Module.Main || pkg.Module.Path != "github.com/Kaivodev/upstream-plugins" || filepath.Clean(pkg.Module.Dir) != root {
			return "", errors.New("plugin dependency not allowed")
		}
		for _, name := range append(append(pkg.GoFiles, pkg.CgoFiles...), pkg.EmbedFiles...) {
			rel, e := filepath.Rel(root, filepath.Join(pkg.Dir, name))
			if e != nil || !fs.ValidPath(filepath.ToSlash(rel)) {
				return "", errors.New("source outside module")
			}
			paths[filepath.ToSlash(rel)] = true
		}
	}
	ordered := make([]string, 0, len(paths))
	for path := range paths {
		ordered = append(ordered, path)
	}
	sort.Strings(ordered)
	h := sha256.New()
	field := func(b []byte) { _ = binary.Write(h, binary.BigEndian, uint64(len(b))); h.Write(b) }
	field([]byte("kaivo.plugin.source-closure.v2"))
	field([]byte("GOOS=wasip1;GOARCH=wasm;CGO_ENABLED=0;tags="))
	for _, path := range ordered {
		abs := filepath.Join(root, filepath.FromSlash(path))
		st, err := os.Lstat(abs)
		if err != nil {
			return "", err
		}
		resolved, err := filepath.EvalSymlinks(abs)
		if err != nil || resolved != abs || !st.Mode().IsRegular() {
			return "", errors.New("non-regular or linked source")
		}
		b, err := os.ReadFile(abs)
		if err != nil {
			return "", err
		}
		field([]byte("file"))
		field([]byte(path))
		field(b)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func Build(ctx context.Context, root, source, out string) (host.Package, error) {
	var p host.Package
	run := func(args ...string) ([]byte, error) {
		c := exec.CommandContext(ctx, "go", args...)
		c.Dir = root
		c.Env = GoEnv()
		b, e := c.CombinedOutput()
		if e != nil {
			return nil, errors.New("Go build command failed: " + string(b))
		}
		return b, nil
	}
	version, err := run("env", "GOVERSION")
	if err != nil {
		return p, err
	}
	if strings.TrimSpace(string(version)) != Toolchain {
		return p, errors.New("build requires " + Toolchain)
	}
	abs, err := filepath.Abs(filepath.Join(root, source))
	if err != nil {
		return p, err
	}
	rel, err := filepath.Rel(root, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return p, errors.New("source must be in module")
	}
	template, err := os.ReadFile(filepath.Join(abs, "manifest.json"))
	if err != nil {
		return p, err
	}
	var manifest host.Manifest
	if err = abi.Decode(template, &manifest); err != nil {
		return p, err
	}
	tree, err := TreeDigest(ctx, root, rel)
	if err != nil {
		return p, err
	}
	commit := "uncommitted"
	git := exec.CommandContext(ctx, "git", "rev-parse", "HEAD")
	git.Dir = root
	if b, e := git.Output(); e == nil {
		commit = strings.TrimSpace(string(b))
		status := exec.CommandContext(ctx, "git", "status", "--porcelain")
		status.Dir = root
		if b, e := status.Output(); e != nil || len(b) != 0 {
			commit = "uncommitted"
		}
	}
	manifest.Build = host.BuildInfo{GoVersion: Toolchain, SourceCommit: commit, SourceTreeSHA256: tree}
	if err = manifest.Validate(); err != nil {
		return p, err
	}
	p.ManifestJSON, err = json.Marshal(manifest)
	if err != nil {
		return p, err
	}
	outAbs, e := filepath.Abs(out)
	if e != nil {
		return p, e
	}
	sourceRel, e := filepath.Rel(abs, outAbs)
	if e != nil {
		return p, e
	}
	if sourceRel == "." || !strings.HasPrefix(sourceRel, ".."+string(filepath.Separator)) && sourceRel != ".." {
		return p, errors.New("build output must be outside plugin source")
	}
	if err = safeDirectory(outAbs); err != nil {
		return p, err
	}
	if err = os.MkdirAll(out, 0755); err != nil {
		return p, err
	}
	wasmPath := filepath.Join(out, "plugin.wasm")
	if _, err = run("build", "-trimpath", "-buildvcs=false", "-buildmode=c-shared", "-ldflags=-buildid=", "-o", wasmPath, "./"+filepath.ToSlash(rel)); err != nil {
		return p, err
	}
	p.Wasm, err = os.ReadFile(wasmPath)
	if err != nil {
		return p, err
	}
	p.Fixtures = map[string][]byte{}
	err = filepath.WalkDir(filepath.Join(abs, "fixtures"), func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.Type()&os.ModeSymlink != 0 {
			return errors.New("fixture symlink")
		}
		if d.IsDir() {
			return nil
		}
		rel, e := filepath.Rel(abs, path)
		if e != nil {
			return e
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		p.Fixtures[filepath.ToSlash(rel)] = b
		return nil
	})
	if err != nil {
		return p, err
	}
	if _, err = p.Hash(); err != nil {
		return p, err
	}
	if err = WritePackage(out, p); err != nil {
		return p, err
	}
	return p, nil
}
func safeDirectory(path string) error {
	abs, e := filepath.Abs(path)
	if e != nil {
		return e
	}
	current := filepath.VolumeName(abs) + string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(abs, current), string(filepath.Separator)) {
		current = filepath.Join(current, part)
		st, e := os.Lstat(current)
		if os.IsNotExist(e) {
			if e = os.Mkdir(current, 0755); e != nil {
				return e
			}
			continue
		}
		if e != nil {
			return e
		}
		// macOS system aliases are outside the package tree and are trusted.
		if st.Mode()&os.ModeSymlink != 0 && (current == "/var" || current == "/tmp") {
			target, e := filepath.EvalSymlinks(current)
			if e == nil && (target == "/private/var" || target == "/private/tmp") {
				continue
			}
		}
		if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return errors.New("output directory must not contain links")
		}
	}
	return nil
}
func WritePackage(out string, p host.Package) error {
	if _, err := p.Hash(); err != nil {
		return err
	}
	if err := safeDirectory(filepath.Join(out, "fixtures")); err != nil {
		return err
	}
	if len(p.Fixtures) > 0 {
		if err := host.ValidateFixtures(p.Fixtures); err != nil {
			return err
		}
	}
	// Remove stale fixture files only, never user-selected directories.
	if err := filepath.WalkDir(filepath.Join(out, "fixtures"), func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.Type()&os.ModeSymlink != 0 {
			return errors.New("fixture output symlink")
		}
		if d.IsDir() {
			return nil
		}
		rel, e := filepath.Rel(out, path)
		if e != nil {
			return e
		}
		rel = filepath.ToSlash(rel)
		if !host.ValidFixturePath(rel) {
			return errors.New("unexpected fixture output file")
		}
		if _, ok := p.Fixtures[rel]; !ok {
			return os.Remove(path)
		}
		return nil
	}); err != nil {
		return err
	}
	files := map[string][]byte{"manifest.json": p.ManifestJSON, "plugin.wasm": p.Wasm}
	for path, b := range p.Fixtures {
		if !host.ValidFixturePath(path) {
			return errors.New("invalid fixture path")
		}
		files[path] = b
	}
	for path, b := range files {
		dst := filepath.Join(out, filepath.FromSlash(path))
		if err := safeDirectory(filepath.Dir(dst)); err != nil {
			return err
		}
		if s, e := os.Lstat(dst); e == nil && !s.Mode().IsRegular() {
			return errors.New("non-regular output")
		}
		if err := os.WriteFile(dst, b, 0644); err != nil {
			return err
		}
	}
	return nil
}
func Verify(ctx context.Context, root, source string, p host.Package) error {
	tmp, e := os.MkdirTemp("", "plugin-verify-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(tmp)
	rebuilt, e := Build(ctx, root, source, tmp)
	if e != nil {
		return e
	}
	if !bytes.Equal(rebuilt.Wasm, p.Wasm) {
		return errors.New("wasm differs from source rebuild")
	}
	m, _, e := p.Manifest()
	if e != nil {
		return e
	}
	r, _, e := rebuilt.Manifest()
	if e != nil {
		return e
	}
	if m.Build != r.Build {
		return errors.New("build provenance differs")
	}
	return nil
}
