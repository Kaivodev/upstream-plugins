package buildtool

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSourceDigestInputs(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"go.mod": "module github.com/Kaivodev/upstream-plugins\n\ngo 1.27.0\n", "go.sum": "",
		"plugins/one/main.go": `package main
import _ "github.com/Kaivodev/upstream-plugins/sdk"
func main() {}`,
		"sdk/sdk.go": `package sdk
import _ "github.com/Kaivodev/upstream-plugins/abi"
import _ "embed"
//go:embed asset.txt
var asset string`,
		"sdk/asset.txt": "embedded", "abi/abi.go": "package abi\n", "plugins/two/main.go": "package main\n",
		"host/host.go": "package host\n", "cmd/tool/main.go": "package main\n", "sdk/sdk_test.go": "package sdk\n",
		"sdk/native.go": "//go:build !wasip1\n\npackage sdk\n", "README.md": "docs",
	}
	for path, body := range files {
		abs := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(abs), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	digest := func() string {
		t.Helper()
		d, e := TreeDigest(context.Background(), root, "plugins/one")
		if e != nil {
			t.Fatal(e)
		}
		return d
	}
	original := digest()
	for _, path := range []string{"host/host.go", "cmd/tool/main.go", "plugins/two/main.go", "sdk/sdk_test.go", "sdk/native.go", "README.md"} {
		if err := os.WriteFile(filepath.Join(root, path), []byte(files[path]+"\n// changed\n"), 0644); err != nil {
			t.Fatal(err)
		}
		if digest() != original {
			t.Fatalf("unrelated file %s changed digest", path)
		}
	}
	for _, path := range []string{"plugins/one/main.go", "sdk/sdk.go", "abi/abi.go", "go.mod", "go.sum", "sdk/asset.txt"} {
		if err := os.WriteFile(filepath.Join(root, path), []byte(files[path]+"\n// changed\n"), 0644); err != nil {
			t.Fatal(err)
		}
		if digest() == original {
			t.Fatalf("closure input %s not bound", path)
		}
		if err := os.WriteFile(filepath.Join(root, path), []byte(files[path]), 0644); err != nil {
			t.Fatal(err)
		}
	}
}
func TestBuildEnvironment(t *testing.T) {
	for _, want := range []string{"GOWORK=off", "GOOS=wasip1", "GOARCH=wasm", "CGO_ENABLED=0", "GOPROXY=off", "GOTOOLCHAIN=local"} {
		found := false
		key, _, _ := strings.Cut(want, "=")
		for _, v := range GoEnv() {
			if strings.HasPrefix(v, key+"=") {
				if v != want {
					t.Fatal(v)
				}
				found = true
			}
		}
		if !found {
			t.Fatal(want)
		}
	}
}

func TestBuildInheritsCache(t *testing.T) {
	cache := t.TempDir()
	t.Setenv("GOCACHE", cache)
	found := false
	for _, v := range GoEnv() {
		if v == "GOCACHE="+cache {
			found = true
		}
	}
	if !found {
		t.Fatal("caller cache not inherited")
	}
}
