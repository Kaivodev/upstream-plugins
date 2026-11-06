package buildtool

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSourceDigestInputs(t *testing.T) {
	root := t.TempDir()
	for n, b := range map[string]string{"go.mod": "module test\n", "go.sum": "", "main.go": "package main\n", "main_test.go": "package main\n", "README.md": "docs"} {
		if e := os.WriteFile(filepath.Join(root, n), []byte(b), 0644); e != nil {
			t.Fatal(e)
		}
	}
	a, e := TreeDigest(root)
	if e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(root, "README.md"), []byte("changed docs"), 0644)
	os.WriteFile(filepath.Join(root, "main_test.go"), []byte("changed tests"), 0644)
	b, e := TreeDigest(root)
	if e != nil || a != b {
		t.Fatal("non-build inputs changed digest")
	}
	os.WriteFile(filepath.Join(root, "main.go"), []byte("package changed"), 0644)
	b, e = TreeDigest(root)
	if e != nil || a == b {
		t.Fatal("source change not bound")
	}
}
func TestBuildEnvironment(t *testing.T) {
	for _, want := range []string{"GOWORK=off", "GOCACHE=/private/tmp/codex-gocache/upstream-plugins", "GOOS=wasip1", "GOARCH=wasm", "CGO_ENABLED=0", "GOPROXY=off", "GOTOOLCHAIN=local"} {
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
