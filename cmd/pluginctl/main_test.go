package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"github.com/Kaivodev/upstream-plugins/abi"
	"github.com/Kaivodev/upstream-plugins/host"
	"github.com/Kaivodev/upstream-plugins/internal/buildtool"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildTwiceAndVerify(t *testing.T) {
	root, e := filepath.Abs("../..")
	if e != nil {
		t.Fatal(e)
	}
	for _, plugin := range []string{"sim_json_rsa", "sim_form_md5", "sim_json_rsa_verify", "sim_form_md5_verify"} {
		t.Run(plugin, func(t *testing.T) {
			a, b := filepath.Join(t.TempDir(), "a"), filepath.Join(t.TempDir(), "b")
			for _, out := range []string{a, b} {
				if e := run(context.Background(), []string{"build", "--root", root, "--source", "plugins/" + plugin, "--out", out}); e != nil {
					t.Fatal(e)
				}
			}
			x, e := host.ReadPackage(a)
			if e != nil {
				t.Fatal(e)
			}
			y, e := host.ReadPackage(b)
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(x.Wasm, y.Wasm) || !bytes.Equal(x.ManifestJSON, y.ManifestJSON) {
				t.Fatal("build is not byte reproducible")
			}
			if e = run(context.Background(), []string{"verify", "--root", root, "--source", "plugins/" + plugin, "--dir", a}); e != nil {
				t.Fatal(e)
			}
			x.Wasm[len(x.Wasm)-1] ^= 1
			if e = os.WriteFile(filepath.Join(a, "plugin.wasm"), x.Wasm, 0644); e != nil {
				t.Fatal(e)
			}
			if e = run(context.Background(), []string{"verify", "--root", root, "--source", "plugins/" + plugin, "--dir", a}); e == nil {
				t.Fatal("tampered artifact verified")
			}
		})
	}
}
func TestCommandValidation(t *testing.T) {
	for _, args := range [][]string{nil, {"unknown"}, {"build"}, {"record", "--dir", "missing"}, {"package"}, {"replay", "--bad-option"}} {
		if run(context.Background(), args) == nil {
			t.Fatal("invalid command accepted", args)
		}
	}
}

func TestGenericRecord(t *testing.T) {
	root, e := filepath.Abs("../..")
	if e != nil {
		t.Fatal(e)
	}
	built := filepath.Join(t.TempDir(), "plugin")
	if e = run(context.Background(), []string{"build", "--root", root, "--source", "plugins/sim_form_md5", "--out", built}); e != nil {
		t.Fatal(e)
	}
	secretBytes := make([]byte, 32)
	rand.Read(secretBytes)
	secret := hex.EncodeToString(secretBytes)
	credentials, _ := json.Marshal(map[string]any{"secrets": map[string]string{"shared": secret}, "public_keys": map[string]string{}})
	t.Setenv("PLUGIN_ONLY_TEST_CASE_CREDENTIALS", string(credentials))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result":"accepted","code":"ok","order":{"account_id":"md5-demo","order_id":"only_test_generic_record","upstream_id":"only_test_upstream","amount":100,"currency":"CNY","method":"alipay","status":"pending","url":"https://cashier.example/test"}}`))
	}))
	defer server.Close()
	input, _ := json.Marshal(abi.CreatePaymentInput{OrderID: "only_test_generic_record", Money: abi.Money{Amount: "100", Currency: "CNY"}, Method: "alipay", CallbackURL: "https://callback.example/test"})
	plan := host.Fixture{Name: "create_payment/success", Operation: abi.CreatePayment, Input: input, Config: map[string]string{"gateway": server.URL, "account_id": "md5-demo"}}
	data, _ := json.Marshal(plan)
	casePath := filepath.Join(t.TempDir(), "case.json")
	if e = os.WriteFile(casePath, data, 0600); e != nil {
		t.Fatal(e)
	}
	out := filepath.Join(t.TempDir(), "fixtures")
	if e = run(context.Background(), []string{"record", "--test-only", "--allow-test-http", "--dir", built, "--case", casePath, "--credentials-env", "PLUGIN_ONLY_TEST_CASE_CREDENTIALS", "--out", out}); e != nil {
		t.Fatal(e)
	}
	recorded, e := os.ReadFile(filepath.Join(out, "create_payment_success.json"))
	if e != nil || bytes.Contains(recorded, []byte(secret)) {
		t.Fatal("record contained test credential", e)
	}
	var fixture host.Fixture
	if e = abi.Decode(recorded, &fixture); e != nil || fixture.Source != "recorded_test_upstream" || fixture.Expected.Category != host.Completed || len(fixture.Exchanges) != 1 {
		t.Fatal("invalid recording", e)
	}
	// Verify the recorded exchange's protocol payload and signature redaction.
	if !strings.Contains(string(fixture.Exchanges[0].Request.Body), host.TestSignature) {
		t.Fatal("signature not normalized")
	}
}

func TestGenericReplayCredentialSource(t *testing.T) {
	root, _ := filepath.Abs("../..")
	built := filepath.Join(t.TempDir(), "plugin")
	if e := run(context.Background(), []string{"build", "--root", root, "--source", "plugins/sim_form_md5", "--out", built}); e != nil {
		t.Fatal(e)
	}
	p, e := host.ReadPackage(built)
	if e != nil {
		t.Fatal(e)
	}
	m, _, e := p.Manifest()
	if e != nil {
		t.Fatal(e)
	}
	m.Capabilities = []abi.Operation{abi.CreatePayment}
	m.Callback = nil
	p.ManifestJSON, _ = json.Marshal(m)
	names := []string{"success", "rejected", "timeout", "signature_error", "amount_mismatch"}
	files := map[string][]byte{}
	for _, name := range names {
		path := "fixtures/create_payment_" + name + ".json"
		files[path] = p.Fixtures[path]
	}
	p.Fixtures = files
	// These recorded request signatures are normalized; generating a different
	// test shared credential must still reproduce the exact recorded facts.
	raw := make([]byte, 32)
	rand.Read(raw)
	secret := hex.EncodeToString(raw)
	credentials, _ := json.Marshal(map[string]any{"secrets": map[string]string{"shared": secret}, "public_keys": map[string]string{}})
	t.Setenv("PLUGIN_ONLY_TEST_REPLAY_CREDENTIALS", string(credentials))
	packaged := filepath.Join(t.TempDir(), "package")
	if e = buildtool.WritePackage(packaged, p); e != nil {
		t.Fatal(e)
	}
	report := filepath.Join(t.TempDir(), "report.json")
	if e = run(context.Background(), []string{"replay", "--dir", packaged, "--credentials-env", "PLUGIN_ONLY_TEST_REPLAY_CREDENTIALS", "--out", report}); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(report)
	if e != nil || bytes.Contains(b, []byte(secret)) {
		t.Fatal("report secret", e)
	}
	var result host.Report
	if e = abi.Decode(b, &result); e != nil || !result.Passed || len(result.Cases) != 5 {
		t.Fatal("generic replay failed", e)
	}
}
