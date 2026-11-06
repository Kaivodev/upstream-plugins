// pluginctl builds, packages, replays, verifies and records test-only plugins.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Kaivodev/upstream-plugins/abi"
	"github.com/Kaivodev/upstream-plugins/host"
	"github.com/Kaivodev/upstream-plugins/internal/buildtool"
	"github.com/Kaivodev/upstream-plugins/internal/simrecord"
)

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: pluginctl build|package|replay|verify|record [flags]")
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	root := f.String("root", ".", "module source root")
	source := f.String("source", "", "plugin source directory relative to root")
	dir := f.String("dir", "", "built package directory")
	out := f.String("out", "", "output directory (or report JSON for replay)")
	casePath := f.String("case", "", "single host.Fixture input plan for generic test recording")
	credentialsEnv := f.String("credentials-env", "", "environment variable containing test-only secret/public-key JSON")
	allowHTTP := f.Bool("allow-test-http", false, "explicit HTTP exception for generic test recording")
	testOnly := f.Bool("test-only", false, "explicitly authorize test-only loopback recording")
	simURL := f.String("sim-url", "http://127.0.0.1:9080", "test simulator origin")
	tokenEnv := f.String("control-token-env", "UPSTREAM_SIM_CONTROL_TOKEN", "environment containing simulator test control token")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	abs, e := filepath.Abs(*root)
	if e != nil {
		return e
	}
	emit := func(v any) error { return json.NewEncoder(os.Stdout).Encode(v) }
	switch args[0] {
	case "build":
		if *source == "" || *out == "" {
			return errors.New("build requires --source and --out")
		}
		dst, e := filepath.Abs(*out)
		if e != nil {
			return e
		}
		p, e := buildtool.Build(ctx, abs, *source, dst)
		if e != nil {
			return e
		}
		hash, e := p.Hash()
		if e != nil {
			return e
		}
		return emit(map[string]string{"package_sha256": hash, "directory": dst})
	case "package", "replay", "verify", "record":
		if args[0] == "record" && (!*testOnly || *out == "") {
			return errors.New("record requires --test-only and --out; never use production credentials")
		}
		if *dir == "" {
			return errors.New("--dir required")
		}
		p, e := host.ReadPackage(*dir)
		if e != nil {
			return e
		}
		switch args[0] {
		case "package":
			if *out == "" {
				return errors.New("package requires --out")
			}
			if e = host.ValidateFixtures(p.Fixtures); e != nil {
				return e
			}
			if e = buildtool.WritePackage(*out, p); e != nil {
				return e
			}
			hash, _ := p.Hash()
			return emit(map[string]string{"package_sha256": hash, "directory": *out})
		case "replay":
			var b []byte
			var hash string
			if *credentialsEnv == "" {
				b, hash, e = host.Replay(ctx, p)
			} else {
				credentials, err := readCredentials(*credentialsEnv)
				if err != nil {
					return err
				}
				b, hash, e = host.ReplayWithEnvironment(ctx, p, func(context.Context, host.Manifest, host.Fixture) (host.Environment, func(*host.Fixture) error, error) {
					return credentials.Services(), nil, nil
				})
			}
			if len(b) > 0 {
				if *out != "" {
					if err := os.WriteFile(*out, b, 0644); err != nil {
						return err
					}
				} else {
					fmt.Println(string(b))
				}
				fmt.Fprintln(os.Stderr, "regression_report_sha256="+hash)
			}
			return e
		case "verify":
			if *source == "" {
				return errors.New("verify requires --source")
			}
			if e = buildtool.Verify(ctx, abs, *source, p); e != nil {
				return e
			}
			return emit(map[string]bool{"verified": true})
		case "record":
			if !*testOnly || *out == "" {
				return errors.New("record requires --test-only and --out; never use production credentials")
			}
			if *casePath != "" {
				if *credentialsEnv == "" {
					return errors.New("generic record requires --credentials-env")
				}
				credentials, err := readCredentials(*credentialsEnv)
				if err != nil {
					return err
				}
				data, err := os.ReadFile(*casePath)
				if err != nil {
					return err
				}
				var plan host.Fixture
				if err = abi.Decode(data, &plan); err != nil {
					return errors.New("invalid recording case")
				}
				return simrecord.RecordCase(ctx, p, plan, credentials, *allowHTTP, *out)
			}
			return simrecord.Record(ctx, p, *simURL, os.Getenv(*tokenEnv), *out)
		}
	}
	return errors.New("unknown subcommand")
}

func readCredentials(name string) (simrecord.Credentials, error) {
	var c simrecord.Credentials
	data, ok := os.LookupEnv(name)
	if !ok || abi.Decode([]byte(data), &c) != nil {
		return c, errors.New("test credential environment unavailable or invalid")
	}
	return c, nil
}
