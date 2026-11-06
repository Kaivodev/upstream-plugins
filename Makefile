SHELL := /bin/sh
export GOWORK := off
export GOPROXY := off

.PHONY: fmt check build plugins plugins-replay plugins-verify bench
PLUGINS := sim_json_rsa sim_form_md5 sim_json_rsa_verify sim_form_md5_verify
fmt:
	gofmt -w .
check:
	go vet ./...
	go test -race -timeout 30m ./...
build:
	CGO_ENABLED=0 go build -trimpath -buildvcs=false -o bin/pluginctl ./cmd/pluginctl
plugins: build
	@set -e; for plugin in $(PLUGINS); do bin/pluginctl build --source plugins/$$plugin --out dist/$$plugin; done
plugins-replay: plugins
	@set -e; for plugin in $(PLUGINS); do bin/pluginctl replay --dir dist/$$plugin --out dist/$$plugin/regression-report.json; done
plugins-verify: plugins-replay
	@set -e; for plugin in $(PLUGINS); do \
		bin/pluginctl package --dir dist/$$plugin --out dist/packages/$$plugin; \
		bin/pluginctl verify --source plugins/$$plugin --dir dist/packages/$$plugin; \
	done
bench:
	go test ./host -run '^$$' -bench BenchmarkFresh -benchmem
