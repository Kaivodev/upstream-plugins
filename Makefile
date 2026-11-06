SHELL := /bin/sh
export GOWORK := off
export GOPROXY := off

.PHONY: fmt check build plugins plugins-replay bench
fmt:
	gofmt -w .
check:
	go vet ./...
	go test -race ./...
build:
	CGO_ENABLED=0 go build -trimpath -buildvcs=false -o bin/pluginctl ./cmd/pluginctl
plugins: build
	bin/pluginctl build --source plugins/sim_json_rsa --out dist/sim_json_rsa
	bin/pluginctl build --source plugins/sim_form_md5 --out dist/sim_form_md5
plugins-replay: plugins
	bin/pluginctl replay --dir dist/sim_json_rsa --out dist/sim_json_rsa/regression-report.json
	bin/pluginctl replay --dir dist/sim_form_md5 --out dist/sim_form_md5/regression-report.json
bench:
	go test ./host -run '^$$' -bench BenchmarkFresh -benchmem
