// sim_json_rsa is a test-only read-only upstream-sim JSON/RSA reactor.
package main

import "github.com/Kaivodev/upstream-plugins/internal/simprotocol"

func init() { simprotocol.RegisterVerification("json-rsa") }
func main() {}
