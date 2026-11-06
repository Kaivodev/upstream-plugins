// sim_json_rsa is a test-only upstream-sim JSON/RSA reactor.
package main

import "github.com/Kaivodev/upstream-plugins/internal/simprotocol"

func init() { simprotocol.Register("json-rsa") }
func main() {}
