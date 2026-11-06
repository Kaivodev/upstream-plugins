// sim_form_md5 is a test-only read-only upstream-sim form/MD5 reactor.
package main

import "github.com/Kaivodev/upstream-plugins/internal/simprotocol"

func init() { simprotocol.RegisterVerification("form-md5") }
func main() {}
