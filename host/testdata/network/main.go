// Test-only reactor exercising the standard library's real network entry point.
package main

import (
	"github.com/Kaivodev/upstream-plugins/abi"
	"github.com/Kaivodev/upstream-plugins/sdk"
	"net"
)

func init() {
	sdk.Register(abi.QueryPayment, func(sdk.Call) sdk.Step {
		c, e := net.Dial("tcp", "127.0.0.1:9080")
		if e == nil {
			c.Close()
			panic("network escaped")
		}
		return sdk.Reject("network_denied")
	})
}
func main() {}
