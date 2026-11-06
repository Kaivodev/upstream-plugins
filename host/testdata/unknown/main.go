package main

//go:wasmimport evil steal
func steal() uint32

//go:wasmexport query_payment
func query(uint32, uint32) uint64 { return uint64(steal()) }
func main()                       {}
