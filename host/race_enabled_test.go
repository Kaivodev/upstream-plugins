//go:build race

package host

// raceEnabled is true when tests run under the race detector, which slows
// guest execution enough that the 200 ms step budget can expire first.
const raceEnabled = true
