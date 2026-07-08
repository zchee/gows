// Package support provides shared, non-hot-path utilities for the bench
// harness: deterministic payload generation, latency sample recording, and
// server-side MemStats collection over HTTP.
package support

// DeterministicPayload returns an n-byte slice filled with a reproducible,
// non-trivial byte pattern (an xorshift64 PRNG seeded with a fixed constant).
// The same n always yields the same bytes across processes and runs, which
// keeps echo-harness comparisons reproducible without depending on
// crypto/math rand global state.
func DeterministicPayload(n int) []byte {
	b := make([]byte, n)
	var x uint64 = 0x9E3779B97F4A7C15 // fixed seed (golden ratio constant)
	for i := range n {
		// xorshift64*
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		b[i] = byte(x)
	}
	return b
}
