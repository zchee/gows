// Package support provides the shared utilities of the bench harness:
// deterministic payload generation and echo verification, mergeable HDR
// latency recording, allocation/MemStats/rusage accounting, atomic file and
// JSON I/O, SHA-256 helpers, environment merging, host boot identity,
// module-root resolution, and the loadgen result schema. Payload verification and latency recording sit
// on the per-message hot path; the rest is control-plane code.
package support

import "unicode/utf8"

const defaultPayloadSeed uint64 = 0x9E3779B97F4A7C15

// DeterministicPayload returns an n-byte slice filled with a reproducible,
// non-trivial byte pattern (an xorshift64 PRNG seeded with a fixed constant).
// The same n always yields the same bytes across processes and runs, which
// keeps echo-harness comparisons reproducible without depending on
// crypto/math rand global state.
func DeterministicPayload(n int) []byte {
	return DeterministicPayloadSeed(n, defaultPayloadSeed)
}

// DeterministicPayloadSeed returns an n-byte reproducible binary payload for
// one explicit stream seed. Benchmark connections receive distinct seeds so
// identical content cannot correlate every connection while candidate and
// comparator runs can still replay byte-identical inputs.
func DeterministicPayloadSeed(n int, seed uint64) []byte {
	b := make([]byte, n)
	x := seed
	if x == 0 {
		x = defaultPayloadSeed
	}
	for i := range n {
		// xorshift64*
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		b[i] = byte(x)
	}
	return b
}

// DeterministicTextPayloadSeed returns exactly n bytes of valid UTF-8 while
// varying the token stream per explicit seed.
func DeterministicTextPayloadSeed(n int, seed uint64) []byte {
	if n <= 0 {
		return nil
	}
	patterns := [...]string{"g", "é", "世", "🙂"}
	result := make([]byte, 0, n)
	x := seed
	if x == 0 {
		x = defaultPayloadSeed
	}
	for len(result) < n {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		pattern := patterns[int(x%uint64(len(patterns)))]
		if len(result)+len(pattern) > n {
			result = append(result, byte('a'+x%26))
			continue
		}
		result = append(result, pattern...)
	}
	if !utf8.Valid(result) {
		panic("support: deterministic text payload generator produced invalid UTF-8")
	}
	return result
}
