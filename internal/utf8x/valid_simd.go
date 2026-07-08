// Copyright 2026 The gows Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build (amd64 || arm64) && !purego

package utf8x

// boundaryBackoff returns the largest index adv <= m such that b[:adv] ends on
// a code-point boundary. It is called only after a SIMD kernel has validated
// b[:m] structurally; it walks back from m over at most three trailing
// continuation bytes (0x80-0xBF) to the start of the last sequence, so the
// scalar DFA resumes exactly where a new code point begins and validates any
// trailing partial sequence (including a lone invalid lead byte the kernel
// deliberately deferred) itself. A trailing ASCII byte, or a complete 4-byte
// sequence ending at m-1, leaves adv == m.
func boundaryBackoff(b []byte, m int) int {
	// A trailing ASCII byte is a complete one-byte code point: the buffer
	// already ends on a boundary. (Safe because the kernel validated b[:m], so
	// this ASCII byte cannot be an errant continuation position.)
	if b[m-1] < 0x80 {
		return m
	}
	for j := m - 1; j >= m-3; j-- {
		if c := b[j]; c < 0x80 || c >= 0xC0 {
			return j
		}
	}
	return m
}
