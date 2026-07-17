package support

import (
	"bytes"
	"fmt"
)

// MaxInflightBytes bounds capacity*payload for a pipelined loadgen connection.
// Priming k messages back-to-back pushes up to k*payload bytes toward the
// server before the client reads a single echo; keeping that product well
// under a megabyte stays comfortably inside typical loopback socket buffers so
// the synchronous gobwas write path can never silently deadlock against an
// unread echo stream. Both loadgen and the policy schema reject configurations
// above it.
const MaxInflightBytes = 1 << 20

// VerifyEcho reports a descriptive error when got is not byte-for-byte equal to
// expected. The loadgen payload is deterministic and identical for every
// message, so a correct echo server always returns expected exactly; any
// difference in length or content is a server- or transport-level corruption
// that must fail the run rather than be silently counted as throughput.
//
// The common case (a correct echo) is decided by a single [bytes.Equal], which
// dispatches to the runtime's SIMD memequal and is far cheaper than a scalar
// byte loop on the per-message hot path. Only a genuine mismatch pays for the
// descriptive length/content diagnosis.
func VerifyEcho(expected, got []byte) error {
	if bytes.Equal(expected, got) {
		return nil
	}
	if len(got) != len(expected) {
		return fmt.Errorf("echo length mismatch: got %d bytes, want %d", len(got), len(expected))
	}
	for i := range expected {
		if got[i] != expected[i] {
			return fmt.Errorf("echo content mismatch at byte %d: got 0x%02x, want 0x%02x", i, got[i], expected[i])
		}
	}
	return nil
}
