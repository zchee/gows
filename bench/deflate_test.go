// Package bench also holds the permessage-deflate backend comparison of
// stdlib compress/flate vs github.com/klauspost/compress/flate, under the
// exact per-message, no-context-takeover framing gows's compress.go uses.
//
// Run with: go test -run=TestDeflateRoundTrip -bench=BenchmarkDeflate -benchmem -count=10 .
package bench

import (
	"bytes"
	"compress/flate"
	"fmt"
	"io"
	"strconv"
	"testing"

	kpflate "github.com/klauspost/compress/flate"
	"github.com/zchee/gows/bench/harness/support"
)

// syncFlushTail is the 4-byte marker compress/flate's Writer.Flush always
// terminates a non-final block with. RFC 7692 §7.2.1 (permessage-deflate)
// has the sender strip these 4 bytes off the wire and the receiver
// re-append them before inflating, since they're always reconstructible.
var syncFlushTail = [4]byte{0x00, 0x00, 0xff, 0xff}

var (
	deflateSizes  = []int{256, 1024, 4096, 16384}
	deflateLevels = []int{1, 6}
)

// flateWriter is the subset of *compress/flate.Writer and
// *github.com/klauspost/compress/flate.Writer's method sets this benchmark
// needs; both concrete types satisfy it structurally, letting every
// benchmark below share one code path across backends.
type flateWriter interface {
	io.Writer
	Reset(dst io.Writer)
	Flush() error
}

// flateResetter mirrors both packages' (identically shaped) Resetter
// interface, letting a pooled reader be reused across messages instead of
// allocating a new one per decode — the realistic no-context-takeover
// receive path.
type flateResetter interface {
	Reset(r io.Reader, dict []byte) error
}

type deflateBackend struct {
	name      string
	newWriter func(w io.Writer, level int) (flateWriter, error)
	newReader func(r io.Reader) io.ReadCloser
}

var deflateBackends = []deflateBackend{
	{
		name: "stdlib",
		newWriter: func(w io.Writer, level int) (flateWriter, error) {
			return flate.NewWriter(w, level)
		},
		newReader: flate.NewReader,
	},
	{
		name: "klauspost",
		newWriter: func(w io.Writer, level int) (flateWriter, error) {
			return kpflate.NewWriter(w, level)
		},
		newReader: kpflate.NewReader,
	},
}

type payloadKind struct {
	name string
	gen  func(n int) []byte
}

var payloadKinds = []payloadKind{
	{"jsonlike", genJSONLike},
	{"random", support.DeterministicPayload},
	{"repetitive", genRepetitive},
}

// genJSONLike returns n bytes of deterministic, JSON-like text modeled on
// small real-time web/app traffic (chat/game-state update records),
// truncated to exactly n bytes.
func genJSONLike(n int) []byte {
	var buf bytes.Buffer
	var x uint64 = 0x2545F4914F6CDD1D // fixed seed
	next := func() uint64 {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		return x
	}
	for buf.Len() < n {
		fmt.Fprintf(&buf,
			`{"id":%d,"type":"update","user":"user_%d","ts":%d,"value":%.2f,"active":%t,"tags":["a","b","c"]},`,
			next()%1_000_000, next()%10_000, 1_700_000_000+next()%100_000, float64(next()%10_000)/100, next()%2 == 0)
	}
	return buf.Bytes()[:n]
}

// genRepetitive returns n bytes of a short repeating text pattern,
// representative of highly redundant payloads (e.g. padded/templated
// messages).
func genRepetitive(n int) []byte {
	const pattern = "the quick brown fox jumps over the lazy dog. "
	b := make([]byte, n)
	for i := range b {
		b[i] = pattern[i%len(pattern)]
	}
	return b
}

// encodeMessage runs one permessage-deflate no-context-takeover encode
// cycle on an already-constructed (pooled) writer: Reset onto dst, Write
// the payload, Flush, and return the wire-ready bytes with the sync-flush
// tail stripped.
func encodeMessage(w flateWriter, dst *bytes.Buffer, payload []byte) []byte {
	dst.Reset()
	w.Reset(dst)
	_, _ = w.Write(payload)
	_ = w.Flush()
	out := dst.Bytes()
	return out[:len(out)-len(syncFlushTail)]
}

func benchName(be deflateBackend, level int, pk payloadKind, size int) string {
	return be.name + "/level" + strconv.Itoa(level) + "/" + pk.name + "/" + sizeName(size)
}

// TestDeflateRoundTrip verifies encodeMessage's output, once the sync-flush
// tail is re-appended, decodes back to the exact original payload for every
// backend/level/payload-kind/size combination the benchmarks below exercise.
// This is the correctness gate the benchmark numbers depend on: a framing
// mistake here would silently invalidate every ratio/throughput result.
func TestDeflateRoundTrip(t *testing.T) {
	type testCase struct {
		backend deflateBackend
		level   int
		payload []byte
	}
	tests := make(map[string]testCase)
	for _, be := range deflateBackends {
		for _, level := range deflateLevels {
			for _, pk := range payloadKinds {
				for _, size := range deflateSizes {
					tests[benchName(be, level, pk, size)] = testCase{
						backend: be,
						level:   level,
						payload: pk.gen(size),
					}
				}
			}
		}
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var dst bytes.Buffer
			w, err := tc.backend.newWriter(&dst, tc.level)
			if err != nil {
				t.Fatalf("newWriter: %v", err)
			}
			compressed := encodeMessage(w, &dst, tc.payload)
			wire := append(append([]byte(nil), compressed...), syncFlushTail[:]...)

			rc := tc.backend.newReader(bytes.NewReader(wire))
			defer rc.Close()
			got := make([]byte, len(tc.payload))
			if _, err := io.ReadFull(rc, got); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !bytes.Equal(got, tc.payload) {
				t.Fatalf("round-trip mismatch: %d bytes decoded, %d bytes expected", len(got), len(tc.payload))
			}
		})
	}
}

// BenchmarkDeflateEncode measures the full per-message no-context-takeover
// encode cycle (Reset+Write+Flush+tail-strip) a pooled *flate.Writer would
// perform in compress.go, across both backends.
func BenchmarkDeflateEncode(b *testing.B) {
	for _, be := range deflateBackends {
		for _, level := range deflateLevels {
			for _, pk := range payloadKinds {
				for _, size := range deflateSizes {
					payload := pk.gen(size)
					b.Run(benchName(be, level, pk, size), func(b *testing.B) {
						var dst bytes.Buffer
						w, err := be.newWriter(&dst, level)
						if err != nil {
							b.Fatalf("newWriter: %v", err)
						}
						var out []byte
						b.SetBytes(int64(size))
						for b.Loop() {
							out = encodeMessage(w, &dst, payload)
						}
						b.ReportMetric(float64(len(out))/float64(size), "ratio")
					})
				}
			}
		}
	}
}

// BenchmarkDeflateDecode measures the full per-message no-context-takeover
// decode cycle (tail re-append is precomputed once; timed loop covers
// pooled-reader Reset + inflate) across both backends, matching
// BenchmarkDeflateEncode's matrix.
func BenchmarkDeflateDecode(b *testing.B) {
	for _, be := range deflateBackends {
		for _, level := range deflateLevels {
			for _, pk := range payloadKinds {
				for _, size := range deflateSizes {
					payload := pk.gen(size)
					b.Run(benchName(be, level, pk, size), func(b *testing.B) {
						var encDst bytes.Buffer
						ew, err := be.newWriter(&encDst, level)
						if err != nil {
							b.Fatalf("newWriter: %v", err)
						}
						compressed := encodeMessage(ew, &encDst, payload)
						wire := append(append([]byte(nil), compressed...), syncFlushTail[:]...)

						br := bytes.NewReader(wire)
						rc := be.newReader(br)
						defer rc.Close()
						resetter, ok := rc.(flateResetter)
						if !ok {
							b.Fatalf("%s: reader does not implement Reset(io.Reader, []byte) error", be.name)
						}

						dst := make([]byte, size)
						b.SetBytes(int64(size))
						for b.Loop() {
							br.Reset(wire)
							if err := resetter.Reset(br, nil); err != nil {
								b.Fatalf("reset: %v", err)
							}
							if _, err := io.ReadFull(rc, dst); err != nil {
								b.Fatalf("read: %v", err)
							}
						}
					})
				}
			}
		}
	}
}

// BenchmarkDeflateWriterReset isolates the cost of Reset alone on an
// already-used writer (simulating pulling one out of a sync.Pool between
// messages), independent of payload size/kind since Reset's cost doesn't
// depend on prior message content.
func BenchmarkDeflateWriterReset(b *testing.B) {
	warm := genJSONLike(4096)
	for _, be := range deflateBackends {
		for _, level := range deflateLevels {
			b.Run(be.name+"/level"+strconv.Itoa(level), func(b *testing.B) {
				var dst bytes.Buffer
				w, err := be.newWriter(&dst, level)
				if err != nil {
					b.Fatalf("newWriter: %v", err)
				}
				// Warm the writer with one real write+flush cycle so Reset
				// measures resetting genuinely-used internal state, not a
				// freshly constructed (and possibly cheaper) writer.
				_, _ = w.Write(warm)
				_ = w.Flush()

				for b.Loop() {
					w.Reset(&dst)
				}
			})
		}
	}
}
