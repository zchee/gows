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

package gows

import (
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/zchee/gows/internal/pool"
)

// inflateChunkSize is the scratch read size [Conn.decompressMessage]
// uses per [deflateReader.Read] call while inflating a compressed
// message.
const inflateChunkSize = 4096

// deflateFlushTail is the 4-byte DEFLATE sync-flush marker (RFC 7692
// §7.2.1) that [deflateWriter.Flush] always appends to its output;
// compressPayload strips exactly these 4 trailing bytes before the
// result goes on the wire.
var deflateFlushTail = [4]byte{0x00, 0x00, 0xff, 0xff}

// deflateReadTail is what [tailReader] appends to a received message's
// compressed bytes before inflating -- RFC 7692 §7.2.2's mirror of
// deflateFlushTail, but 5 bytes longer. A bare 4-byte sync-flush marker
// decodes to the right bytes but leaves the underlying DEFLATE bitstream
// non-final (BFINAL=0): a [deflateReader.Read] fed only those 4 bytes
// correctly reports io.ErrUnexpectedEOF once tailReader's source is
// exhausted, since the stream never saw a real terminator. Appending 5
// more bytes forming a genuine final empty stored block (BFINAL=1,
// BTYPE=00, LEN=0x0000/NLEN=0xffff) gives the decompressor a clean
// end-of-stream instead, so Read reports a plain io.EOF -- the same
// technique gorilla/websocket and coder/websocket use for the same
// reason (verified against stdlib compress/flate directly: appending
// only deflateFlushTail yields io.ErrUnexpectedEOF from io.ReadAll,
// appending deflateReadTail yields a nil error, for identical decoded
// output either way).
var deflateReadTail = [9]byte{0x00, 0x00, 0xff, 0xff, 0x01, 0x00, 0x00, 0xff, 0xff}

// deflateWriterPool recycles pooled [deflateWriter] values (backed by
// [newDeflateWriter] at [defaultDeflateLevel]) across messages and
// connections. Every borrow calls Reset onto a fresh destination before
// use, which -- per compress/flate's documented Reset semantics --
// discards any prior LZ77 window state too, giving each message a fresh,
// empty window: exactly RFC 7692 §7.2.1's no-context-takeover behavior,
// achieved without any per-Conn compressor state.
var deflateWriterPool = sync.Pool{
	New: func() any { return newDeflateWriter(defaultDeflateLevel) },
}

// deflateReaderPool is deflateWriterPool's read-side counterpart: every
// borrow calls Reset with a fresh source before use, discarding any
// prior decompression window state (no-context-takeover for the receive
// direction).
var deflateReaderPool = sync.Pool{
	New: func() any { return newDeflateReader() },
}

// errDecompressedTooLarge is compress.go's internal bomb-defense
// sentinel: [Conn.decompressMessage] returns it once inflating a
// message's compressed bytes would produce more than c.readLimit bytes
// of output, without continuing to inflate an unbounded decompression
// bomb. The caller translates it into a 1009 (Message Too Big) close,
// mirroring the existing wire-size enforcement already applied to
// compressed bytes in [Conn.readFramePayload].
var errDecompressedTooLarge = errors.New("gows: decompressed message exceeds read limit")

// sliceWriter is an io.Writer that appends to an owned byte slice,
// letting compressPayload capture a pooled [deflateWriter]'s Flush
// output directly into a caller-supplied scratch buffer with no
// intermediate allocation.
type sliceWriter struct {
	b []byte
}

// Write implements io.Writer.
func (w *sliceWriter) Write(p []byte) (int, error) {
	w.b = append(w.b, p...)
	return len(p), nil
}

// tailReader serves message bytes b followed by [deflateReadTail]'s 9
// bytes, without copying or mutating b: a [deflateReader] reads through
// this exactly as if the tail had been appended to b directly, but a
// message reassembly buffer can be handed off regardless of its spare
// capacity, and no allocation is needed to build the concatenation.
type tailReader struct {
	b       []byte
	tailPos int
}

// Read implements io.Reader.
func (r *tailReader) Read(p []byte) (int, error) {
	if len(r.b) > 0 {
		n := copy(p, r.b)
		r.b = r.b[n:]
		return n, nil
	}
	if r.tailPos < len(deflateReadTail) {
		n := copy(p, deflateReadTail[r.tailPos:])
		r.tailPos += n
		return n, nil
	}
	return 0, io.EOF
}

// compressPayload deflate-compresses p (RFC 7692 §7.2.1) using a pooled
// [deflateWriter] reset onto a fresh, empty LZ77 window
// (no-context-takeover), appends the result to dst[:0] (reusing its
// storage), strips the trailing 4-byte sync-flush marker Flush always
// emits, and returns the extended slice.
func compressPayload(dst, p []byte) ([]byte, error) {
	w := deflateWriterPool.Get().(deflateWriter)
	defer deflateWriterPool.Put(w)

	sw := sliceWriter{b: dst[:0]}
	w.Reset(&sw)
	if _, err := w.Write(p); err != nil {
		return nil, fmt.Errorf("gows: compress message: %w", err)
	}
	if err := w.Flush(); err != nil {
		return nil, fmt.Errorf("gows: flush compressed message: %w", err)
	}

	out := sw.b
	if len(out) < len(deflateFlushTail) {
		// Flush is documented to always emit the 4-byte marker (verified
		// directly against stdlib compress/flate, including for a
		// zero-length payload, which still flushes 5 bytes); this should
		// be unreachable, but never slice out of range on a backend that
		// somehow violates the contract.
		return nil, errors.New("gows: compressed output shorter than the sync-flush marker")
	}
	return out[:len(out)-len(deflateFlushTail)], nil
}

// decompressMessage inflates compressed -- a reassembled permessage-deflate
// message with its trailing sync-flush marker already stripped, per RFC
// 7692 §7.2.1 -- using a pooled [deflateReader] and [deflateReadTail]
// re-appended (§7.2.2), into c.inflateBuf (reused across messages, like
// c.msgBuf). Decompressed output is bounded by c.readLimit; exceeding it
// returns [errDecompressedTooLarge] instead of continuing to inflate an
// unbounded decompression bomb.
func (c *Conn) decompressMessage(compressed []byte) ([]byte, error) {
	r := deflateReaderPool.Get().(deflateReader)
	defer deflateReaderPool.Put(r)

	tr := tailReader{b: compressed}
	if err := r.Reset(&tr, nil); err != nil {
		return nil, fmt.Errorf("gows: reset decompressor: %w", err)
	}
	if c.inflateScratch == nil {
		c.inflateScratch = pool.Get(inflateChunkSize)[:inflateChunkSize]
	}

	out := c.inflateBuf[:0]
	var total int64
	for {
		n, err := r.Read(c.inflateScratch)
		if n > 0 {
			total += int64(n)
			if total > c.readLimit {
				c.inflateBuf = out
				return nil, errDecompressedTooLarge
			}
			out = append(out, c.inflateScratch[:n]...)
		}
		if err != nil {
			c.inflateBuf = out
			if errors.Is(err, io.EOF) {
				return out, nil
			}
			return nil, fmt.Errorf("gows: decompress message: %w", err)
		}
	}
}
