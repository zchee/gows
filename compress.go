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
	"bytes"
	"compress/flate"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/zchee/gows/internal/pool"
)

// inflateChunkSize is the scratch read size [Conn.decompressMessage]
// uses per [DeflateReader.Read] call while inflating a compressed
// message.
const inflateChunkSize = 4096

// deflateFlushTail is the 4-byte DEFLATE sync-flush marker (RFC 7692
// §7.2.1) that [DeflateWriter.Flush] always appends to its output;
// compressPayload strips exactly these 4 trailing bytes before the
// result goes on the wire.
var deflateFlushTail = [4]byte{0x00, 0x00, 0xff, 0xff}

// deflateReadTail is what [tailReader] appends to a received message's
// compressed bytes before inflating -- RFC 7692 §7.2.2's mirror of
// deflateFlushTail, but 5 bytes longer. A bare 4-byte sync-flush marker
// decodes to the right bytes but leaves the underlying DEFLATE bitstream
// non-final (BFINAL=0): a [DeflateReader.Read] fed only those 4 bytes
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

// defaultDeflateBackend is compress.go's built-in permessage-deflate
// backend: stdlib compress/flate, restricted to the RFC 7692 default
// 32KB window ([deflateWindowBits]) since stdlib flate has no public API
// to compress at a smaller one (see .omc/research/compress-design.md
// §4) -- MinWindowBits == MaxWindowBits == 15 advertises exactly that.
// This is the active backend until (or unless) [SetDeflateBackend]
// installs a different one.
var defaultDeflateBackend = &DeflateBackend{
	Name: "compress/flate",
	NewWriter: func(level, windowBits int) (DeflateWriter, error) {
		if windowBits != deflateWindowBits {
			return nil, fmt.Errorf("gows: compress/flate backend only supports window bits %d, got %d", deflateWindowBits, windowBits)
		}
		w, err := flate.NewWriter(io.Discard, level)
		if err != nil {
			return nil, err
		}
		return w, nil
	},
	NewReader: func(windowBits int) DeflateReader {
		// flate.NewReader's returned io.ReadCloser also implements
		// flate.Resetter (Reset(io.Reader, []byte) error), a stable
		// stdlib guarantee this package relies on instead of
		// redeclaring the interface with an incompatible name. windowBits
		// is unused: stdlib's decompressor always allocates a full 32KB
		// window and needs no advance sizing hint.
		return flate.NewReader(bytes.NewReader(nil)).(DeflateReader)
	},
	MinLevel: flate.HuffmanOnly, MaxLevel: flate.BestCompression,
	MinWindowBits: deflateWindowBits, MaxWindowBits: deflateWindowBits,
}

// deflateConfig is one immutable snapshot of "what compress.go's
// compressor/decompressor pools actually do": a backend, the compression
// level and window bits it was installed with, and the two pools
// themselves. [SetDeflateBackend] builds a new deflateConfig and
// atomically swaps it in rather than mutating pool fields in place, so a
// compressPayload/decompressMessage call in flight never observes a pool
// whose New func was reassigned mid-use, and previously pooled
// writers/readers from an old backend are simply dropped (left for GC)
// instead of resurfacing from a Get call under the new configuration.
type deflateConfig struct {
	backend    *DeflateBackend
	level      int
	windowBits int
	writers    sync.Pool
	readers    sync.Pool
}

// newDeflateConfig builds a deflateConfig backed by b at level/windowBits,
// without validating them against b's advertised ranges -- callers
// (activeDeflate's init below, and [SetDeflateBackend]) are responsible
// for validating first.
func newDeflateConfig(b *DeflateBackend, level, windowBits int) *deflateConfig {
	cfg := &deflateConfig{backend: b, level: level, windowBits: windowBits}
	cfg.writers.New = func() any {
		w, err := b.NewWriter(level, windowBits)
		if err != nil {
			// SetDeflateBackend already validated level/windowBits
			// against b's MinLevel/MaxLevel/MinWindowBits/MaxWindowBits,
			// so a backend whose NewWriter still errors here is
			// violating its own advertised capability -- a backend bug,
			// not a caller one, and there is no sensible recovery for a
			// pool's New func other than to say so loudly.
			panic("gows: DeflateBackend " + b.Name + ".NewWriter: " + err.Error())
		}
		return w
	}
	cfg.readers.New = func() any { return b.NewReader(windowBits) }
	return cfg
}

// activeDeflate holds compress.go's process-global permessage-deflate
// configuration: which backend, compression level, and window bits every
// Conn in the process actually compresses/decompresses with, regardless
// of which [Upgrader] or [Dialer] negotiated that Conn's own handshake.
// See [SetDeflateBackend] for why this is a process-wide switch rather
// than a per-Conn one.
var activeDeflate atomic.Pointer[deflateConfig]

func init() {
	activeDeflate.Store(newDeflateConfig(defaultDeflateBackend, defaultDeflateLevel, deflateWindowBits))
}

// SetDeflateBackend installs b as the process-wide permessage-deflate
// backend: every subsequent [Conn.WriteMessage] compression and
// [Conn.ReadMessage] decompression in the process, for every Conn built
// by every [Upgrader]/[Dialer]/[NewServerConn]/[NewClientConn] call,
// immediately starts using b at level/windowBits -- not just Conns
// created afterward. Pooled writers/readers already borrowed from the
// previous backend are unaffected (they simply aren't returned to the
// new pool); a compress/decompress call already in flight when
// SetDeflateBackend runs always completes correctly, since it already
// holds a reference to whichever pooled value it borrowed before the
// swap.
//
// This is a process-wide setting, not a per-Upgrader/per-Dialer/per-Conn
// [ConnOption], because [Conn] itself has no per-connection backend,
// level, or window-bits state in this phase -- only a compression bool
// (see [WithCompression]) -- so compress.go's pools have nowhere to
// store a different configuration per connection; adding that is out of
// this phase's scope (see .omc/handoffs/project-status.md's deferred
// item 4, "context-takeover opt-in", which will need the same per-Conn
// state this seam deliberately isn't adding yet). [Upgrader.NegotiateWindowBits]
// and [Dialer.WindowBits] still exist as explicit, independent
// per-instance opt-ins: whether a *specific* Upgrader/Dialer negotiates
// (or offers) a non-default window size with its peers is a legitimate
// policy choice to make per handshake surface even though the actual
// compressor those connections end up sharing is process-wide -- see
// their docs. Keeping those two concerns separate also means an
// existing Upgrader/Dialer that never sets those fields keeps this
// package's original behavior byte-for-byte even after some other part
// of the same process calls SetDeflateBackend for an unrelated reason.
//
// level and windowBits must be within b's [DeflateBackend.MinLevel],
// [DeflateBackend.MaxLevel] and [DeflateBackend.MinWindowBits],
// [DeflateBackend.MaxWindowBits] ranges, or SetDeflateBackend returns an
// error and leaves the previously active backend in place.
func SetDeflateBackend(b *DeflateBackend, level, windowBits int) error {
	if b == nil {
		return errors.New("gows: SetDeflateBackend: nil backend")
	}
	if b.NewWriter == nil || b.NewReader == nil {
		return fmt.Errorf("gows: SetDeflateBackend: backend %q has a nil NewWriter or NewReader", b.Name)
	}
	if level < b.MinLevel || level > b.MaxLevel {
		return fmt.Errorf("gows: SetDeflateBackend: level %d outside backend %q's range [%d, %d]", level, b.Name, b.MinLevel, b.MaxLevel)
	}
	if windowBits < b.MinWindowBits || windowBits > b.MaxWindowBits {
		return fmt.Errorf("gows: SetDeflateBackend: window bits %d outside backend %q's range [%d, %d]", windowBits, b.Name, b.MinWindowBits, b.MaxWindowBits)
	}
	activeDeflate.Store(newDeflateConfig(b, level, windowBits))
	return nil
}

// currentDeflateWindowBits reports the window bits [SetDeflateBackend]'s
// active backend actually compresses at: [deflateWindowBits] (15) until
// or unless SetDeflateBackend installs a backend configured for less.
// negotiateDeflate and [Dialer]'s handshake consult this (gated by
// [Upgrader.NegotiateWindowBits]/[Dialer.WindowBits] respectively) to
// decide what window bits to accept or offer.
func currentDeflateWindowBits() int {
	return activeDeflate.Load().windowBits
}

// DefaultDeflateBackend returns compress.go's built-in permessage-deflate
// backend: stdlib compress/flate, fixed at the RFC 7692 default 32KB
// window -- the backend active before any [SetDeflateBackend] call.
// Pass it back to SetDeflateBackend (with [defaultDeflateLevel] and
// [deflateWindowBits], or any other level within its advertised range)
// to revert to stdlib after trying a different one; there is otherwise
// no way for a caller outside this package to reconstruct it, since
// gows's own default is not exported as a package-level value.
func DefaultDeflateBackend() *DeflateBackend {
	return defaultDeflateBackend
}

// deflateState holds a Conn's per-connection permessage-deflate (RFC 7692)
// context-takeover state: allocated only by [newDeflateState] when
// [WithCompressionParams] negotiates context takeover for at least one
// direction, nil otherwise, in which case compress.go's original pooled,
// no-context-takeover compressPayload/decompressMessage path applies with
// no per-Conn cost at all -- see [WithCompressionParams] for the real
// memory cost once this is non-nil.
//
// A deflateState pins the backend, level, and window bits it was built
// against at construction time (see newDeflateState); a later
// [SetDeflateBackend] call changes what newly constructed Conns use but
// never reaches back into an already-built deflateState, since its
// persistent compressor already exists and cannot be transplanted onto a
// different backend mid-life, and its sliding-window dictionary's
// capacity is fixed to the window bits negotiated for this connection.
type deflateState struct {
	windowBits int

	// outgoing is non-nil only when this Conn's own outgoing direction
	// negotiated context takeover: a persistent [DeflateWriter]
	// constructed once, here, and never Reset again for the Conn's life
	// -- only outgoingDst's target buffer is swapped per message (see
	// [Conn.compressMessage]), preserving the compressor's LZ77 window
	// across messages.
	outgoing    DeflateWriter
	outgoingDst *sliceWriter

	// incomingDict is non-nil only when this Conn's incoming direction
	// (the peer's own outgoing direction) negotiated context takeover: a
	// sliding window of up to 2^windowBits bytes of the most recently
	// decompressed plaintext, grown and capped by [Conn.decompressMessage]
	// after each message and passed as [DeflateReader.Reset]'s preset
	// dictionary -- see decompressMessage's doc for why this needs no
	// persistent reader object, unlike outgoing.
	incomingDict []byte
}

// newDeflateState builds the deflateState a Conn with the given role and
// negotiated [CompressionParams] needs, or returns nil if neither
// direction negotiated context takeover (in which case the caller must
// leave Conn.deflate nil, preserving this package's original,
// zero-per-Conn-state behavior exactly). It pins the process's currently
// active backend/level/window bits ([SetDeflateBackend]) for this Conn's
// entire lifetime -- seeing this Conn's own direction(s) is the one and
// only time a context-takeover Conn ever consults SetDeflateBackend's
// active configuration.
func newDeflateState(client bool, p CompressionParams) *deflateState {
	// Direction mapping (RFC 7692 §7.1.1): server_no_context_takeover
	// governs the server's own outgoing compression and, symmetrically,
	// the client's incoming decompression; client_no_context_takeover is
	// the mirror image. CompressionParams stores the inverted
	// (*ContextTakeover, true meaning takeover applies) sense.
	var outgoingTakeover, incomingTakeover bool
	if client {
		outgoingTakeover, incomingTakeover = p.ClientContextTakeover, p.ServerContextTakeover
	} else {
		outgoingTakeover, incomingTakeover = p.ServerContextTakeover, p.ClientContextTakeover
	}
	if !outgoingTakeover && !incomingTakeover {
		return nil
	}

	cfg := activeDeflate.Load()
	ds := &deflateState{windowBits: cfg.windowBits}
	if outgoingTakeover {
		w, err := cfg.backend.NewWriter(cfg.level, cfg.windowBits)
		if err != nil {
			// cfg is the process's already-validated active configuration
			// (SetDeflateBackend checked level/windowBits against this
			// exact backend's advertised range before it became active),
			// so a backend whose NewWriter still errors here is violating
			// its own advertised capability -- see newDeflateConfig's
			// identical panic for the same reasoning.
			panic("gows: DeflateBackend " + cfg.backend.Name + ".NewWriter: " + err.Error())
		}
		ds.outgoingDst = &sliceWriter{}
		// One-time Reset: establishes the persistent destination adapter
		// and a fresh window, correct for a brand-new connection that has
		// sent nothing yet. Never called again for this writer -- see
		// Conn.compressMessage.
		w.Reset(ds.outgoingDst)
		ds.outgoing = w
	}
	if incomingTakeover {
		ds.incomingDict = make([]byte, 0, 1<<cfg.windowBits)
	}
	return ds
}

// slideWindow appends add to dict, keeping only the trailing max bytes
// (dropping the oldest content first when that would exceed max) -- the
// sliding LZ77 history a context-takeover decompressor's next
// [DeflateReader.Reset] dict argument needs to resolve back-references
// into any message received so far, not just the most recent one. dict
// must have been allocated with cap(dict) == max (see newDeflateState),
// so appending never reallocates.
func slideWindow(dict, add []byte, max int) []byte {
	if len(add) >= max {
		return append(dict[:0], add[len(add)-max:]...)
	}
	total := len(dict) + len(add)
	if total <= max {
		return append(dict, add...)
	}
	drop := total - max
	n := copy(dict, dict[drop:])
	return append(dict[:n], add...)
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
// letting compressPayload capture a pooled [DeflateWriter]'s Flush
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
// bytes, without copying or mutating b: a [DeflateReader] reads through
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
// [DeflateWriter] (from the process's active [DeflateBackend]; see
// [SetDeflateBackend]) reset onto a fresh, empty LZ77 window
// (no-context-takeover), appends the result to dst[:0] (reusing its
// storage), strips the trailing 4-byte sync-flush marker Flush always
// emits, and returns the extended slice. It is compress.go's original,
// always-no-context-takeover entry point: [NewPreparedMessage] calls it
// directly (never [Conn.compressMessage]'s context-takeover branch),
// since a message precompressed once for broadcast to many connections
// must be compressed as if no-context-takeover were in effect regardless
// of any individual target connection's own negotiated context takeover
// -- a back-reference into one connection's private LZ77 window would be
// meaningless (or wrong) to a different connection's decompressor (see
// .omc/research/compress-design.md §6).
func compressPayload(dst, p []byte) ([]byte, error) {
	cfg := activeDeflate.Load()
	w := cfg.writers.Get().(DeflateWriter)
	defer cfg.writers.Put(w)

	sw := &sliceWriter{b: dst[:0]}
	w.Reset(sw)
	return writeAndFlush(w, sw, p)
}

// compressMessage is compressPayload's per-Conn counterpart, used by
// [Conn.WriteMessage]/writeFrameLocked instead of compressPayload
// directly. When c's own outgoing direction did not negotiate context
// takeover (c.deflate == nil or c.deflate.outgoing == nil -- this
// package's original, zero-per-Conn-state path and overwhelmingly the
// common case), it is identical to compressPayload: a pooled compressor,
// fresh window, no per-Conn cost. Otherwise it reuses c.deflate's
// persistent compressor instead, preserving the LZ77 window across
// messages exactly as RFC 7692 §7.2.3.2's worked example demonstrates
// (verified directly: compressing "Hello" twice through the same,
// never-Reset *compress/flate.Writer produces a strictly shorter second
// encoding than compressing it twice through two independent, freshly
// Reset writers, which produce identical-length output both times).
func (c *Conn) compressMessage(dst, p []byte) ([]byte, error) {
	if c.deflate == nil || c.deflate.outgoing == nil {
		return compressPayload(dst, p)
	}
	sw := c.deflate.outgoingDst
	sw.b = dst[:0]
	return writeAndFlush(c.deflate.outgoing, sw, p)
}

// writeAndFlush writes p to w, flushes the RFC 7692 §7.2.1 sync-flush
// marker, and returns sw's accumulated bytes with that trailing 4-byte
// marker stripped. Shared by compressPayload (pooled, freshly Reset onto
// sw immediately before this call) and compressMessage's
// context-takeover branch (persistent w, sw merely repointed at dst) --
// both need the identical Write+Flush+strip sequence once w and sw are
// ready; only how they got that way differs between the two callers.
func writeAndFlush(w DeflateWriter, sw *sliceWriter, p []byte) ([]byte, error) {
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
// 7692 §7.2.1 -- using a pooled [DeflateReader] (from the process's
// active [DeflateBackend]; see [SetDeflateBackend]) and [deflateReadTail]
// re-appended (§7.2.2), into c.inflateBuf (reused across messages, like
// c.msgBuf). Decompressed output is bounded by c.readLimit; exceeding it
// returns [errDecompressedTooLarge] instead of continuing to inflate an
// unbounded decompression bomb.
//
// When c's incoming direction negotiated context takeover, the reader is
// still borrowed from the shared pool exactly as in the no-context-takeover
// case -- unlike compressMessage's outgoing side, no persistent per-Conn
// [DeflateReader] is needed. Instead, Reset's dict parameter is given
// c.deflate.incomingDict, a sliding window of the most recently
// decompressed plaintext: per DEFLATE's own preset-dictionary mechanism,
// resetting a fresh decompressor with the correct preceding bytes as dict
// is exactly equivalent to a decompressor that stayed alive and never
// reset, for the purpose of resolving cross-message back-references --
// which pooled object services the request stops mattering once dict
// alone determines the effective window contents. (Verified against a
// live github.com/coder/websocket -- an Autobahn-tested implementation --
// whose own context-takeover decompressor takes exactly this shape:
// resetFlate's getFlateReader(r, dict) call, dict coming from a per-Conn
// slidingWindow, never a persistent reader object.) On a successful
// decode, decompressMessage grows incomingDict with this message's newly
// decompressed bytes, capped at the negotiated window size, for the next
// call to draw on.
func (c *Conn) decompressMessage(compressed []byte) ([]byte, error) {
	cfg := activeDeflate.Load()
	r := cfg.readers.Get().(DeflateReader)
	defer cfg.readers.Put(r)

	var ds *deflateState
	if c.deflate != nil && c.deflate.incomingDict != nil {
		ds = c.deflate
	}
	var dict []byte
	if ds != nil {
		dict = ds.incomingDict
	}

	tr := tailReader{b: compressed}
	if err := r.Reset(&tr, dict); err != nil {
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
				if ds != nil {
					ds.incomingDict = slideWindow(ds.incomingDict, out, 1<<ds.windowBits)
				}
				return out, nil
			}
			return nil, fmt.Errorf("gows: decompress message: %w", err)
		}
	}
}
