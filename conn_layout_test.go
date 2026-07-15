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
	"testing"
	"unsafe"
)

// cacheLine is the M-series (Apple Silicon) L1 data cache line size the Conn
// field layout is packed against.
const cacheLine = 128

// TestConnFieldLayout pins the cache-line packing of Conn:
// the read-hot working set fits in the first 128-byte line, the write block
// starts on the next 128-byte boundary, and compression-only scratch is pushed
// off both hot lines. It is a layout guard, not a behavioral test: it fails if a
// future field reorder silently regresses the packing.
func TestConnFieldLayout(t *testing.T) {
	var c Conn

	// The write block must start exactly on the second 128B cache line so a
	// concurrent writer's mutex and scratch never share a line with the reader's
	// working set.
	if off := unsafe.Offsetof(c.wmu); off != cacheLine {
		t.Errorf("wmu (write block start) at offset %d, want %d (fresh 128B boundary)", off, cacheLine)
	}
	if off := unsafe.Offsetof(c.wmu); off%cacheLine != 0 {
		t.Errorf("wmu at offset %d, not on a 128B boundary", off)
	}

	// Every read-hot field must lie wholly within the first 128B line.
	readHot := []struct {
		name      string
		off, size uintptr
	}{
		{"conn", unsafe.Offsetof(c.conn), unsafe.Sizeof(c.conn)},
		{"rbuf", unsafe.Offsetof(c.rbuf), unsafe.Sizeof(c.rbuf)},
		{"r0", unsafe.Offsetof(c.r0), unsafe.Sizeof(c.r0)},
		{"r1", unsafe.Offsetof(c.r1), unsafe.Sizeof(c.r1)},
		{"hdrTable", unsafe.Offsetof(c.hdrTable), unsafe.Sizeof(c.hdrTable)},
		{"readLimit", unsafe.Offsetof(c.readLimit), unsafe.Sizeof(c.readLimit)},
		{"readErr", unsafe.Offsetof(c.readErr), unsafe.Sizeof(c.readErr)},
		{"msgReader", unsafe.Offsetof(c.msgReader), unsafe.Sizeof(c.msgReader)},
		{"msgBuf", unsafe.Offsetof(c.msgBuf), unsafe.Sizeof(c.msgBuf)},
		{"hdrMaskBit", unsafe.Offsetof(c.hdrMaskBit), unsafe.Sizeof(c.hdrMaskBit)},
		{"client", unsafe.Offsetof(c.client), unsafe.Sizeof(c.client)},
		{"vectored", unsafe.Offsetof(c.vectored), unsafe.Sizeof(c.vectored)},
		{"skipUTF8", unsafe.Offsetof(c.skipUTF8), unsafe.Sizeof(c.skipUTF8)},
		{"msgIsText", unsafe.Offsetof(c.msgIsText), unsafe.Sizeof(c.msgIsText)},
		{"msgCompressed", unsafe.Offsetof(c.msgCompressed), unsafe.Sizeof(c.msgCompressed)},
		{"utf8v", unsafe.Offsetof(c.utf8v), unsafe.Sizeof(c.utf8v)},
	}
	for _, f := range readHot {
		if f.off+f.size > cacheLine {
			t.Errorf("read-hot field %s spans [%d,%d), past the first %dB line", f.name, f.off, f.off+f.size, cacheLine)
		}
	}

	// conn must be first so the hottest transport pointer is at the line head.
	if off := unsafe.Offsetof(c.conn); off != 0 {
		t.Errorf("conn at offset %d, want 0", off)
	}

	// Compression-only scratch must sit below both hot lines (off the write
	// block core), never within the first 128B read line.
	cold := []struct {
		name string
		off  uintptr
	}{
		{"wcomp", unsafe.Offsetof(c.wcomp)},
		{"wslice", unsafe.Offsetof(c.wslice)},
		{"inflateBuf", unsafe.Offsetof(c.inflateBuf)},
		{"deflate", unsafe.Offsetof(c.deflate)},
		{"outgoingWindowCeil", unsafe.Offsetof(c.outgoingWindowCeil)},
	}
	writeCoreEnd := unsafe.Offsetof(c.tornDown)
	for _, f := range cold {
		if f.off < cacheLine {
			t.Errorf("cold field %s at offset %d, want >= %d (off the read line)", f.name, f.off, cacheLine)
		}
		if f.off < writeCoreEnd {
			t.Errorf("cold field %s at offset %d, want after the write-core end %d", f.name, f.off, writeCoreEnd)
		}
	}
}
