// Package gorilla vendors gorilla/websocket's unexported masking kernel for
// benchmark comparison purposes (bench/kernels_test.go).
//
// Source: github.com/gorilla/websocket@v1.5.3, mask.go, func maskBytes.
// License: BSD-2-Clause (Gorilla WebSocket Authors).
// https://github.com/gorilla/websocket/blob/v1.5.3/LICENSE
package gorilla

import "unsafe"

const wordSize = int(unsafe.Sizeof(uintptr(0)))

// MaskBytes is a verbatim copy of gorilla/websocket's unexported maskBytes,
// renamed for exported use. Behavior, including its unsafe pointer
// arithmetic, is unchanged from upstream.
func MaskBytes(key [4]byte, pos int, b []byte) int {
	// Mask one byte at a time for small buffers.
	if len(b) < 2*wordSize {
		for i := range b {
			b[i] ^= key[pos&3]
			pos++
		}
		return pos & 3
	}

	// Mask one byte at a time to word boundary.
	if n := int(uintptr(unsafe.Pointer(&b[0]))) % wordSize; n != 0 {
		n = wordSize - n
		for i := range b[:n] {
			b[i] ^= key[pos&3]
			pos++
		}
		b = b[n:]
	}

	// Create aligned word size key.
	var k [wordSize]byte
	for i := range k {
		k[i] = key[(pos+i)&3]
	}
	kw := *(*uintptr)(unsafe.Pointer(&k))

	// Mask one word at a time.
	n := (len(b) / wordSize) * wordSize
	for i := 0; i < n; i += wordSize {
		*(*uintptr)(unsafe.Pointer(uintptr(unsafe.Pointer(&b[0])) + uintptr(i))) ^= kw
	}

	// Mask one byte at a time for remaining bytes.
	b = b[n:]
	for i := range b {
		b[i] ^= key[pos&3]
		pos++
	}

	return pos & 3
}
