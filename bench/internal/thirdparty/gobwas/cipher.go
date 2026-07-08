// Package gobwas vendors gobwas/ws's masking kernel for benchmark
// comparison purposes (bench/kernels_test.go). PR #198 reported ~16.8 GB/s
// @4KB for this implementation on the reference hardware of the era; that
// figure is re-measured here rather than assumed (see AC4 in the plan).
//
// Source: github.com/gobwas/ws@v1.4.0, cipher.go, func Cipher and var remain.
// License: MIT (Sergey Kamardin).
// https://github.com/gobwas/ws/blob/v1.4.0/LICENSE
package gobwas

import "encoding/binary"

// remain maps position in masking key [0,4) to number of bytes that need to
// be processed manually inside Cipher().
var remain = [4]int{0, 3, 2, 1}

// Cipher is a verbatim copy of gobwas/ws's exported ws.Cipher. It applies an
// XOR cipher to payload using mask; offset allows resuming a chunked cipher
// (e.g. across multiple io.Reader calls) at the correct rotation.
func Cipher(payload []byte, mask [4]byte, offset int) {
	n := len(payload)
	if n < 8 {
		for i := 0; i < n; i++ {
			payload[i] ^= mask[(offset+i)%4]
		}
		return
	}

	// Calculate position in mask due to previously processed bytes number.
	mpos := offset % 4
	// Count number of bytes will processed one by one from the beginning of payload.
	ln := remain[mpos]
	// Count number of bytes will processed one by one from the end of payload.
	// This is done to process payload by 16 bytes in each iteration of main loop.
	rn := (n - ln) % 16

	for i := 0; i < ln; i++ {
		payload[i] ^= mask[(mpos+i)%4]
	}
	for i := n - rn; i < n; i++ {
		payload[i] ^= mask[(mpos+i)%4]
	}

	// NOTE: we use here binary.LittleEndian regardless of what is real
	// endianness on machine is. To do so, we have to use binary.LittleEndian in
	// the masking loop below as well.
	var (
		m  = binary.LittleEndian.Uint32(mask[:])
		m2 = uint64(m)<<32 | uint64(m)
	)
	// Skip already processed right part.
	// Get number of uint64 parts remaining to process.
	n = (n - ln - rn) >> 4
	j := ln
	for i := 0; i < n; i++ {
		chunk := payload[j : j+16]
		p := binary.LittleEndian.Uint64(chunk) ^ m2
		p2 := binary.LittleEndian.Uint64(chunk[8:]) ^ m2
		binary.LittleEndian.PutUint64(chunk, p)
		binary.LittleEndian.PutUint64(chunk[8:], p2)
		j += 16
	}
}
