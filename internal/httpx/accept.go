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

package httpx

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
)

const (
	// acceptGUID is the fixed GUID concatenated onto the client key
	// before hashing, per RFC 6455 §1.3.
	acceptGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	// acceptKeyLen is the length of a valid Sec-WebSocket-Key value: the
	// base64 encoding of a 16-byte nonce, per RFC 6455 §4.1.
	acceptKeyLen = 24
	// acceptInputLen is the length of the SHA-1 input (client key +
	// GUID). At 60 bytes it fits within a single 64-byte SHA-1 block.
	acceptInputLen = acceptKeyLen + len(acceptGUID)
	// acceptEncodedLen is the base64-encoded length of a 20-byte SHA-1
	// digest.
	acceptEncodedLen = 28
)

// AppendAccept computes the Sec-WebSocket-Accept value for the given
// Sec-WebSocket-Key client key and appends its base64 encoding to dst,
// returning the extended buffer.
//
// AppendAccept assumes key is exactly 24 bytes, as validated by the
// caller (the upgrade paths reject any other length with a 400); it
// performs no length check and never returns an error. Passing a key of any other
// length does not panic, but produces an accept value with no defined
// meaning.
//
// AppendAccept performs no heap allocations of its own: the SHA-1 input
// is built in a fixed 60-byte stack array (24-byte key + 36-byte GUID,
// RFC 6455 §1.3) and the base64 encoding is computed into a fixed
// 28-byte stack array before being appended to dst. Appending to dst
// itself allocates only if dst lacks sufficient spare capacity, exactly
// as with [append].
func AppendAccept(dst, key []byte) []byte {
	var scratch [acceptInputLen]byte
	copy(scratch[:acceptKeyLen], key)
	copy(scratch[acceptKeyLen:], acceptGUID)

	sum := sha1.Sum(scratch[:])

	var enc [acceptEncodedLen]byte
	base64.StdEncoding.Encode(enc[:], sum[:])
	return append(dst, enc[:]...)
}

// AppendKey generates a new random Sec-WebSocket-Key client handshake
// value: 16 cryptographically random bytes, base64-encoded per RFC 6455
// §4.1, appended to dst.
//
// Unlike [AppendAccept], AppendKey is not allocation-free: it reads fresh
// entropy from crypto/rand on every call. This is expected to be
// acceptable, since a client generates at most one key per handshake, not
// on a steady-state hot path.
func AppendKey(dst []byte) []byte {
	var nonce [16]byte
	_, _ = rand.Read(nonce[:])
	var enc [acceptKeyLen]byte
	base64.StdEncoding.Encode(enc[:], nonce[:])
	return append(dst, enc[:]...)
}
