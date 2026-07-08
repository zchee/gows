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

package mask

import (
	"bytes"
	"testing"
)

// FuzzMask differentially fuzzes the size-dispatching Mask entry point and
// every available kernel against the longhand reference. Any payload/key that
// produces a differing transform or returned key is a crash.
func FuzzMask(f *testing.F) {
	seeds := []struct {
		b   []byte
		key uint32
	}{
		{nil, 0},
		{[]byte{}, 0xffffffff},
		{[]byte("h"), 0x01020304},
		{[]byte("hello, websocket"), 0x9e3779b1},
		{bytes.Repeat([]byte{0xa5}, 63), 0xdeadbeef},
		{bytes.Repeat([]byte{0x00}, 64), 0x80000001},
		{bytes.Repeat([]byte{0xff}, 255), 0x12345678},
		{bytes.Repeat([]byte{0x5a}, 4097), 0xcafebabe},
	}
	for _, s := range seeds {
		f.Add(s.b, s.key)
	}

	f.Fuzz(func(t *testing.T, b []byte, key uint32) {
		want := append([]byte(nil), b...)
		wantKey := maskRef(want, key)

		maskers := append([]NamedKernel{{Name: "dispatch", Fn: Mask}}, Kernels()...)
		for _, m := range maskers {
			got := append([]byte(nil), b...)
			gotKey := m.Fn(got, key)
			if gotKey != wantKey || !bytes.Equal(got, want) {
				t.Fatalf("kernel %s: len=%d key=%#08x mismatch\n got=% x key=%#08x\nwant=% x key=%#08x",
					m.Name, len(b), key, got, gotKey, want, wantKey)
			}
		}
	})
}
