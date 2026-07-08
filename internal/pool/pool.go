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

// Package pool provides an allocation-minimizing byte-slice pool keyed by
// power-of-two size classes, following the size-classed [sync.Pool] model
// used by high-throughput WebSocket implementations such as lxzan/gws.
//
// Buffers are pooled in classes from 128B (2^7) to 256KB (2^18) inclusive.
// [Get] returns a zero-length slice whose capacity is at least the
// requested size, drawn from the smallest class that satisfies it.
// Requests larger than 256KB bypass the pool and allocate directly. [Put]
// only accepts buffers whose capacity exactly matches one of the pooled
// classes; anything else is dropped for the garbage collector to reclaim.
package pool

import (
	"math/bits"
	"sync"
)

const (
	// minClassShift is the exponent of the smallest pooled size class
	// (128B = 2^7).
	minClassShift = 7
	// maxClassShift is the exponent of the largest pooled size class
	// (256KB = 2^18).
	maxClassShift = 18
	// minClassSize is the smallest pooled buffer capacity, in bytes.
	minClassSize = 1 << minClassShift
	// maxClassSize is the largest pooled buffer capacity, in bytes.
	// Requests larger than this bypass the pool entirely.
	maxClassSize = 1 << maxClassShift
	// numClasses is the number of power-of-two size classes managed by
	// the pool.
	numClasses = maxClassShift - minClassShift + 1
)

// classes holds one [sync.Pool] per power-of-two size class, indexed by
// class number (0 == minClassSize, numClasses-1 == maxClassSize). Each
// pool stores *[]byte rather than []byte: a pointer value fits directly
// in the interface data word, so passing it through sync.Pool's any-typed
// Get/Put does not box a fresh copy on the heap the way passing a slice
// header (a 3-word struct) by value would.
var classes [numClasses]sync.Pool

// wrapperPool recycles the *[]byte header objects used to move buffers
// through classes, so that Put does not need to allocate a new pointer
// wrapper on every call.
var wrapperPool = sync.Pool{
	New: func() any { return new([]byte) },
}

// classIndex returns the size-class index that can satisfy a request of n
// bytes, and reports whether n falls within the pooled range (n <=
// maxClassSize).
func classIndex(n int) (idx int, ok bool) {
	if n > maxClassSize {
		return 0, false
	}
	if n <= minClassSize {
		return 0, true
	}
	// Ceil log2(n): the smallest shift s such that 1<<s >= n.
	shift := bits.Len(uint(n - 1))
	return shift - minClassShift, true
}

// Get returns a zero-length slice with capacity of at least n, drawn from
// the smallest size class that satisfies n. Requests larger than 256KB
// allocate directly via make and are not pooled.
func Get(n int) []byte {
	idx, ok := classIndex(n)
	if !ok {
		return make([]byte, 0, n)
	}
	if v := classes[idx].Get(); v != nil {
		bp := v.(*[]byte)
		b := (*bp)[:0]
		*bp = nil
		wrapperPool.Put(bp)
		return b
	}
	return make([]byte, 0, 1<<(minClassShift+idx))
}

// Put returns b to the pool for reuse by a future [Get] call. Only
// buffers whose capacity exactly matches one of the power-of-two size
// classes (128B-256KB inclusive) are retained; buffers with a larger,
// smaller, or non-power-of-two capacity are dropped and left for the
// garbage collector.
func Put(b []byte) {
	c := cap(b)
	if c < minClassSize || c > maxClassSize || c&(c-1) != 0 {
		return
	}
	idx := bits.Len(uint(c)) - 1 - minClassShift
	bp := wrapperPool.Get().(*[]byte)
	*bp = b[:c]
	classes[idx].Put(bp)
}
