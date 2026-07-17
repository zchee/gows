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

// Package gows implements the WebSocket protocol defined in RFC 6455,
// including the permessage-deflate compression extension defined in
// RFC 7692, using only the standard library.
//
// The package supports both endpoint roles. A server accepts an HTTP
// upgrade with [Upgrade] or [UpgradeHTTP] (or a configured [Upgrader])
// and wraps the underlying [net.Conn] with [NewServerConn]; a client
// establishes a connection with [Dial] (or a configured [Dialer]) and
// wraps it with [NewClientConn].
//
// A [Conn] exchanges messages either whole, with [Conn.ReadMessage] and
// [Conn.WriteMessage], or as streams, with [Conn.NextReader] and
// [Conn.NextWriter]. [Conn.Serve] runs a single-goroutine callback loop
// that drains every complete buffered message per wakeup and, combined
// with [Conn.WriteMessageBuffered] and [Conn.Flush], coalesces replies
// into a single write. A [PreparedMessage] encodes a payload once for
// broadcast across many connections. The frame-level primitives
// ([Header], [DecodeHeader], [AppendHeader]) are exported for callers
// that need to process frames directly.
//
// permessage-deflate is negotiated through the EnableCompression fields
// of [Upgrader] and [Dialer] and enabled per connection with
// [WithCompression] or [WithCompressionParams]. The compressor backend
// is pluggable via [SetDeflateBackend]; the default is the standard
// library's compress/flate, and an optional klauspost/compress backend
// ships in the separate flatekp module so the root module stays free of
// third-party dependencies.
//
// The implementation targets strict RFC conformance (validated against
// the full Autobahn|Testsuite matrix in both directions) and high
// throughput: frame masking and UTF-8 validation dispatch to SIMD
// kernels at runtime, reads are allocation-free steady-state, and the
// handshake path can operate zero-copy.
package gows
