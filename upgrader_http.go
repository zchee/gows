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
	"fmt"
	"net"
	"net/http"

	"github.com/zchee/gows/internal/extension"
	"github.com/zchee/gows/internal/httpx"
)

// UpgradeHTTP performs the server side of a WebSocket opening handshake
// on top of an in-flight net/http request, using the zero-value
// [Upgrader] (no subprotocols, no Origin check). It is a convenience
// equivalent to (&Upgrader{}).UpgradeHTTP(w, r).
func UpgradeHTTP(w http.ResponseWriter, r *http.Request) (net.Conn, Handshake, error) {
	var u Upgrader
	return u.UpgradeHTTP(w, r)
}

// UpgradeHTTP performs the server side of a WebSocket opening handshake
// (RFC 6455 §4.2) from within a net/http handler, for callers that need
// to sit behind the rest of net/http's routing, middleware, and TLS
// handling rather than owning a raw net.Conn directly (see
// [Upgrader.Upgrade] for that path).
//
// Unlike [Upgrader.Upgrade], UpgradeHTTP validates the request using the
// already-parsed r.Method, r.Header, and r.URL, which necessarily
// allocates (e.g. converting header values to []byte for reuse with the
// internal/httpx helpers); this is the accepted cost of interoperating
// with net/http. [Upgrader.MaxHeaderBytes] and [Upgrader.RawPath] have no
// effect here: header block size is already bounded by net/http's own
// http.Server.MaxHeaderBytes, and Handshake.Path/Query always come from
// the already-allocated r.URL.
//
// UpgradeHTTP hijacks the connection via
// [http.ResponseController.Hijack], which fails (and so does
// UpgradeHTTP) if the underlying http.ResponseWriter does not support
// hijacking, e.g. an HTTP/2 request. Any bytes net/http had already
// buffered from the client past the request headers (e.g. a pipelined
// first WebSocket frame) are copied out and returned as
// Handshake.Buffered; see [Handshake] for the contract a caller building
// a Conn on top of the returned net.Conn must follow.
func (u *Upgrader) UpgradeHTTP(w http.ResponseWriter, r *http.Request) (net.Conn, Handshake, error) {
	if err := u.validateClientWindowBits(); err != nil {
		return nil, Handshake{}, err
	}
	if r.Method != http.MethodGet {
		http.Error(w, "gows: method is not GET", http.StatusBadRequest)
		return nil, Handshake{}, ErrNotUpgrade
	}
	if !httpx.ContainsToken([]byte(r.Header.Get("Upgrade")), "websocket") {
		http.Error(w, "gows: Upgrade header does not contain \"websocket\"", http.StatusBadRequest)
		return nil, Handshake{}, ErrNotUpgrade
	}
	if !httpx.ContainsToken([]byte(r.Header.Get("Connection")), "upgrade") {
		http.Error(w, "gows: Connection header does not contain \"upgrade\"", http.StatusBadRequest)
		return nil, Handshake{}, ErrNotConnectionUpgrade
	}
	if r.Header.Get("Sec-WebSocket-Version") != "13" {
		w.Header().Set("Sec-WebSocket-Version", "13")
		http.Error(w, "gows: Sec-WebSocket-Version is not 13", http.StatusUpgradeRequired)
		return nil, Handshake{}, ErrUnsupportedVersion
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if len(key) != 24 {
		http.Error(w, "gows: missing or invalid Sec-WebSocket-Key", http.StatusBadRequest)
		return nil, Handshake{}, ErrMissingKey
	}
	if u.OriginCheck != nil {
		var origin []byte
		if v := r.Header.Get("Origin"); v != "" {
			origin = []byte(v)
		}
		if !u.OriginCheck(origin) {
			http.Error(w, "gows: Origin rejected", http.StatusForbidden)
			return nil, Handshake{}, ErrOriginRejected
		}
	}

	selected := ""
	if clientProtocols := r.Header.Get("Sec-WebSocket-Protocol"); len(u.Subprotocols) > 0 && clientProtocols != "" {
		selected = negotiateSubprotocol(u.Subprotocols, []byte(clientProtocols))
	}

	var deflateParams extension.DeflateParams
	var clientWindowBitsHint int
	var deflateOK bool
	if u.EnableCompression {
		if extValue := r.Header.Get("Sec-WebSocket-Extensions"); extValue != "" {
			deflateParams, clientWindowBitsHint, deflateOK = negotiateDeflateWithHint([]byte(extValue), u.NegotiateWindowBits, u.AllowContextTakeover, u.ClientWindowBits)
		}
	}

	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		http.Error(w, "gows: hijack: "+err.Error(), http.StatusInternalServerError)
		return nil, Handshake{}, fmt.Errorf("gows: hijack: %w", err)
	}

	var buffered []byte
	if n := brw.Reader.Buffered(); n > 0 {
		peeked, _ := brw.Reader.Peek(n) // Peek(Buffered()) always succeeds.
		buffered = append([]byte(nil), peeked...)
	}

	resp := appendSwitchingProtocolsResponse(make([]byte, 0, 160+len(selected)), []byte(key), selected, deflateParams, deflateOK)
	if _, werr := conn.Write(resp); werr != nil {
		conn.Close()
		return nil, Handshake{}, werr
	}

	hs := Handshake{
		Path:        r.URL.Path,
		Query:       r.URL.RawQuery,
		Subprotocol: selected,
		Buffered:    buffered,
		Compressed:  deflateOK,
	}
	if deflateOK {
		hs.CompressionParams = compressionParamsFromDeflate(deflateParams)
		if u.TrustClientWindowBitsHint && deflateParams.ClientMaxWindowBits == 0 {
			hs.CompressionParams.ClientMaxWindowBitsHint = clientWindowBitsHint
		}
	}
	return conn, hs, nil
}
