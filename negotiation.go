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
	"strings"

	"github.com/zchee/gows/internal/extension"
	"github.com/zchee/gows/internal/httpx"
)

// ParseCompression validates the actual Sec-WebSocket-Extensions response
// against the request offer and returns the negotiated parameters. Each slice
// element is one header line; neither input is retained. The boolean reports
// whether permessage-deflate was negotiated. A response without extensions
// returns false and no error, including when compression was offered.
//
// Unsupported, unsolicited, duplicated, or malformed response extensions return
// an error wrapping ErrInvalidCompressionResponse. Multiple alternative offers
// are supported; the response must match at least one valid offer. Returned
// parameters describe the response, not a client's self-imposed offer ceiling.
func ParseCompression(offer, response []string) (CompressionParams, bool, error) {
	responseBytes := []byte(strings.Join(response, ","))
	sc := extension.NewOfferScanner(responseBytes)
	found := false
	for sc.Next() {
		if found || !httpx.EqualFold(sc.Name(), extension.DeflateExtensionName) {
			return CompressionParams{}, false, ErrInvalidCompressionResponse
		}
		found = true
	}
	if !found {
		return CompressionParams{}, false, nil
	}

	var lastErr error = extension.ErrDeflateInvalidResponse
	for _, line := range offer {
		sc := extension.NewOfferScanner([]byte(line))
		for sc.Next() {
			if !httpx.EqualFold(sc.Name(), extension.DeflateExtensionName) {
				continue
			}
			offered, ok := extension.ParseDeflateOfferParams(sc.Params())
			if !ok {
				continue
			}
			agreed, err := extension.ValidateDeflateResponse(offered, responseBytes)
			if err != nil {
				lastErr = err
				continue
			}
			// These server-side limits must be accepted explicitly, unlike the
			// advisory client window and client context-takeover offer flags.
			if offered.ServerNoContextTakeover && !agreed.ServerNoContextTakeover || offered.ServerMaxWindowBits != 0 && agreed.ServerMaxWindowBits == 0 {
				lastErr = extension.ErrDeflateInvalidResponse
				continue
			}
			return compressionParamsFromDeflate(agreed), true, nil
		}
	}
	return CompressionParams{}, false, fmt.Errorf("%w: %w", ErrInvalidCompressionResponse, lastErr)
}
