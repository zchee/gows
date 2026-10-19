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

// Command autobahn runs the window-9 flatekp Autobahn feature profile.
package main

import (
	"os"

	"github.com/zchee/gows"
	"github.com/zchee/gows/internal/autobahnapp"

	"github.com/zchee/gows/flatekp"
)

const windowBits = 9

// featureConfig returns the profile for both directions. The agent name only
// reaches the wire in client mode, where the app reports its results to the
// fuzzingserver; in server mode the fuzzingclient's own configuration names
// the agent, so one client name serves both.
func featureConfig() autobahnapp.Config {
	return autobahnapp.Config{
		AgentName: "gows-v04-feature-client",
		Upgrader: gows.Upgrader{
			EnableCompression:    true,
			AllowContextTakeover: true,
			NegotiateWindowBits:  true,
			ClientWindowBits:     windowBits,
		},
		Dialer: gows.Dialer{
			EnableCompression:        true,
			AllowContextTakeover:     true,
			ServerWindowBits:         windowBits,
			OfferClientMaxWindowBits: true,
		},
	}
}

func main() {
	if err := gows.SetDeflateBackend(flatekp.Backend(), 6, windowBits); err != nil {
		panic(err)
	}
	os.Exit(autobahnapp.Run(os.Args[1:], featureConfig(), os.Stderr))
}
