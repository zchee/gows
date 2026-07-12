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
	"strings"

	"github.com/zchee/gows"
	"github.com/zchee/gows/flatekp"
	"github.com/zchee/gows/internal/autobahnapp"
)

const windowBits = 9

func featureConfig(mode string) autobahnapp.Config {
	name := "gows-v04-feature-client"
	if mode == "server" {
		name = "gows-v04-feature-server"
	}
	return autobahnapp.Config{
		AgentName: name,
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
	mode := modeFromArgs(os.Args[1:])
	if err := gows.SetDeflateBackend(flatekp.Backend(), 6, windowBits); err != nil {
		panic(err)
	}
	os.Exit(autobahnapp.Run(os.Args[1:], featureConfig(mode), os.Stdout, os.Stderr))
}

func modeFromArgs(args []string) string {
	for i, arg := range args {
		if strings.HasPrefix(arg, "-mode=") {
			return strings.TrimPrefix(arg, "-mode=")
		}
		if arg == "-mode" && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}
