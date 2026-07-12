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

// Command autobahn is the canonical gows side of the Autobahn|Testsuite gate.
package main

import (
	"os"

	"github.com/zchee/gows"
	"github.com/zchee/gows/internal/autobahnapp"
)

func main() {
	os.Exit(autobahnapp.Run(os.Args[1:], autobahnapp.Config{
		AgentName: "gows",
		Upgrader:  gows.Upgrader{EnableCompression: true},
		Dialer:    gows.Dialer{EnableCompression: true},
	}, os.Stdout, os.Stderr))
}
