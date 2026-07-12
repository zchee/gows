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

// Command reportctl safely backs up, publishes, and restores Autobahn reports.
package main

import (
	"fmt"
	"os"

	"github.com/zchee/gows/autobahn/reporttxn"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: reportctl backup|publish|restore <source> <destination>")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "backup":
		err = reporttxn.Backup(os.Args[2], os.Args[3])
	case "publish":
		err = reporttxn.Publish(os.Args[2], os.Args[3])
	case "restore":
		err = reporttxn.Restore(os.Args[2], os.Args[3])
	default:
		fmt.Fprintf(os.Stderr, "reportctl: unknown operation %q\n", os.Args[1])
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "reportctl:", err)
		os.Exit(1)
	}
}
