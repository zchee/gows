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
	"io"
	"os"

	"github.com/zchee/gows/autobahn/reporttxn"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

// run performs the operation named by args[0] and returns the process exit
// code: 2 for a usage error, 1 when the operation fails, 0 on success.
func run(args []string, stderr io.Writer) int {
	if len(args) != 3 {
		fmt.Fprintln(stderr, "usage: reportctl backup|publish|restore <source> <destination>")
		return 2
	}
	var err error
	switch args[0] {
	case "backup":
		err = reporttxn.Backup(args[1], args[2])
	case "publish":
		err = reporttxn.Publish(args[1], args[2])
	case "restore":
		err = reporttxn.Restore(args[1], args[2])
	default:
		fmt.Fprintf(stderr, "reportctl: unknown operation %q\n", args[0])
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, "reportctl:", err)
		return 1
	}
	return 0
}
