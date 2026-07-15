// Command benchdoc verifies or regenerates the machine-owned metadata tables
// in bench/README.md.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/zchee/gows/bench/harness/doccheck"
)

func main() {
	write := flag.Bool("write", false, "atomically regenerate the generated README sections")
	flag.Parse()
	benchRoot, err := os.Getwd()
	if err != nil {
		fatal(err)
	}
	readme := filepath.Join(benchRoot, "README.md")
	if *write {
		err = doccheck.WriteREADME(benchRoot, readme)
	} else {
		err = doccheck.CheckREADME(benchRoot, readme)
	}
	if err != nil {
		fatal(err)
	}
	mode := "current"
	if *write {
		mode = "regenerated"
	}
	fmt.Printf("benchdoc: generated metadata is %s\n", mode)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "benchdoc:", err)
	os.Exit(1)
}
