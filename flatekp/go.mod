module github.com/zchee/gows/flatekp

go 1.26

require (
	github.com/klauspost/compress v1.18.6
	github.com/zchee/gows v0.0.0
)

// gows itself is unpublished; flatekp always builds against the working
// tree, per bench/README.md's identical rationale for bench/go.mod.
replace github.com/zchee/gows => ../
