module github.com/zchee/gows/flatekp

go 1.26

require (
	github.com/klauspost/compress v1.19.0
	github.com/zchee/gows v0.1.0
)

// This module is published on its own tag and must resolve gows from the
// module proxy, so there is no replace directive here. To build against
// the working tree instead, run from this directory:
//
//	go mod edit -replace github.com/zchee/gows=../ && go test -mod=mod ./...
//
// and drop the edit before committing. CI does exactly that so a change to
// the root module is tested here before it is tagged.
