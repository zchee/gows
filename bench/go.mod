module github.com/zchee/gows/bench

go 1.26

require (
	github.com/antlabs/quickws v0.2.2
	github.com/coder/websocket v1.8.15
	github.com/fasthttp/websocket v1.5.12
	github.com/gobwas/ws v1.4.0
	github.com/gorilla/websocket v1.5.3
	github.com/klauspost/compress v1.18.6
	github.com/lesismal/nbio v1.6.11
	github.com/lxzan/gws v1.9.1
	github.com/valyala/fasthttp v1.72.0
	github.com/zchee/gows v0.0.0
)

require (
	github.com/andybalholm/brotli v1.2.1 // indirect
	github.com/antlabs/wsutil v0.1.11 // indirect
	github.com/gobwas/httphead v0.1.0 // indirect
	github.com/gobwas/pool v0.2.1 // indirect
	github.com/lesismal/llib v1.2.3 // indirect
	github.com/savsgio/gotils v0.0.0-20240704082632-aef3928b8a38 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	golang.org/x/crypto v0.53.0 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
)

// gows itself always measures the working tree, per bench/README.md.
replace github.com/zchee/gows => ../
