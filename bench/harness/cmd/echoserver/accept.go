package main

import (
	"log"
	"net"
	"os"
	"runtime/trace"
	"sync"
	"time"
)

// serverConfig carries the per-run echoserver configuration derived from the
// command-line flags plus any gows read-buffer variant selected by -lib. Its
// zero value reproduces the historical defaults, so every backend behaves
// byte-identically when the new flags are unset.
type serverConfig struct {
	// readBufSize is the gows read-buffer size in bytes; 0 selects gows's
	// own default. It is meaningful only for the gows family (see
	// gowsVariants); other backends ignore it.
	readBufSize int
	// skipUTF8 opts gows out of UTF-8 validation; meaningful only for gows.
	skipUTF8 bool
	// notsentLowat is the TCP_NOTSENT_LOWAT value (bytes) applied to every
	// accepted connection before the WebSocket upgrade; 0 disables it.
	notsentLowat int
	// tracer is non-nil only when -trace-file is set, in which case the first
	// accepted connection arms a one-shot runtime/trace capture.
	tracer *traceController
}

// hooked reports whether cfg requires the accept path to be wrapped. When it
// returns false, newListener hands back the bare listener so the default path
// allocates nothing extra and spawns no goroutine.
func (c serverConfig) hooked() bool {
	return c.notsentLowat > 0 || c.tracer != nil
}

// newListener opens a TCP listener on addr and, when cfg requires it, wraps it
// so every accepted connection passes through the cross-cutting accept hooks:
// the TCP_NOTSENT_LOWAT socket option (hypothesis H5) and the one-shot
// runtime/trace trigger (hypothesis H3). Backends that obtain their listener
// through this helper (gows and gobwas via a raw accept loop, and gorilla,
// coder, and quickws via serveHTTP) therefore share a single accept-wrapping
// point. The gws, nbio, and fasthttp backends manage their listeners inside
// the library (gws.Server.Run, nbhttp.Engine, fasthttp.Server.ListenAndServe)
// and so are not wrapped; the H3/H5 experiments only exercise gows and
// quickws, both of which route through here.
func newListener(addr string, cfg serverConfig) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	if !cfg.hooked() {
		return ln, nil
	}
	return &hookListener{Listener: ln, cfg: cfg}, nil
}

// hookListener applies the run's cross-cutting accept hooks to each accepted
// connection. It is created only when serverConfig.hooked reports true.
type hookListener struct {
	net.Listener
	cfg          serverConfig
	lowatLogOnce sync.Once
}

// Accept accepts one connection, applies TCP_NOTSENT_LOWAT when configured
// (logging the effective value exactly once, off any message hot path), and
// arms the runtime/trace capture on the first connection when a tracer is set.
func (l *hookListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if l.cfg.notsentLowat > 0 {
		setErr := setNotsentLowat(conn, l.cfg.notsentLowat)
		l.lowatLogOnce.Do(func() {
			if setErr != nil {
				log.Printf("echoserver: TCP_NOTSENT_LOWAT=%d apply failed: %v", l.cfg.notsentLowat, setErr)
				return
			}
			readback, getErr := getNotsentLowat(conn)
			if getErr != nil {
				log.Printf("echoserver: TCP_NOTSENT_LOWAT set to %d bytes; read-back failed: %v", l.cfg.notsentLowat, getErr)
				return
			}
			log.Printf("echoserver: TCP_NOTSENT_LOWAT set to %d bytes (read back %d) on accepted connections", l.cfg.notsentLowat, readback)
		})
	}
	if l.cfg.tracer != nil {
		l.cfg.tracer.onAccept()
	}
	return conn, nil
}

// traceController performs a single runtime/trace capture over the lifetime of
// the process: the first accepted connection arms it, capture begins after
// delay and runs for duration. All fields are set at construction; onAccept is
// safe to call from every accepted connection because the capture is guarded
// by a sync.Once.
type traceController struct {
	path     string
	delay    time.Duration
	duration time.Duration
	once     sync.Once
}

// newTraceController builds a controller that writes a runtime/trace to path,
// starting delay after the first connection and running for duration.
func newTraceController(path string, delay, duration time.Duration) *traceController {
	return &traceController{path: path, delay: delay, duration: duration}
}

// onAccept arms the capture on its first call and is a no-op thereafter, so a
// process captures at most one trace regardless of how many connections
// arrive.
func (t *traceController) onAccept() {
	t.once.Do(func() { go t.capture() })
}

// capture waits out the delay, records a runtime/trace to the configured path
// for the configured duration, then stops. Failures are logged (stderr, off
// the hot path) rather than aborting the server, since a benchmark run should
// keep serving even if trace capture cannot start.
func (t *traceController) capture() {
	if t.delay > 0 {
		time.Sleep(t.delay)
	}
	f, err := os.Create(t.path)
	if err != nil {
		log.Printf("echoserver: trace: create %s: %v", t.path, err)
		return
	}
	defer f.Close()
	if err := trace.Start(f); err != nil {
		log.Printf("echoserver: trace: start: %v", err)
		return
	}
	log.Printf("echoserver: trace: started -> %s for %s", t.path, t.duration)
	time.Sleep(t.duration)
	trace.Stop()
	log.Printf("echoserver: trace: stopped -> %s", t.path)
}
