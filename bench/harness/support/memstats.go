package support

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/pprof"
	"runtime"
	"time"

	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
)

const debugRequestTimeout = 5 * time.Second

const maxDebugResponseBytes = 64 << 10

// MemSnapshot is the subset of runtime.MemStats the harness cares about for
// per-library allocation comparisons.
type MemSnapshot struct {
	Mallocs    uint64 `json:"mallocs"`
	Frees      uint64 `json:"frees"`
	TotalAlloc uint64 `json:"total_alloc"`
	HeapAlloc  uint64 `json:"heap_alloc"`
	NumGC      uint32 `json:"num_gc"`
	Goroutines int    `json:"goroutines"`
}

// ReadMemSnapshot captures the process's current runtime allocation counters.
func ReadMemSnapshot() MemSnapshot {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return MemSnapshot{
		Mallocs:    m.Mallocs,
		Frees:      m.Frees,
		TotalAlloc: m.TotalAlloc,
		HeapAlloc:  m.HeapAlloc,
		NumGC:      m.NumGC,
		Goroutines: runtime.NumGoroutine(),
	}
}

// StartDebugServer starts a plain net/http server on addr exposing
// GET /debug/memstats as JSON, plus the standard net/http/pprof handlers
// under /debug/pprof/ (e.g. "curl .../debug/pprof/profile?seconds=10" for a
// CPU profile of a losing config under load -- plan §8's regression-tuning
// evidence requirement). Both are intentionally isolated from every
// echoserver library implementation's hot path: runtime.ReadMemStats and
// profiling only run when this endpoint is polled/hit by loadgen or an
// operator, never on the per-message code path.
//
// It returns the *http.Server so the caller can Shutdown it; the caller is
// responsible for running Serve in a goroutine.
func StartDebugServer(addr string) (*http.Server, <-chan error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/memstats", func(w http.ResponseWriter, _ *http.Request) {
		snap := ReadMemSnapshot()
		w.Header().Set("Content-Type", "application/json")
		enc := jsontext.NewEncoder(w)
		_ = json.MarshalEncode(enc, snap)
	})
	mux.HandleFunc("/debug/rusage", func(w http.ResponseWriter, _ *http.Request) {
		usage := SelfRusage()
		w.Header().Set("Content-Type", "application/json")
		enc := jsontext.NewEncoder(w)
		_ = json.MarshalEncode(enc, usage)
	})
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	srv := &http.Server{Addr: addr, Handler: mux}
	errCh := make(chan error, 1)
	go func() {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			errCh <- err
			return
		}
		errCh <- srv.Serve(ln)
	}()
	return srv, errCh
}

// FetchMemSnapshot performs a GET against the /debug/memstats endpoint of an
// echoserver started with StartDebugServer.
func FetchMemSnapshot(ctx context.Context, debugAddr string) (MemSnapshot, error) {
	req, cancel, err := newDebugRequest(ctx, debugAddr, "/debug/memstats")
	if err != nil {
		return MemSnapshot{}, err
	}
	defer cancel()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return MemSnapshot{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return MemSnapshot{}, fmt.Errorf("support: unexpected status %s from %s", resp.Status, debugAddr)
	}
	var snap MemSnapshot
	if err := decodeDebugResponse(resp.Body, &snap); err != nil {
		return MemSnapshot{}, err
	}
	return snap, nil
}

// FetchUsage reads the benchmark server's normalized cumulative rusage. The
// caller takes before/after readings and applies UsageDelta so warmup and
// process startup cannot leak into measurement-window CPU accounting.
func FetchUsage(ctx context.Context, debugAddr string) (Usage, error) {
	req, cancel, err := newDebugRequest(ctx, debugAddr, "/debug/rusage")
	if err != nil {
		return Usage{}, err
	}
	defer cancel()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return Usage{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Usage{}, fmt.Errorf("support: unexpected status %s from %s", resp.Status, debugAddr)
	}
	var usage Usage
	if err := decodeDebugResponse(resp.Body, &usage); err != nil {
		return Usage{}, err
	}
	if !usage.Available {
		return Usage{}, fmt.Errorf("support: server rusage unavailable at %s", debugAddr)
	}
	return usage, nil
}

func newDebugRequest(ctx context.Context, debugAddr, path string) (*http.Request, context.CancelFunc, error) {
	requestCtx, cancel := context.WithTimeout(ctx, debugRequestTimeout)
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, "http://"+debugAddr+path, nil)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	return req, cancel, nil
}

func decodeDebugResponse(body io.Reader, target any) error {
	raw, err := io.ReadAll(io.LimitReader(body, maxDebugResponseBytes+1))
	if err != nil {
		return fmt.Errorf("support: read debug response: %w", err)
	}
	if len(raw) > maxDebugResponseBytes {
		return fmt.Errorf("support: debug response exceeds %d bytes", maxDebugResponseBytes)
	}
	if err := json.Unmarshal(raw, target, json.RejectUnknownMembers(true)); err != nil {
		return fmt.Errorf("support: decode debug response: %w", err)
	}
	return nil
}

// WaitForDebugServer polls the debug endpoint until it responds or ctx is
// done, so loadgen does not race the echoserver's startup.
func WaitForDebugServer(ctx context.Context, debugAddr string) error {
	for {
		if _, err := FetchMemSnapshot(ctx, debugAddr); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}
