package support

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"runtime"
	"time"

	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
)

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
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		snap := MemSnapshot{
			Mallocs:    m.Mallocs,
			Frees:      m.Frees,
			TotalAlloc: m.TotalAlloc,
			HeapAlloc:  m.HeapAlloc,
			NumGC:      m.NumGC,
			Goroutines: runtime.NumGoroutine(),
		}
		w.Header().Set("Content-Type", "application/json")
		enc := jsontext.NewEncoder(w)
		_ = json.MarshalEncode(enc, snap)
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+debugAddr+"/debug/memstats", nil)
	if err != nil {
		return MemSnapshot{}, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return MemSnapshot{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return MemSnapshot{}, fmt.Errorf("support: unexpected status %s from %s", resp.Status, debugAddr)
	}
	var snap MemSnapshot
	dec := jsontext.NewDecoder(resp.Body)
	if err := json.UnmarshalDecode(dec, &snap); err != nil {
		return MemSnapshot{}, err
	}
	return snap, nil
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
