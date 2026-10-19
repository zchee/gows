package support

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestFetchMemSnapshotRejectsInvalidResponses(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"unknown field":  `{"mallocs":1,"unknown":true}`,
		"trailing value": `{"mallocs":1}{"mallocs":2}`,
		"oversized":      strings.Repeat(" ", maxDebugResponseBytes+1),
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(body))
			}))
			defer server.Close()
			addr := strings.TrimPrefix(server.URL, "http://")
			if _, err := FetchMemSnapshot(t.Context(), addr); err == nil {
				t.Fatalf("FetchMemSnapshot accepted %s", name)
			}
		})
	}
}

func TestNewDebugRequestHasBoundedDeadline(t *testing.T) {
	t.Parallel()
	started := time.Now()
	req, cancel, err := newDebugRequest(t.Context(), "127.0.0.1:1", "/debug/memstats")
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	deadline, ok := req.Context().Deadline()
	if !ok {
		t.Fatal("request context has no deadline")
	}
	if remaining := deadline.Sub(started); remaining <= 0 || remaining > debugRequestTimeout+100*time.Millisecond {
		t.Fatalf("request deadline remaining = %s", remaining)
	}
}

func TestFetchUsage(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		status  int
		body    string
		want    Usage
		wantErr string
	}{
		"success: available usage is returned": {
			status: http.StatusOK,
			body:   `{"available":true,"cpu_seconds":1.5,"maxrss_bytes":4096,"source":"getrusage"}`,
			want:   Usage{Available: true, CPUSeconds: 1.5, MaxRSSBytes: 4096, Source: "getrusage"},
		},
		"error: server reports usage unavailable": {
			status:  http.StatusOK,
			body:    `{"available":false,"cpu_seconds":0,"maxrss_bytes":0,"source":""}`,
			wantErr: "server rusage unavailable",
		},
		"error: non-200 status": {
			status:  http.StatusServiceUnavailable,
			body:    `{"available":true}`,
			wantErr: "unexpected status 503",
		},
		"error: unknown member is rejected": {
			status:  http.StatusOK,
			body:    `{"available":true,"extra":1}`,
			wantErr: "decode debug response",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var gotPath string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()
			got, err := FetchUsage(t.Context(), strings.TrimPrefix(server.URL, "http://"))
			if gotPath != "/debug/rusage" {
				t.Fatalf("FetchUsage requested %q, want /debug/rusage", gotPath)
			}
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("FetchUsage error = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("FetchUsage: %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("FetchUsage mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestWaitForDebugServer(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		addr    func(t *testing.T) string
		timeout time.Duration
		wantErr error
	}{
		"success: ready server": {
			addr: func(t *testing.T) string {
				t.Helper()
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					_, _ = w.Write([]byte(`{"mallocs":1,"frees":0,"total_alloc":0,"heap_alloc":0,"num_gc":0,"goroutines":1}`))
				}))
				t.Cleanup(server.Close)
				return strings.TrimPrefix(server.URL, "http://")
			},
			timeout: 5 * time.Second,
		},
		"success: server that becomes ready after failing first": {
			addr: func(t *testing.T) string {
				t.Helper()
				var calls atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					if calls.Add(1) < 3 {
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					}
					_, _ = w.Write([]byte(`{"mallocs":1}`))
				}))
				t.Cleanup(server.Close)
				return strings.TrimPrefix(server.URL, "http://")
			},
			timeout: 5 * time.Second,
		},
		"error: context ends before the server is ready": {
			addr:    closedLoopbackAddr,
			timeout: 100 * time.Millisecond,
			wantErr: context.DeadlineExceeded,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(t.Context(), tt.timeout)
			defer cancel()
			if err := WaitForDebugServer(ctx, tt.addr(t)); !errors.Is(err, tt.wantErr) {
				t.Fatalf("WaitForDebugServer error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestStartDebugServer(t *testing.T) {
	t.Parallel()

	t.Run("success: serves memstats, rusage and pprof until shut down", func(t *testing.T) {
		t.Parallel()

		addr := closedLoopbackAddr(t)
		srv, errCh := StartDebugServer(addr)
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		if err := WaitForDebugServer(ctx, addr); err != nil {
			t.Fatalf("WaitForDebugServer: %v", err)
		}
		if snap, err := FetchMemSnapshot(ctx, addr); err != nil || snap.Goroutines <= 0 {
			t.Fatalf("FetchMemSnapshot = %+v, %v", snap, err)
		}
		if SelfRusage().Available {
			if usage, err := FetchUsage(ctx, addr); err != nil || usage.Source == "" {
				t.Fatalf("FetchUsage = %+v, %v", usage, err)
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/debug/pprof/cmdline", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET /debug/pprof/cmdline: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /debug/pprof/cmdline status = %s", resp.Status)
		}
		if err := srv.Shutdown(ctx); err != nil {
			t.Fatalf("Shutdown: %v", err)
		}
		if err := <-errCh; !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("serve error after Shutdown = %v, want %v", err, http.ErrServerClosed)
		}
	})

	t.Run("error: listen failure is delivered on the channel", func(t *testing.T) {
		t.Parallel()

		held, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer held.Close()
		_, errCh := StartDebugServer(held.Addr().String())
		select {
		case err := <-errCh:
			if opErr, ok := errors.AsType[*net.OpError](err); !ok || opErr.Op != "listen" {
				t.Fatalf("StartDebugServer error = %v, want a listen *net.OpError", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("StartDebugServer did not report the listen failure")
		}
	})
}

// closedLoopbackAddr returns a loopback address that was free a moment ago.
func closedLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}
