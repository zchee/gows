package support

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
