package paired

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadSamples covers benchcmp's only data-ingestion path: blank-line
// tolerance, field decoding, and the malformed-line error carrying the
// offending line number.
func TestLoadSamples(t *testing.T) {
	t.Parallel()

	const (
		gowsLine    = `{"scenario":"binary-1k-200","library":"gows","repetition":0,"throughput_messages_per_second":100.5,"p99_nanoseconds":1500}`
		quickwsLine = `{"scenario":"binary-1k-200","library":"quickws","repetition":0,"throughput_messages_per_second":90.25,"p99_nanoseconds":1800}`
	)

	tests := map[string]struct {
		content string
		wantN   int
		wantErr string
	}{
		"success: two samples separated by a blank line": {
			content: gowsLine + "\n\n" + quickwsLine + "\n",
			wantN:   2,
		},
		"success: empty file yields no samples": {
			content: "",
			wantN:   0,
		},
		"error: malformed line reports its line number": {
			content: gowsLine + "\n\n{not json}\n",
			wantErr: "line 3",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "samples.jsonl")
			if err := os.WriteFile(path, []byte(tt.content), 0o644); err != nil {
				t.Fatal(err)
			}

			samples, err := LoadSamples(path)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("LoadSamples error = %v, want one containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadSamples: %v", err)
			}
			if len(samples) != tt.wantN {
				t.Fatalf("len(samples) = %d, want %d", len(samples), tt.wantN)
			}
			if tt.wantN == 2 {
				if samples[0].Library != "gows" || samples[1].Library != "quickws" {
					t.Fatalf("libraries = %q, %q, want gows, quickws", samples[0].Library, samples[1].Library)
				}
				if samples[0].ThroughputMessagesPerSecond != 100.5 {
					t.Fatalf("throughput = %v, want 100.5", samples[0].ThroughputMessagesPerSecond)
				}
				if samples[1].P99Nanoseconds != 1800 {
					t.Fatalf("p99 = %d, want 1800", samples[1].P99Nanoseconds)
				}
			}
		})
	}

	t.Run("error: missing file", func(t *testing.T) {
		t.Parallel()

		if _, err := LoadSamples(filepath.Join(t.TempDir(), "absent.jsonl")); err == nil {
			t.Fatal("LoadSamples on a missing file: nil error, want non-nil")
		}
	})
}
