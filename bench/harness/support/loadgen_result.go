package support

// LoadgenResult is the machine-readable measurement summary loadgen emits as a
// single JSON line when invoked with -json. The latency/throughput fields are
// derived from the same Recorder-based computation path as the human-readable
// summary, so the two outputs never disagree; the client resource fields come
// from the loadgen process's own getrusage(RUSAGE_SELF), never from a net.Conn
// counting wrapper. Client names the WebSocket client transport that drove the
// run ("gows" or "gobwas"), so a sample records which client stack produced its
// figures. The schema is fixed (no omitzero): benchrun parses these lines by
// exact field, so a zero value must still be present.
type LoadgenResult struct {
	Client                      string  `json:"client"`
	Connections                 int     `json:"connections"`
	PayloadBytes                int     `json:"payload_bytes"`
	Inflight                    int     `json:"inflight"`
	WarmupNanoseconds           int64   `json:"warmup_nanoseconds"`
	DurationNanoseconds         int64   `json:"duration_nanoseconds"`
	Messages                    int64   `json:"messages"`
	ThroughputMessagesPerSecond float64 `json:"throughput_messages_per_second"`
	P50Nanoseconds              int64   `json:"p50_nanoseconds"`
	P90Nanoseconds              int64   `json:"p90_nanoseconds"`
	P99Nanoseconds              int64   `json:"p99_nanoseconds"`
	P999Nanoseconds             int64   `json:"p999_nanoseconds"`
	Errors                      int     `json:"errors"`
	ClientCPUSeconds            float64 `json:"client_cpu_seconds"`
	ClientMaxRSSBytes           int64   `json:"client_maxrss_bytes"`
}
