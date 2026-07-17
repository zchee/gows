package support

import (
	"fmt"
	"math"
	"time"
)

// LoadgenSchemaVersion is the only machine-result schema accepted by
// benchrun.
const LoadgenSchemaVersion = 5

// MaxOpenLoopRate is the highest representable true open-loop schedule. A
// higher rate would require multiple arrivals at one nanosecond and cannot be
// expressed by the harness's time.Time-based observation contract.
const MaxOpenLoopRate = 1_000_000_000

// LoadgenResult is the machine-readable measurement summary loadgen emits as a
// single JSON line when invoked with -json. The latency/throughput fields are
// derived from the same HDR-histogram computation path as the human-readable
// summary, so the two outputs never disagree; the client resource fields come
// from the loadgen process's own getrusage(RUSAGE_SELF), never from a net.Conn
// counting wrapper. Client names the WebSocket client transport that drove the
// run ("gows", "gobwas", or "raw"), so a sample records which client stack produced its
// figures. The schema is fixed (no omitzero): every line carries every field,
// so samples.jsonl stays uniformly greppable and jq-able without per-field
// presence checks.
type LoadgenResult struct {
	SchemaVersion                     int             `json:"schema_version"`
	Client                            string          `json:"client"`
	MessageType                       string          `json:"message_type"`
	Arrival                           string          `json:"arrival"`
	Connections                       int             `json:"connections"`
	PayloadBytes                      int             `json:"payload_bytes"`
	PayloadSeed                       uint64          `json:"payload_seed"`
	Inflight                          int             `json:"inflight"`
	WarmupNanoseconds                 int64           `json:"warmup_nanoseconds"`
	DurationNanoseconds               int64           `json:"duration_nanoseconds"`
	Messages                          int64           `json:"messages"`
	OfferedMessages                   int64           `json:"offered_messages"`
	RequestedOfferedMessagesPerSecond int             `json:"requested_offered_messages_per_second"`
	AchievedMessages                  int64           `json:"achieved_messages"`
	RejectedMessages                  int64           `json:"rejected_messages"`
	DroppedMessages                   int64           `json:"dropped_messages"`
	QueueOverflows                    int64           `json:"queue_overflows"`
	SchedulerLateMessages             int64           `json:"scheduler_late_messages"`
	PostWindowMessages                int64           `json:"post_window_messages"`
	SchedulerLatenessLimitNanoseconds int64           `json:"scheduler_lateness_limit_nanoseconds"`
	SchedulerMaxLatenessNanoseconds   int64           `json:"scheduler_max_lateness_nanoseconds"`
	MeasurementDrainNanoseconds       int64           `json:"measurement_drain_nanoseconds"`
	VerificationMismatches            int64           `json:"verification_mismatches"`
	OfferedMessagesPerSecond          float64         `json:"offered_messages_per_second"`
	ThroughputMessagesPerSecond       float64         `json:"throughput_messages_per_second"`
	RejectedMessagesPerSecond         float64         `json:"rejected_messages_per_second"`
	P50Nanoseconds                    int64           `json:"p50_nanoseconds"`
	P90Nanoseconds                    int64           `json:"p90_nanoseconds"`
	P99Nanoseconds                    int64           `json:"p99_nanoseconds"`
	P999Nanoseconds                   int64           `json:"p999_nanoseconds"`
	Errors                            int64           `json:"errors"`
	Latency                           LatencySnapshot `json:"latency"`
	LatencyObservationNanoseconds     float64         `json:"latency_observation_nanoseconds_per_record"`
	ServerAllocations                 AllocationStats `json:"server_allocations"`
	ClientAllocations                 AllocationStats `json:"client_allocations"`
	ServerUsage                       Usage           `json:"server_usage"`
	ClientUsage                       Usage           `json:"client_usage"`
	ClientCPUSeconds                  float64         `json:"client_cpu_seconds"`
	ClientMaxRSSBytes                 int64           `json:"client_maxrss_bytes"`
	ClientMaxRSSAvailable             bool            `json:"client_maxrss_available"`
}

// Validate checks the internal identity and accounting invariants of one
// loadgen result. It deliberately does not decide whether overload is allowed;
// HardFailure implements the Phase 0 no-loss verdict gate separately.
func (r LoadgenResult) Validate() error {
	if r.SchemaVersion != LoadgenSchemaVersion {
		return fmt.Errorf("support: loadgen schema_version = %d, want %d", r.SchemaVersion, LoadgenSchemaVersion)
	}
	switch r.Client {
	case "gows", "gobwas", "raw":
	default:
		return fmt.Errorf("support: unknown loadgen client %q", r.Client)
	}
	if r.MessageType != "binary" && r.MessageType != "text" {
		return fmt.Errorf("support: unknown message type %q", r.MessageType)
	}
	switch r.Arrival {
	case "closed_loop", "pipelined", "open_loop":
	default:
		return fmt.Errorf("support: unknown arrival kind %q", r.Arrival)
	}
	if r.Arrival == "open_loop" {
		if r.RequestedOfferedMessagesPerSecond <= 0 || r.RequestedOfferedMessagesPerSecond > MaxOpenLoopRate {
			return fmt.Errorf("support: open_loop requested offered rate = %d, want in [1,%d]", r.RequestedOfferedMessagesPerSecond, MaxOpenLoopRate)
		}
		if r.SchedulerLatenessLimitNanoseconds <= 0 {
			return fmt.Errorf("support: open_loop requires a positive scheduler lateness limit")
		}
	} else if r.RequestedOfferedMessagesPerSecond != 0 || r.SchedulerLatenessLimitNanoseconds != 0 ||
		r.SchedulerMaxLatenessNanoseconds != 0 || r.SchedulerLateMessages != 0 || r.PostWindowMessages != 0 {
		return fmt.Errorf("support: %s carries open-loop-only scheduler accounting", r.Arrival)
	}
	if r.Connections <= 0 || r.PayloadBytes <= 0 || r.Inflight <= 0 || r.WarmupNanoseconds < 0 || r.DurationNanoseconds <= 0 {
		return fmt.Errorf("support: invalid load shape connections=%d payload=%d inflight=%d duration=%d", r.Connections, r.PayloadBytes, r.Inflight, r.DurationNanoseconds)
	}
	if r.PayloadSeed == 0 {
		return fmt.Errorf("support: payload_seed must be nonzero")
	}
	if r.Inflight > MaxInflightBytes/r.PayloadBytes {
		return fmt.Errorf("support: inflight*payload exceeds %d", MaxInflightBytes)
	}
	counts := []struct {
		name  string
		value int64
	}{
		{"messages", r.Messages},
		{"offered_messages", r.OfferedMessages},
		{"achieved_messages", r.AchievedMessages},
		{"rejected_messages", r.RejectedMessages},
		{"dropped_messages", r.DroppedMessages},
		{"queue_overflows", r.QueueOverflows},
		{"scheduler_late_messages", r.SchedulerLateMessages},
		{"post_window_messages", r.PostWindowMessages},
		{"scheduler_lateness_limit_nanoseconds", r.SchedulerLatenessLimitNanoseconds},
		{"scheduler_max_lateness_nanoseconds", r.SchedulerMaxLatenessNanoseconds},
		{"measurement_drain_nanoseconds", r.MeasurementDrainNanoseconds},
		{"verification_mismatches", r.VerificationMismatches},
		{"errors", r.Errors},
	}
	for _, count := range counts {
		if count.value < 0 {
			return fmt.Errorf("support: %s is negative: %d", count.name, count.value)
		}
	}
	if r.Messages != r.AchievedMessages {
		return fmt.Errorf("support: messages %d != achieved_messages %d", r.Messages, r.AchievedMessages)
	}
	if r.AchievedMessages <= 0 {
		return fmt.Errorf("support: achieved_messages must be > 0, got %d", r.AchievedMessages)
	}
	if r.OfferedMessages != r.AchievedMessages+r.RejectedMessages+r.DroppedMessages {
		return fmt.Errorf("support: offered %d != achieved %d + rejected %d + dropped %d", r.OfferedMessages, r.AchievedMessages, r.RejectedMessages, r.DroppedMessages)
	}
	if r.RejectedMessages != r.QueueOverflows+r.SchedulerLateMessages {
		return fmt.Errorf("support: rejected_messages %d != queue_overflows %d + scheduler_late_messages %d", r.RejectedMessages, r.QueueOverflows, r.SchedulerLateMessages)
	}
	if r.PostWindowMessages > r.DroppedMessages {
		return fmt.Errorf("support: post_window_messages %d exceeds dropped_messages %d", r.PostWindowMessages, r.DroppedMessages)
	}
	if r.Arrival == "open_loop" {
		expected, err := OpenLoopOfferedMessages(time.Duration(r.DurationNanoseconds), r.RequestedOfferedMessagesPerSecond)
		if err != nil {
			return err
		}
		if r.OfferedMessages != expected {
			return fmt.Errorf("support: open_loop offered_messages = %d, want exact schedule count %d", r.OfferedMessages, expected)
		}
		if r.SchedulerLateMessages == 0 && r.SchedulerMaxLatenessNanoseconds > r.SchedulerLatenessLimitNanoseconds {
			return fmt.Errorf("support: scheduler max lateness exceeds its limit without rejected late messages")
		}
	}
	if r.Latency.Raw.Seen != r.AchievedMessages || r.Latency.Corrected.Seen != r.AchievedMessages {
		return fmt.Errorf("support: latency observations raw=%d corrected=%d, want achieved=%d", r.Latency.Raw.Seen, r.Latency.Corrected.Seen, r.AchievedMessages)
	}
	if err := validateHistogramCounts(r.Latency.Raw.HistogramCounts); err != nil {
		return fmt.Errorf("support: raw latency counts: %w", err)
	}
	if err := validateHistogramCounts(r.Latency.Corrected.HistogramCounts); err != nil {
		return fmt.Errorf("support: corrected latency counts: %w", err)
	}
	if _, err := r.Latency.Raw.Percentiles(); err != nil {
		return fmt.Errorf("support: raw latency: %w", err)
	}
	corrected, err := r.Latency.Corrected.Percentiles()
	if err != nil {
		return fmt.Errorf("support: corrected latency: %w", err)
	}
	if corrected.P50.Nanoseconds() != r.P50Nanoseconds || corrected.P90.Nanoseconds() != r.P90Nanoseconds || corrected.P99.Nanoseconds() != r.P99Nanoseconds || corrected.P999.Nanoseconds() != r.P999Nanoseconds {
		return fmt.Errorf("support: latency percentile summary disagrees with corrected histogram")
	}
	durationSeconds := float64(r.DurationNanoseconds) / 1e9
	if !sameFiniteFloat(r.OfferedMessagesPerSecond, float64(r.OfferedMessages)/durationSeconds) ||
		!sameFiniteFloat(r.ThroughputMessagesPerSecond, float64(r.AchievedMessages)/durationSeconds) ||
		!sameFiniteFloat(r.RejectedMessagesPerSecond, float64(r.RejectedMessages)/durationSeconds) {
		return fmt.Errorf("support: throughput rate fields disagree with counts and duration")
	}
	if math.IsNaN(r.LatencyObservationNanoseconds) || math.IsInf(r.LatencyObservationNanoseconds, 0) || r.LatencyObservationNanoseconds <= 0 {
		return fmt.Errorf("support: invalid latency observation overhead %g", r.LatencyObservationNanoseconds)
	}
	if err := r.ServerAllocations.Validate(r.AchievedMessages); err != nil {
		return fmt.Errorf("support: server allocations: %w", err)
	}
	if err := r.ClientAllocations.Validate(r.AchievedMessages); err != nil {
		return fmt.Errorf("support: client allocations: %w", err)
	}
	if err := validateUsage("server", r.ServerUsage); err != nil {
		return err
	}
	if err := validateUsage("client", r.ClientUsage); err != nil {
		return err
	}
	if r.ClientCPUSeconds != r.ClientUsage.CPUSeconds || r.ClientMaxRSSBytes != r.ClientUsage.MaxRSSBytes || r.ClientMaxRSSAvailable != r.ClientUsage.Available {
		return fmt.Errorf("support: compatibility resource fields disagree with client_usage")
	}
	return nil
}

func validateHistogramCounts(counts HistogramCounts) error {
	if counts.Seen < 0 || counts.Recorded < 0 || counts.Dropped < 0 || counts.Overflow < 0 {
		return fmt.Errorf("negative histogram count")
	}
	if counts.Seen != counts.Recorded+counts.Dropped {
		return fmt.Errorf("seen %d != recorded %d + dropped %d", counts.Seen, counts.Recorded, counts.Dropped)
	}
	if counts.Overflow > counts.Dropped {
		return fmt.Errorf("overflow %d exceeds dropped %d", counts.Overflow, counts.Dropped)
	}
	return nil
}

func validateUsage(name string, usage Usage) error {
	if !usage.Available || usage.Source == "" || math.IsNaN(usage.CPUSeconds) || math.IsInf(usage.CPUSeconds, 0) || usage.CPUSeconds < 0 || usage.MaxRSSBytes <= 0 {
		return fmt.Errorf("support: invalid or unavailable %s resource accounting: %+v", name, usage)
	}
	return nil
}

// HardFailure reports measurements that cannot be promoted into Phase 0
// evidence even when their schema is valid.
func (r LoadgenResult) HardFailure() error {
	if err := r.Validate(); err != nil {
		return err
	}
	if r.Errors != 0 || r.VerificationMismatches != 0 || r.RejectedMessages != 0 || r.DroppedMessages != 0 || r.QueueOverflows != 0 || r.SchedulerLateMessages != 0 || r.PostWindowMessages != 0 {
		return fmt.Errorf("support: hard measurement failure errors=%d mismatches=%d rejected=%d dropped=%d queue_overflows=%d scheduler_late=%d post_window=%d", r.Errors, r.VerificationMismatches, r.RejectedMessages, r.DroppedMessages, r.QueueOverflows, r.SchedulerLateMessages, r.PostWindowMessages)
	}
	if r.Latency.Raw.Dropped != 0 || r.Latency.Raw.Overflow != 0 || r.Latency.Corrected.Dropped != 0 || r.Latency.Corrected.Overflow != 0 {
		return fmt.Errorf("support: latency observation loss raw=%d/%d corrected=%d/%d", r.Latency.Raw.Dropped, r.Latency.Raw.Overflow, r.Latency.Corrected.Dropped, r.Latency.Corrected.Overflow)
	}
	return nil
}

// OpenLoopOfferedMessages returns the exact count of arrivals scheduled in
// [start,start+duration). It avoids floating-point rounding and rejects counts
// that cannot fit the machine result's signed 64-bit fields.
func OpenLoopOfferedMessages(duration time.Duration, rate int) (int64, error) {
	if duration <= 0 {
		return 0, fmt.Errorf("support: open-loop duration must be > 0, got %s", duration)
	}
	if rate <= 0 || rate > MaxOpenLoopRate {
		return 0, fmt.Errorf("support: open-loop rate = %d, want in [1,%d]", rate, MaxOpenLoopRate)
	}
	seconds := int64(duration / time.Second)
	rate64 := int64(rate)
	if seconds > math.MaxInt64/rate64 {
		return 0, fmt.Errorf("support: open-loop schedule count overflows int64")
	}
	total := seconds * rate64
	remainder := int64(duration % time.Second)
	product := remainder * rate64
	extra := (product + int64(time.Second) - 1) / int64(time.Second)
	if total > math.MaxInt64-extra {
		return 0, fmt.Errorf("support: open-loop schedule count overflows int64")
	}
	return total + extra, nil
}
