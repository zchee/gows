//go:build linux

package support

import "math"

// Linux reports ru_maxrss in KiB.
func normalizeMaxRSS(value int64) (int64, bool) {
	if value < 0 || value > math.MaxInt64/1024 {
		return 0, false
	}
	return value * 1024, true
}
