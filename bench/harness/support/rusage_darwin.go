//go:build darwin

package support

// Darwin reports ru_maxrss in bytes.
func normalizeMaxRSS(value int64) (int64, bool) {
	return value, value >= 0
}
