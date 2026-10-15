package support

import "strings"

// PMSetPowerSource returns the power source named on the first line of
// "pmset -g batt" output ("Now drawing from 'AC Power'"), or "" when that line
// is absent or malformed.
func PMSetPowerSource(pmset string) string {
	line, _, _ := strings.Cut(pmset, "\n")
	const prefix = "Now drawing from '"
	if !strings.HasPrefix(line, prefix) || !strings.HasSuffix(line, "'") {
		return ""
	}
	return strings.TrimSuffix(strings.TrimPrefix(line, prefix), "'")
}

// PMSetThermalClean reports whether "pmset -g therm" output records neither a
// thermal nor a performance warning level.
func PMSetThermalClean(pmset string) bool {
	return strings.Contains(pmset, "No thermal warning level has been recorded") &&
		strings.Contains(pmset, "No performance warning level has been recorded")
}
