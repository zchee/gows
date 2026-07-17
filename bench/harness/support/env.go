package support

import "strings"

// MergeEnv returns base with every KEY=VALUE entry in overrides replacing the
// base entries that share the same KEY, preserving base order and appending
// the overrides at the end. An override without "=" replaces nothing and is
// appended as-is, and repeated override keys are all appended, matching
// os/exec's last-entry-wins environment semantics.
func MergeEnv(base []string, overrides ...string) []string {
	keys := make(map[string]struct{}, len(overrides))
	for _, override := range overrides {
		if key, _, ok := strings.Cut(override, "="); ok {
			keys[key] = struct{}{}
		}
	}
	result := make([]string, 0, len(base)+len(overrides))
	for _, entry := range base {
		key, _, ok := strings.Cut(entry, "=")
		if _, replaced := keys[key]; ok && replaced {
			continue
		}
		result = append(result, entry)
	}
	return append(result, overrides...)
}
