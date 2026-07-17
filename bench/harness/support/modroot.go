package support

import (
	"os"
	"path/filepath"
	"strings"
)

// FindModuleRoot walks up from start to the nearest ancestor directory whose
// go.mod declares modulePath, returning that directory and true, or "" and
// false when no ancestor declares it. Only the module directive's exact path
// matches — comments, blank lines, or a nested module with a different path
// never do — so an unrelated repository above the tree cannot be mistaken for
// the target.
func FindModuleRoot(start, modulePath string) (string, bool) {
	dir := start
	for {
		if data, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil {
			for line := range strings.Lines(string(data)) {
				if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "module "); ok {
					if strings.TrimSpace(rest) == modulePath {
						return dir, true
					}
					break
				}
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}
