package support

import "strings"

// fileNameReplacer maps the characters that would split or escape a path
// component to '-'.
var fileNameReplacer = strings.NewReplacer("/", "-", "\\", "-", ":", "-", " ", "-")

// SafeName replaces '/', '\\', ':' and ' ' in value with '-' so it can be used
// as a single file-name component.
func SafeName(value string) string {
	return fileNameReplacer.Replace(value)
}

// RunLogPrefix returns the file-name prefix shared by every per-block log a
// benchrun run writes under logs/ (for example "<prefix>.guard.jsonl"). The
// evidence validator derives the same name to find each block's guard log.
func RunLogPrefix(scenario, block, library string) string {
	return SafeName(scenario) + "__" + SafeName(block) + "__" + SafeName(library)
}

// ValidArtifactID reports whether value is usable as a single run-artifact
// path component: non-empty, not "." or "..", and made only of ASCII letters,
// digits, '-', '_' and '.'.
func ValidArtifactID(value string) bool {
	if value == "" || value == "." || value == ".." {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_' && r != '.' {
			return false
		}
	}
	return true
}
