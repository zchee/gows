package support

import (
	"fmt"
	"os"

	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
)

// WriteJSONFile marshals v as indented JSON with a trailing newline and writes
// it to path. It is the one serialization point for every JSON artifact a run
// directory records (meta.json, the env snapshots, done.json, verdict.json),
// so they all share one format.
func WriteJSONFile(path string, v any) error {
	b, err := json.Marshal(v, jsontext.WithIndent("  "))
	if err != nil {
		return fmt.Errorf("marshal %s: %w", path, err)
	}
	b = append(b, '\n')
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
