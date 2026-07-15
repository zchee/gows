package support

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteJSONFileIsDeterministicAndAtomic(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "artifact.json")
	value := map[string]int{"z": 1, "a": 2}
	if err := WriteJSONFile(path, value); err != nil {
		t.Fatalf("WriteJSONFile first: %v", err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteJSONFile(path, value); err != nil {
		t.Fatalf("WriteJSONFile second: %v", err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatalf("deterministic writes differ:\n%s\n%s", first, second)
	}
	if string(first) != "{\n  \"a\": 2,\n  \"z\": 1\n}\n" {
		t.Fatalf("unexpected deterministic JSON:\n%s", first)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp-") {
			t.Fatalf("temporary artifact leaked: %s", entry.Name())
		}
	}
}
