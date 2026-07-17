package support

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindModuleRoot(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	nested := filepath.Join(root, "bench", "harness", "cmd")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	rootMod := "// The root module.\n\nmodule example.com/root\n\ngo 1.26\n"
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte(rootMod), 0o644); err != nil {
		t.Fatal(err)
	}
	benchMod := "module example.com/root/bench\n\ngo 1.26\n"
	if err := os.WriteFile(filepath.Join(root, "bench", "go.mod"), []byte(benchMod), 0o644); err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		start      string
		modulePath string
		wantDir    string
		wantOK     bool
	}{
		"nested module wins from inside it": {
			start:      nested,
			modulePath: "example.com/root/bench",
			wantDir:    filepath.Join(root, "bench"),
			wantOK:     true,
		},
		"outer module found past a nested non-matching one": {
			start:      nested,
			modulePath: "example.com/root",
			wantDir:    root,
			wantOK:     true,
		},
		"module line preceded by comments still matches": {
			start:      root,
			modulePath: "example.com/root",
			wantDir:    root,
			wantOK:     true,
		},
		"unknown module path reports not found": {
			start:      nested,
			modulePath: "example.com/elsewhere",
			wantOK:     false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			dir, ok := FindModuleRoot(tc.start, tc.modulePath)
			if ok != tc.wantOK {
				t.Fatalf("FindModuleRoot(%q, %q) ok = %v, want %v", tc.start, tc.modulePath, ok, tc.wantOK)
			}
			if tc.wantOK && dir != tc.wantDir {
				t.Fatalf("FindModuleRoot(%q, %q) = %q, want %q", tc.start, tc.modulePath, dir, tc.wantDir)
			}
		})
	}
}
