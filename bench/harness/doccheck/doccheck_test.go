package doccheck

import (
	"os"
	"path/filepath"
	"testing"
)

func TestREADMEGeneratedMetadataIsCurrent(t *testing.T) {
	benchRoot := filepath.Clean(filepath.Join("..", ".."))
	if err := CheckREADME(benchRoot, filepath.Join(benchRoot, "README.md")); err != nil {
		t.Fatal(err)
	}
}

func TestWriteREADMEUpdatesOnlyGeneratedSections(t *testing.T) {
	benchRoot := filepath.Clean(filepath.Join("..", ".."))
	sections, err := Generate(benchRoot)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "README.md")
	raw := "before\n"
	for _, name := range []string{moduleSection, policySection} {
		begin, end := markers(name)
		raw += begin + "\nstale\n" + end + "\n"
	}
	raw += "after\n"
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteREADME(benchRoot, path); err != nil {
		t.Fatal(err)
	}
	if err := CheckREADME(benchRoot, path); err != nil {
		t.Fatal(err)
	}
	updated, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(updated[:7]) != "before\n" || string(updated[len(updated)-6:]) != "after\n" {
		t.Fatalf("prose outside generated sections changed:\n%s", updated)
	}
	for name, want := range sections {
		got, err := section(updated, name)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("section %s was not regenerated", name)
		}
	}
}

func TestSectionRejectsDuplicateMarkers(t *testing.T) {
	begin, end := markers(moduleSection)
	raw := []byte(begin + "\none\n" + end + "\n" + begin + "\ntwo\n" + end)
	if _, err := section(raw, moduleSection); err == nil {
		t.Fatal("section accepted duplicate markers")
	}
}
