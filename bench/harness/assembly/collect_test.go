package assembly

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/zchee/gows/bench/harness/support"
)

func TestNormalizeVersionMRemovesTemporaryPath(t *testing.T) {
	physical := "/private/tmp/gows-asmprov-random/probe"
	logical := "binary/darwin-arm64/asmprobetarget"
	input := []byte(physical + ": go1.26.5\n\tpath\t" + probeImportPath + "\n")
	got, err := normalizeVersionM(input, physical, logical)
	if err != nil {
		t.Fatalf("normalizeVersionM() error = %v", err)
	}
	want := []byte(logical + ": go1.26.5\n\tpath\t" + probeImportPath + "\n")
	if !bytes.Equal(got, want) {
		t.Fatalf("normalizeVersionM() = %q, want %q", got, want)
	}
}

func TestCollectSupportedTargetsAndVerifyImmutableBundles(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skipf("host architecture %s cannot supply supported native runtime evidence", runtime.GOARCH)
	}
	repoRoot, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()

	for _, goarch := range []string{"amd64", "arm64"} {
		t.Run(goarch, func(t *testing.T) {
			runRuntime := goarch == runtime.GOARCH
			bundle, err := Collect(ctx, Config{
				RepoRoot:   repoRoot,
				GOOS:       runtime.GOOS,
				GOARCH:     goarch,
				RunRuntime: runRuntime,
				AllowDirty: true,
			})
			if err != nil {
				t.Fatalf("Collect() error = %v", err)
			}
			if err := bundle.Manifest.Validate(); err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			if len(bundle.Manifest.Packages) != len(productionPackages) {
				t.Fatalf("package count = %d, want %d", len(bundle.Manifest.Packages), len(productionPackages))
			}
			if len(bundle.Manifest.Symbols.Records) == 0 {
				t.Fatal("no linked assembly symbols recorded")
			}
			if bundle.Manifest.Repository.Remote == "" || bundle.Manifest.Repository.Branch == "" ||
				!support.ValidGitObjectID(bundle.Manifest.Repository.SourceHEAD) || !support.ValidSHA256(bundle.Manifest.Repository.SourceTreeSHA256) {
				t.Fatalf("incomplete repository identity: %+v", bundle.Manifest.Repository)
			}
			if len(bundle.Manifest.BuildGraph.Corpus) != 2 || len(bundle.Manifest.Dispatch.Records) != 3 {
				t.Fatalf("corpus/dispatch identity incomplete: corpus=%d dispatch=%d", len(bundle.Manifest.BuildGraph.Corpus), len(bundle.Manifest.Dispatch.Records))
			}
			resolvedGoTool, err := filepath.EvalSymlinks(bundle.Manifest.Toolchain.GoBinaryPath)
			if err != nil || resolvedGoTool != bundle.Manifest.Toolchain.GoBinaryPath {
				t.Fatalf("Go tool path is not exact/canonical: path=%q resolved=%q err=%v", bundle.Manifest.Toolchain.GoBinaryPath, resolvedGoTool, err)
			}
			if runRuntime && runtime.GOOS == "darwin" && !bundle.Manifest.CPU.Runtime.Execution.TranslationAvailable {
				t.Fatalf("Darwin translation identity unavailable: %+v", bundle.Manifest.CPU.Runtime.Execution)
			}

			requireFinal := false // Collect uses explicit AllowDirty diagnostic mode.
			bundleDir := filepath.Join(t.TempDir(), runtime.GOOS+"-"+goarch)
			if err := WriteBundle(bundleDir, bundle, requireFinal); err != nil {
				t.Fatalf("WriteBundle() error = %v", err)
			}
			verified, err := ReadBundle(bundleDir, requireFinal)
			if err != nil {
				t.Fatalf("ReadBundle() error = %v", err)
			}
			if verified.Manifest.Binary.SHA256 != bundle.Manifest.Binary.SHA256 {
				t.Fatalf("binary sha256 = %s, want %s", verified.Manifest.Binary.SHA256, bundle.Manifest.Binary.SHA256)
			}
			if err := WriteBundle(bundleDir, bundle, requireFinal); err == nil || !strings.Contains(err.Error(), "already exists") {
				t.Fatalf("second WriteBundle() error = %v, want existing destination rejection", err)
			}

			t.Run("tampered artifact", func(t *testing.T) {
				dir := filepath.Join(t.TempDir(), "bundle")
				if err := WriteBundle(dir, bundle, requireFinal); err != nil {
					t.Fatal(err)
				}
				binaryPath := filepath.Join(dir, filepath.FromSlash(bundle.Manifest.Binary.Path))
				if err := os.Chmod(binaryPath, 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(binaryPath, []byte("tampered"), 0o644); err != nil {
					t.Fatal(err)
				}
				if _, err := ReadBundle(dir, requireFinal); err == nil || (!strings.Contains(err.Error(), "size") && !strings.Contains(err.Error(), "sha256")) {
					t.Fatalf("ReadBundle() tamper error = %v", err)
				}
			})

			t.Run("unreferenced file", func(t *testing.T) {
				dir := filepath.Join(t.TempDir(), "bundle")
				if err := WriteBundle(dir, bundle, requireFinal); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "untracked.txt"), []byte("not in manifest"), 0o644); err != nil {
					t.Fatal(err)
				}
				if _, err := ReadBundle(dir, requireFinal); err == nil || !strings.Contains(err.Error(), "unreferenced") {
					t.Fatalf("ReadBundle() unreferenced error = %v", err)
				}
			})

			if goarch == runtime.GOARCH {
				t.Run("exact Go tool mismatch", func(t *testing.T) {
					altered := cloneTestBundle(t, bundle)
					altered.Manifest.Toolchain.GoBinarySHA256 = strings.Repeat("a", 64)
					err := WriteBundle(filepath.Join(t.TempDir(), "bundle"), altered, false)
					if err == nil || !strings.Contains(err.Error(), "exact stock Go tool") {
						t.Fatalf("WriteBundle() Go tool mismatch error = %v", err)
					}
				})

				t.Run("module graph identity mismatch", func(t *testing.T) {
					altered := cloneTestBundle(t, bundle)
					replaceTestArtifact(altered.Artifacts, &altered.Manifest.Modules.Graph, []byte("{}\n"))
					err := WriteBundle(filepath.Join(t.TempDir(), "bundle"), altered, false)
					if err == nil || !strings.Contains(err.Error(), "module graph missing") {
						t.Fatalf("WriteBundle() module graph mismatch error = %v", err)
					}
				})

				t.Run("corpus source identity mismatch", func(t *testing.T) {
					altered := cloneTestBundle(t, bundle)
					entry := &altered.Manifest.BuildGraph.Corpus[0]
					entry.Files[0].SHA256 = strings.Repeat("a", 64)
					entry.SHA256 = corpusHash(entry.Class, entry.Files)
					err := WriteBundle(filepath.Join(t.TempDir(), "bundle"), altered, false)
					if err == nil || !strings.Contains(err.Error(), "corpus") {
						t.Fatalf("WriteBundle() corpus mismatch error = %v", err)
					}
				})

				t.Run("dispatcher call edge artifact mismatch", func(t *testing.T) {
					altered := cloneTestBundle(t, bundle)
					var record *DispatchRecord
					for index := range altered.Manifest.Dispatch.Records {
						if len(altered.Manifest.Dispatch.Records[index].Calls) != 0 {
							record = &altered.Manifest.Dispatch.Records[index]
							break
						}
					}
					if record == nil {
						t.Fatal("no dispatcher with a call edge")
					}
					replaceTestArtifact(altered.Artifacts, &record.Objdump, []byte("TEXT "+record.Name+"(SB)\n"))
					err := WriteBundle(filepath.Join(t.TempDir(), "bundle"), altered, false)
					if err == nil || !strings.Contains(err.Error(), "call edge") {
						t.Fatalf("WriteBundle() dispatcher mismatch error = %v", err)
					}
				})
			}
		})
	}
}

func cloneTestBundle(t *testing.T, bundle Bundle) Bundle {
	t.Helper()
	manifestBytes, err := json.Marshal(bundle.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	var manifest Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	artifacts := make(map[string][]byte, len(bundle.Artifacts))
	for name, data := range bundle.Artifacts {
		artifacts[name] = bytes.Clone(data)
	}
	return Bundle{Manifest: manifest, Artifacts: artifacts}
}

func replaceTestArtifact(artifacts map[string][]byte, artifact *Artifact, data []byte) {
	artifacts[artifact.Path] = bytes.Clone(data)
	sum := sha256.Sum256(data)
	artifact.SHA256 = hex.EncodeToString(sum[:])
	artifact.Size = int64(len(data))
}
