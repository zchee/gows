package assembly

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"slices"
	"strings"

	"github.com/zchee/gows/bench/harness/support"
)

const manifestName = "manifest.json"

// WriteBundle writes a new immutable bundle through a same-directory atomic
// rename. Existing destinations are never replaced.
func WriteBundle(outputDir string, bundle Bundle, requireRuntime bool) (resultErr error) {
	if outputDir == "" {
		return errors.New("assembly bundle: output directory is empty")
	}
	if err := validateBundleBytes(bundle, requireRuntime); err != nil {
		return err
	}
	manifestBytes, err := json.MarshalIndent(bundle.Manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("assembly bundle: encode manifest: %w", err)
	}
	manifestBytes = append(manifestBytes, '\n')

	outputDir, err = filepath.Abs(outputDir)
	if err != nil {
		return fmt.Errorf("assembly bundle: output path: %w", err)
	}
	parent := filepath.Dir(outputDir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return fmt.Errorf("assembly bundle: create output parent: %w", err)
	}
	if _, err := os.Lstat(outputDir); err == nil {
		return fmt.Errorf("assembly bundle: destination already exists: %s", outputDir)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("assembly bundle: inspect destination: %w", err)
	}
	tempDir, err := os.MkdirTemp(parent, "."+filepath.Base(outputDir)+".tmp-")
	if err != nil {
		return fmt.Errorf("assembly bundle: create temporary output: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("assembly bundle: clean temporary output: %w", err))
		}
	}()

	paths := make([]string, 0, len(bundle.Artifacts))
	for artifactPath := range bundle.Artifacts {
		paths = append(paths, artifactPath)
	}
	slices.Sort(paths)
	for _, artifactPath := range paths {
		if err := writeImmutableFile(tempDir, artifactPath, bundle.Artifacts[artifactPath]); err != nil {
			return err
		}
	}
	if err := writeImmutableFile(tempDir, manifestName, manifestBytes); err != nil {
		return err
	}
	if err := syncDir(tempDir); err != nil {
		return fmt.Errorf("assembly bundle: sync temporary output: %w", err)
	}
	if err := os.Rename(tempDir, outputDir); err != nil {
		return fmt.Errorf("assembly bundle: publish: %w", err)
	}
	if err := syncDir(parent); err != nil {
		return fmt.Errorf("assembly bundle: sync output parent: %w", err)
	}
	return nil
}

// ReadBundle strictly decodes and hashes every file in an immutable bundle.
// Unreferenced files and symlinks are rejected.
func ReadBundle(bundleDir string, requireRuntime bool) (Bundle, error) {
	manifestPath := filepath.Join(bundleDir, manifestName)
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return Bundle{}, fmt.Errorf("assembly bundle: read manifest: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(manifestBytes))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Bundle{}, fmt.Errorf("assembly bundle: decode manifest: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return Bundle{}, fmt.Errorf("assembly bundle: decode manifest: %w", err)
	}

	artifacts := make(map[string][]byte)
	for _, artifact := range referencedArtifacts(manifest) {
		clean, err := cleanArtifactPath(artifact.Path)
		if err != nil {
			return Bundle{}, err
		}
		info, err := os.Lstat(filepath.Join(bundleDir, filepath.FromSlash(clean)))
		if err != nil {
			return Bundle{}, fmt.Errorf("assembly bundle: stat %q: %w", clean, err)
		}
		if !info.Mode().IsRegular() {
			return Bundle{}, fmt.Errorf("assembly bundle: artifact %q is not a regular file", clean)
		}
		data, err := os.ReadFile(filepath.Join(bundleDir, filepath.FromSlash(clean)))
		if err != nil {
			return Bundle{}, fmt.Errorf("assembly bundle: read %q: %w", clean, err)
		}
		if err := verifyArtifactBytes(artifact, data); err != nil {
			return Bundle{}, err
		}
		artifacts[clean] = data
	}

	wantFiles := map[string]bool{manifestName: true}
	for artifactPath := range artifacts {
		wantFiles[artifactPath] = true
	}
	if err := filepath.WalkDir(bundleDir, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == bundleDir {
			return nil
		}
		rel, err := filepath.Rel(bundleDir, name)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("assembly bundle: symlink %q is forbidden", rel)
		}
		if !entry.IsDir() && !wantFiles[rel] {
			return fmt.Errorf("assembly bundle: unreferenced file %q", rel)
		}
		return nil
	}); err != nil {
		return Bundle{}, err
	}
	bundle := Bundle{Manifest: manifest, Artifacts: artifacts}
	if err := validateBundleBytes(bundle, requireRuntime); err != nil {
		return Bundle{}, err
	}
	return bundle, nil
}

func validateBundleBytes(bundle Bundle, requireRuntime bool) error {
	var err error
	if requireRuntime {
		err = bundle.Manifest.ValidateFinal()
	} else {
		err = bundle.Manifest.Validate()
	}
	if err != nil {
		return fmt.Errorf("assembly bundle: manifest: %w", err)
	}
	referenced := referencedArtifacts(bundle.Manifest)
	if len(bundle.Artifacts) != len(referenced) {
		return fmt.Errorf("assembly bundle: has %d artifacts, manifest references %d", len(bundle.Artifacts), len(referenced))
	}
	seen := make(map[string]bool, len(referenced))
	for _, artifact := range referenced {
		clean, err := cleanArtifactPath(artifact.Path)
		if err != nil {
			return err
		}
		if seen[clean] {
			return fmt.Errorf("assembly bundle: duplicate artifact path %q", clean)
		}
		seen[clean] = true
		data, ok := bundle.Artifacts[clean]
		if !ok {
			return fmt.Errorf("assembly bundle: missing artifact bytes %q", clean)
		}
		if err := verifyArtifactBytes(artifact, data); err != nil {
			return err
		}
	}
	for artifactPath := range bundle.Artifacts {
		if !seen[artifactPath] {
			return fmt.Errorf("assembly bundle: unreferenced artifact bytes %q", artifactPath)
		}
	}
	if err := validateArtifactRelationships(bundle.Manifest, bundle.Artifacts); err != nil {
		return fmt.Errorf("assembly bundle: evidence relationship: %w", err)
	}
	return nil
}

func validateArtifactRelationships(manifest Manifest, artifacts map[string][]byte) error {
	goToolSum, goToolSize, err := support.FileSHA256(manifest.Toolchain.GoBinaryPath)
	if err != nil {
		return fmt.Errorf("read exact stock Go tool: %w", err)
	}
	if goToolSize != manifest.Toolchain.GoBinarySize || goToolSum != manifest.Toolchain.GoBinarySHA256 {
		return errors.New("exact stock Go tool no longer matches manifest identity")
	}
	statusBytes := artifacts[manifest.Repository.Status.Path]
	if manifest.Repository.Dirty != (len(bytes.TrimSpace(statusBytes)) != 0) {
		return errors.New("repository status artifact does not match dirty identity")
	}
	if err := validateModuleGraphArtifact(manifest, artifacts[manifest.Modules.Graph.Path]); err != nil {
		return err
	}
	if manifest.Repository.Stable {
		pathsBytes, err := run(context.Background(), os.Environ(), "git", "-C", manifest.Repository.Root, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
		if err != nil {
			return fmt.Errorf("recompute repository source list: %w", err)
		}
		paths, err := parseNULPaths(pathsBytes)
		if err != nil {
			return err
		}
		paths = sourceIdentityPaths(paths)
		currentSourceTreeHash, err := hashRepositoryTree(manifest.Repository.Root, paths)
		if err != nil || currentSourceTreeHash != manifest.Repository.SourceTreeSHA256 || len(paths) != manifest.Repository.SourceTreeFiles {
			return fmt.Errorf("repository source tree does not match manifest: hash=%q files=%d err=%v", currentSourceTreeHash, len(paths), err)
		}
		if err := validateRepositoryAncestry(manifest.Repository); err != nil {
			return err
		}
	}
	rootModuleHash, err := hashFileSet(manifest.Repository.Root, []string{"go.mod", "go.sum"}, "root-module-files-v1")
	if err != nil || rootModuleHash != manifest.Modules.RootFilesSHA256 {
		return fmt.Errorf("root module files do not match manifest: hash=%q err=%v", rootModuleHash, err)
	}
	benchModuleHash, err := hashFileSet(manifest.Repository.Root, []string{"bench/go.mod", "bench/go.sum"}, "bench-module-files-v1")
	if err != nil || benchModuleHash != manifest.Modules.BenchFilesSHA256 {
		return fmt.Errorf("bench module files do not match manifest: hash=%q err=%v", benchModuleHash, err)
	}
	for _, corpus := range manifest.BuildGraph.Corpus {
		for _, source := range corpus.Files {
			if err := verifyCurrentSource(manifest.Repository.Root, source); err != nil {
				return fmt.Errorf("%s corpus: %w", corpus.Class, err)
			}
		}
	}
	var effective goEnvironment
	if err := json.Unmarshal(artifacts[manifest.GoEnv.Path], &effective); err != nil {
		return fmt.Errorf("decode go env: %w", err)
	}
	if effective.GOOS != manifest.Target.GOOS || effective.GOARCH != manifest.Target.GOARCH ||
		effective.GOEXPERIMENT != manifest.Target.GOEXPERIMENT || effective.GOENV != "" || manifest.Target.GOENV != "off" ||
		effective.GOTOOLCHAIN != manifest.Target.GOTOOLCHAIN || effective.GOFLAGS != manifest.Target.GOFLAGS ||
		effective.GOFIPS140 != manifest.Target.GOFIPS140 || effective.CGOEnabled != manifest.Target.CGOEnabled ||
		effective.GOVERSION != manifest.Toolchain.GoVersion {
		return fmt.Errorf("go env does not match manifest target/toolchain: %+v", effective)
	}

	binaryInfo, err := buildinfo.Read(bytes.NewReader(artifacts[manifest.Binary.Path]))
	if err != nil {
		return fmt.Errorf("read linked binary build info: %w", err)
	}
	if binaryInfo.Path != probeImportPath || binaryInfo.GoVersion != manifest.Toolchain.GoVersion {
		return fmt.Errorf("linked binary identity path=%q goversion=%q", binaryInfo.Path, binaryInfo.GoVersion)
	}
	settings := make(map[string]string, len(binaryInfo.Settings))
	for _, setting := range binaryInfo.Settings {
		settings[setting.Key] = setting.Value
	}
	for key, want := range map[string]string{
		"CGO_ENABLED":  manifest.Target.CGOEnabled,
		"GOARCH":       manifest.Target.GOARCH,
		"GOEXPERIMENT": manifest.Target.GOEXPERIMENT,
		"GOFIPS140":    manifest.Target.GOFIPS140,
		"GOOS":         manifest.Target.GOOS,
	} {
		got := settings[key]
		if key == "GOFIPS140" && want == "off" && got == "" {
			got = "off"
		}
		if got != want {
			return fmt.Errorf("linked binary build setting %s=%q, want %q", key, settings[key], want)
		}
	}
	archSetting, archValue := "GOAMD64", manifest.Target.GOAMD64
	if manifest.Target.GOARCH == "arm64" {
		archSetting, archValue = "GOARM64", manifest.Target.GOARM64
	}
	if settings[archSetting] != archValue {
		return fmt.Errorf("linked binary build setting %s=%q, want %q", archSetting, settings[archSetting], archValue)
	}
	versionText := string(artifacts[manifest.Version.Path])
	if !strings.HasPrefix(versionText, manifest.Binary.Path+": ") ||
		!strings.Contains(versionText, "\tpath\t"+probeImportPath) ||
		!strings.Contains(versionText, "\tbuild\tGOARCH="+manifest.Target.GOARCH) ||
		!strings.Contains(versionText, "\tbuild\tGOOS="+manifest.Target.GOOS) {
		return errors.New("go version -m evidence does not identify the probe path and target")
	}
	if manifest.Target.GOEXPERIMENT == "" && strings.Contains(versionText, "\tbuild\tGOEXPERIMENT=") {
		return errors.New("stock binary unexpectedly records GOEXPERIMENT in go version -m")
	}

	decodedGraph, err := decodeGraph(artifacts[manifest.BuildGraph.GoList.Path])
	if err != nil {
		return fmt.Errorf("decode linked graph: %w", err)
	}
	if !slices.Equal(decodedGraph, manifest.BuildGraph.Linked) {
		return fmt.Errorf("linked graph artifact does not match manifest: got %v want %v", decodedGraph, manifest.BuildGraph.Linked)
	}
	for _, pkg := range manifest.Packages {
		for _, source := range pkg.SelectedFiles {
			if err := verifyCurrentSource(manifest.Repository.Root, source); err != nil {
				return fmt.Errorf("package %q: %w", pkg.ImportPath, err)
			}
		}
		var listed listedPackage
		if err := json.Unmarshal(artifacts[pkg.GoList.Path], &listed); err != nil {
			return fmt.Errorf("decode package %q go list: %w", pkg.ImportPath, err)
		}
		if listed.ImportPath != pkg.ImportPath {
			return fmt.Errorf("package go-list import path %q, want %q", listed.ImportPath, pkg.ImportPath)
		}
		listedFiles := make(map[string]string, len(listed.GoFiles)+len(listed.CgoFiles)+len(listed.SFiles))
		for _, name := range listed.GoFiles {
			listedFiles[name] = "go"
		}
		for _, name := range listed.CgoFiles {
			listedFiles[name] = "cgo"
		}
		for _, name := range listed.SFiles {
			listedFiles[name] = "assembly"
		}
		if len(listedFiles) != len(pkg.SelectedFiles) {
			return fmt.Errorf("package %q go-list selected %d files, manifest records %d", pkg.ImportPath, len(listedFiles), len(pkg.SelectedFiles))
		}
		for _, source := range pkg.SelectedFiles {
			base := path.Base(source.Path)
			if listedFiles[base] != source.Kind {
				return fmt.Errorf("package %q source %q kind %q does not match go-list", pkg.ImportPath, source.Path, source.Kind)
			}
		}
	}

	nmLines := make(map[string]bool)
	for line := range strings.SplitSeq(string(artifacts[manifest.Symbols.NM.Path]), "\n") {
		nmLines[line] = true
	}
	for _, symbol := range manifest.Symbols.Records {
		if !nmLines[symbol.NMLine] {
			return fmt.Errorf("nm artifact does not contain recorded symbol line for %q", symbol.Name)
		}
		objdump := string(artifacts[symbol.Objdump.Path])
		if !strings.Contains(objdump, "TEXT "+symbol.Name) {
			return fmt.Errorf("objdump artifact does not contain TEXT for %q", symbol.Name)
		}
	}

	if manifest.CPU.Runtime.Available {
		decoder := json.NewDecoder(bytes.NewReader(artifacts[manifest.CPU.Runtime.ExecutionEvidence.Path]))
		decoder.DisallowUnknownFields()
		var runtimeEvidence RuntimeProfile
		if err := decoder.Decode(&runtimeEvidence); err != nil {
			return fmt.Errorf("decode runtime evidence: %w", err)
		}
		if err := requireJSONEOF(decoder); err != nil {
			return fmt.Errorf("decode runtime evidence: %w", err)
		}
		wantRuntime := manifest.CPU.Runtime
		wantRuntime.Available = false
		wantRuntime.ExecutionEvidence = Artifact{}
		if !reflect.DeepEqual(runtimeEvidence, wantRuntime) {
			return fmt.Errorf("runtime evidence does not match manifest: got %+v want %+v", runtimeEvidence, wantRuntime)
		}
	}
	for _, record := range manifest.Dispatch.Records {
		if !nmLines[record.NMLine] {
			return fmt.Errorf("nm artifact does not contain dispatcher line for %q", record.Name)
		}
		objdump := string(artifacts[record.Objdump.Path])
		if !strings.Contains(objdump, "TEXT "+record.Name) {
			return fmt.Errorf("dispatcher objdump does not contain TEXT for %q", record.Name)
		}
		for _, edge := range record.Calls {
			if !strings.Contains(objdump, edge.EvidenceLine) || !strings.Contains(edge.EvidenceLine, "CALL "+edge.Callee) {
				return fmt.Errorf("dispatcher objdump does not contain call edge %+v", edge)
			}
		}
	}
	return nil
}

func validateRepositoryAncestry(repository RepositoryIdentity) error {
	git := func(args ...string) ([]byte, error) {
		fullArgs := append([]string{"-C", repository.Root}, args...)
		return run(context.Background(), os.Environ(), "git", fullArgs...)
	}
	remoteBytes, err := git("remote", "get-url", "origin")
	if err != nil || strings.TrimSpace(string(remoteBytes)) != repository.Remote {
		return fmt.Errorf("repository remote does not match manifest: remote=%q err=%v", strings.TrimSpace(string(remoteBytes)), err)
	}
	branchBytes, err := git("branch", "--show-current")
	if err != nil {
		return fmt.Errorf("repository branch: %w", err)
	}
	branch := strings.TrimSpace(string(branchBytes))
	detached := branch == ""
	if detached {
		branch = "HEAD"
	}
	if branch != repository.Branch || detached != repository.Detached {
		return fmt.Errorf("repository branch identity branch=%q detached=%t, want branch=%q detached=%t", branch, detached, repository.Branch, repository.Detached)
	}
	treeBytes, err := git("rev-parse", repository.SourceHEAD+"^{tree}")
	if err != nil || strings.TrimSpace(string(treeBytes)) != repository.GitTree {
		return fmt.Errorf("source HEAD tree does not match manifest: tree=%q err=%v", strings.TrimSpace(string(treeBytes)), err)
	}
	if _, err := git("merge-base", "--is-ancestor", repository.SourceHEAD, "HEAD"); err != nil {
		return fmt.Errorf("source HEAD is not an ancestor of current HEAD: %w", err)
	}
	changedBytes, err := git("diff", "--name-only", "-z", repository.SourceHEAD+"..HEAD")
	if err != nil {
		return fmt.Errorf("repository post-source diff: %w", err)
	}
	changed, err := parseNULPaths(changedBytes)
	if err != nil {
		return err
	}
	for _, name := range changed {
		if !strings.HasPrefix(name, phase0ReceiptPrefix) {
			return fmt.Errorf("post-source HEAD changed non-receipt path %q", name)
		}
	}
	return nil
}

type listedModule struct {
	Path    string
	Main    bool
	Dir     string
	GoMod   string
	Replace *listedModule
}

func validateModuleGraphArtifact(manifest Manifest, data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	mainFound := false
	rootFound := false
	for {
		var module listedModule
		if err := decoder.Decode(&module); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("decode module graph: %w", err)
		}
		if module.Main {
			if mainFound || module.Path != "github.com/zchee/gows/bench" || filepath.Clean(module.Dir) != filepath.Join(manifest.Repository.Root, "bench") {
				return fmt.Errorf("invalid main benchmark module identity: %+v", module)
			}
			mainFound = true
		}
		if module.Path == "github.com/zchee/gows" {
			if rootFound || module.Replace == nil || filepath.Clean(module.Replace.Dir) != manifest.Repository.Root || filepath.Clean(module.Dir) != manifest.Repository.Root {
				return fmt.Errorf("invalid replaced root module identity: %+v", module)
			}
			rootFound = true
		}
	}
	if !mainFound || !rootFound {
		return fmt.Errorf("module graph missing main/root modules: main=%t root=%t", mainFound, rootFound)
	}
	return nil
}

func verifyCurrentSource(repoRoot string, source SourceFile) error {
	data, mode, err := readRepositoryFile(repoRoot, source.Path)
	if err != nil {
		return err
	}
	if mode != "file" || int64(len(data)) != source.Size {
		return fmt.Errorf("source %q mode/size changed", source.Path)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != source.SHA256 {
		return fmt.Errorf("source %q sha256 changed", source.Path)
	}
	return nil
}

func referencedArtifacts(manifest Manifest) []Artifact {
	artifacts := []Artifact{
		manifest.Repository.Status,
		manifest.Modules.Graph,
		manifest.Binary,
		manifest.Version,
		manifest.GoEnv,
		manifest.BuildGraph.GoList,
		manifest.Symbols.NM,
	}
	for _, pkg := range manifest.Packages {
		artifacts = append(artifacts, pkg.GoList, pkg.Object)
	}
	for _, symbol := range manifest.Symbols.Records {
		artifacts = append(artifacts, symbol.Objdump)
	}
	for _, dispatcher := range manifest.Dispatch.Records {
		artifacts = append(artifacts, dispatcher.Objdump)
	}
	if manifest.CPU.Runtime.Available {
		artifacts = append(artifacts, manifest.CPU.Runtime.ExecutionEvidence)
	}
	return artifacts
}

func cleanArtifactPath(artifactPath string) (string, error) {
	if artifactPath == "" || strings.ContainsRune(artifactPath, '\\') || path.IsAbs(artifactPath) {
		return "", fmt.Errorf("assembly bundle: unsafe artifact path %q", artifactPath)
	}
	clean := path.Clean(artifactPath)
	if clean != artifactPath || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || clean == manifestName {
		return "", fmt.Errorf("assembly bundle: unsafe artifact path %q", artifactPath)
	}
	return clean, nil
}

func verifyArtifactBytes(artifact Artifact, data []byte) error {
	if int64(len(data)) != artifact.Size {
		return fmt.Errorf("assembly bundle: artifact %q size %d, want %d", artifact.Path, len(data), artifact.Size)
	}
	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	if got != artifact.SHA256 {
		return fmt.Errorf("assembly bundle: artifact %q sha256 %s, want %s", artifact.Path, got, artifact.SHA256)
	}
	return nil
}

func writeImmutableFile(root, artifactPath string, data []byte) (resultErr error) {
	// The manifest is the one artifact allowed at the bundle root by that exact
	// name; every other artifact path must pass the containment rules that
	// cleanArtifactPath (which deliberately rejects manifestName) enforces.
	clean := manifestName
	if artifactPath != manifestName {
		var err error
		if clean, err = cleanArtifactPath(artifactPath); err != nil {
			return err
		}
	}
	filename := filepath.Join(root, filepath.FromSlash(clean))
	if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
		return fmt.Errorf("assembly bundle: create artifact parent %q: %w", clean, err)
	}
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o444)
	if err != nil {
		return fmt.Errorf("assembly bundle: create artifact %q: %w", clean, err)
	}
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, file.Close())
		}
	}()
	writer := bufio.NewWriter(file)
	if _, err := writer.Write(data); err != nil {
		return fmt.Errorf("assembly bundle: write artifact %q: %w", clean, err)
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("assembly bundle: flush artifact %q: %w", clean, err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("assembly bundle: sync artifact %q: %w", clean, err)
	}
	closeErr := file.Close()
	closed = true
	if closeErr != nil {
		return fmt.Errorf("assembly bundle: close artifact %q: %w", clean, closeErr)
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return err
	}
	return errors.New("trailing JSON value")
}

func syncDir(name string) error {
	dir, err := os.Open(name)
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}
