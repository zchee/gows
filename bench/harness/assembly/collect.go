package assembly

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"

	"github.com/zchee/gows/bench/harness/support"
)

const probeImportPath = "github.com/zchee/gows/bench/harness/cmd/asmprobetarget"

var productionPackages = []string{
	"github.com/zchee/gows/internal/cpu",
	"github.com/zchee/gows/internal/mask",
	"github.com/zchee/gows/internal/utf8x",
}

var referencePrefixes = []string{
	"github.com/zchee/gows/bench/internal/thirdparty/",
}

// Config controls one supported-target collection.
type Config struct {
	RepoRoot string
	GOOS     string
	GOARCH   string
	// TargetGoRoot selects the compiler that produces the target bundle. An
	// empty value preserves the historical runtime.GOROOT default.
	TargetGoRoot string
	RunRuntime   bool
	AllowDirty   bool
}

// Bundle contains a manifest and all immutable artifacts referenced by it.
type Bundle struct {
	Manifest  Manifest
	Artifacts map[string][]byte
}

type listedPackage struct {
	Dir        string
	ImportPath string
	GoFiles    []string
	CgoFiles   []string
	SFiles     []string
	Export     string
}

type goEnvironment struct {
	CGOEnabled   string `json:"CGO_ENABLED"`
	GOARCH       string `json:"GOARCH"`
	GOARM64      string `json:"GOARM64"`
	GOENV        string `json:"GOENV"`
	GOEXPERIMENT string `json:"GOEXPERIMENT"`
	GOFIPS140    string `json:"GOFIPS140"`
	GOFLAGS      string `json:"GOFLAGS"`
	GOOS         string `json:"GOOS"`
	GOAMD64      string `json:"GOAMD64"`
	GOROOT       string `json:"GOROOT"`
	GOTOOLCHAIN  string `json:"GOTOOLCHAIN"`
	GOVERSION    string `json:"GOVERSION"`
}

// Collect builds a stock target probe and captures source, object, binary,
// symbol, disassembly, graph, and optional runtime-dispatch evidence.
func Collect(ctx context.Context, cfg Config) (_ Bundle, resultErr error) {
	if cfg.RepoRoot == "" {
		return Bundle{}, errors.New("assembly collect: repository root is empty")
	}
	repoRoot, err := canonicalRepositoryRoot(cfg.RepoRoot)
	if err != nil {
		return Bundle{}, fmt.Errorf("assembly collect: repository root: %w", err)
	}
	if _, err := os.Stat(filepath.Join(repoRoot, "go.mod")); err != nil {
		return Bundle{}, fmt.Errorf("assembly collect: repository go.mod: %w", err)
	}
	if cfg.GOOS == "" {
		return Bundle{}, errors.New("assembly collect: GOOS is empty")
	}
	if _, err := ExpectedSymbols(cfg.GOARCH); err != nil {
		return Bundle{}, err
	}
	goRoot, goTool, err := resolveTargetGoRoot(cfg.TargetGoRoot)
	if err != nil {
		return Bundle{}, fmt.Errorf("assembly collect: target toolchain: %w", err)
	}
	repository, err := collectRepositorySnapshot(ctx, repoRoot)
	if err != nil {
		return Bundle{}, fmt.Errorf("assembly collect: repository identity: %w", err)
	}
	if repository.Identity.Dirty && !cfg.AllowDirty {
		return Bundle{}, errors.New("assembly collect: final provenance requires a clean repository; use AllowDirty only for explicitly diagnostic evidence")
	}

	benchRoot := filepath.Join(repoRoot, "bench")
	tempDir, err := os.MkdirTemp("", "gows-asmprov-")
	if err != nil {
		return Bundle{}, fmt.Errorf("assembly collect: create temporary directory: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("assembly collect: clean temporary directory: %w", err))
		}
	}()

	goToolSum, goToolSize, err := support.FileSHA256(goTool)
	if err != nil {
		return Bundle{}, fmt.Errorf("assembly collect: read resolved Go tool %q: %w", goTool, err)
	}
	env := targetEnvironment(os.Environ(), cfg.GOOS, cfg.GOARCH, goRoot, "latest")
	artifacts := make(map[string][]byte)
	targetID := cfg.GOOS + "-" + cfg.GOARCH
	repository.Identity.Status = addArtifact(artifacts, "repository/status.txt", repository.Status)

	goEnvBytes, err := run(ctx, env, goTool, "env", "-json")
	if err != nil {
		return Bundle{}, fmt.Errorf("assembly collect: go env: %w", err)
	}
	goEnvArtifact := addArtifact(artifacts, "toolchain/"+targetID+"/go-env.json", goEnvBytes)
	var effectiveGoEnv goEnvironment
	if err := json.Unmarshal(goEnvBytes, &effectiveGoEnv); err != nil {
		return Bundle{}, fmt.Errorf("assembly collect: decode stock go env: %w", err)
	}
	if effectiveGoEnv.GOEXPERIMENT != "" {
		return Bundle{}, fmt.Errorf("assembly collect: resolved target toolchain is not stock: GOEXPERIMENT=%q", effectiveGoEnv.GOEXPERIMENT)
	}
	if effectiveGoEnv.GOROOT != goRoot {
		return Bundle{}, fmt.Errorf("assembly collect: stock Go tool reported GOROOT %q, want %q", effectiveGoEnv.GOROOT, goRoot)
	}
	// The manifest target mandates GOFLAGS=-mod=mod, under which an
	// incompletely locked bench/go.sum would let this listing rewrite the
	// repository mid-collection; readonly turns that into a hard error.
	moduleGraphBytes, err := run(ctx, env, goTool, "-C", benchRoot, "list", "-mod=readonly", "-m", "-json", "all")
	if err != nil {
		return Bundle{}, fmt.Errorf("assembly collect: module graph: %w", err)
	}
	repository.Modules.Graph = addArtifact(artifacts, "modules/"+targetID+"/go-list-m-all.json", moduleGraphBytes)

	binaryPath := filepath.Join(tempDir, "asmprobetarget")
	buildArgs := []string{
		"-C", benchRoot,
		"build",
		"-trimpath",
		"-buildvcs=false",
		"-o", binaryPath,
		"./harness/cmd/asmprobetarget",
	}
	if _, err := run(ctx, env, goTool, buildArgs...); err != nil {
		return Bundle{}, fmt.Errorf("assembly collect: link target probe: %w", err)
	}
	binaryBytes, err := os.ReadFile(binaryPath)
	if err != nil {
		return Bundle{}, fmt.Errorf("assembly collect: read target probe: %w", err)
	}
	binaryArtifact := addArtifact(artifacts, "binary/"+targetID+"/asmprobetarget", binaryBytes)

	versionBytes, err := run(ctx, env, goTool, "version", "-m", binaryPath)
	if err != nil {
		return Bundle{}, fmt.Errorf("assembly collect: go version -m: %w", err)
	}
	versionBytes, err = normalizeVersionM(versionBytes, binaryPath, binaryArtifact.Path)
	if err != nil {
		return Bundle{}, fmt.Errorf("assembly collect: normalize go version -m: %w", err)
	}
	versionArtifact := addArtifact(artifacts, "binary/"+targetID+"/go-version-m.txt", versionBytes)

	graphBytes, err := run(ctx, env, goTool, "-C", benchRoot, "list", "-deps", "-json", "./harness/cmd/asmprobetarget")
	if err != nil {
		return Bundle{}, fmt.Errorf("assembly collect: linked build graph: %w", err)
	}
	graphArtifact := addArtifact(artifacts, "graph/"+targetID+"/go-list-deps.json", graphBytes)
	graphNodes, err := decodeGraph(graphBytes)
	if err != nil {
		return Bundle{}, fmt.Errorf("assembly collect: decode linked build graph: %w", err)
	}

	packages := make([]PackageProvenance, 0, len(productionPackages))
	for _, importPath := range productionPackages {
		listBytes, err := run(ctx, env, goTool, "-C", benchRoot, "list", "-export", "-json", importPath)
		if err != nil {
			return Bundle{}, fmt.Errorf("assembly collect: go list %s: %w", importPath, err)
		}
		var listed listedPackage
		if err := json.Unmarshal(listBytes, &listed); err != nil {
			return Bundle{}, fmt.Errorf("assembly collect: decode go list %s: %w", importPath, err)
		}
		if listed.ImportPath != importPath || listed.Dir == "" || listed.Export == "" {
			return Bundle{}, fmt.Errorf("assembly collect: incomplete go list for %s", importPath)
		}
		listArtifact := addArtifact(artifacts, "packages/"+targetID+"/"+packageSlug(importPath)+".go-list.json", listBytes)
		objectBytes, err := os.ReadFile(listed.Export)
		if err != nil {
			return Bundle{}, fmt.Errorf("assembly collect: read object archive %s: %w", importPath, err)
		}
		objectArtifact := addArtifact(artifacts, "objects/"+targetID+"/"+packageSlug(importPath)+".a", objectBytes)
		selectedFiles, err := hashSelectedFiles(repoRoot, listed)
		if err != nil {
			return Bundle{}, fmt.Errorf("assembly collect: selected sources %s: %w", importPath, err)
		}
		packages = append(packages, PackageProvenance{
			ImportPath:    importPath,
			Class:         GraphClassProduction,
			SelectedFiles: selectedFiles,
			GoList:        listArtifact,
			Object:        objectArtifact,
		})
	}

	nmBytes, err := run(ctx, env, goTool, "tool", "nm", "-size", "-sort", "name", binaryPath)
	if err != nil {
		return Bundle{}, fmt.Errorf("assembly collect: go tool nm: %w", err)
	}
	nmArtifact := addArtifact(artifacts, "symbols/"+targetID+"/nm.txt", nmBytes)
	expectedSymbols, _ := ExpectedSymbols(cfg.GOARCH)
	symbolRecords := make([]SymbolRecord, 0, len(expectedSymbols))
	for _, symbol := range expectedSymbols {
		nmLine, err := findSymbolLine(nmBytes, symbol)
		if err != nil {
			return Bundle{}, fmt.Errorf("assembly collect: %w", err)
		}
		objdumpBytes, err := run(ctx, env, goTool, "tool", "objdump", "-s", regexp.QuoteMeta(symbol), binaryPath)
		if err != nil {
			return Bundle{}, fmt.Errorf("assembly collect: objdump %s: %w", symbol, err)
		}
		if len(bytes.TrimSpace(objdumpBytes)) == 0 {
			return Bundle{}, fmt.Errorf("assembly collect: objdump %s produced no evidence", symbol)
		}
		symbolRecords = append(symbolRecords, SymbolRecord{
			Name:    symbol,
			NMLine:  nmLine,
			Objdump: addArtifact(artifacts, "symbols/"+targetID+"/objdump/"+symbolSlug(symbol)+".txt", objdumpBytes),
		})
	}
	dispatch, err := collectDispatchEvidence(ctx, env, goTool, binaryPath, nmBytes, packages, cfg.GOARCH, targetID, artifacts)
	if err != nil {
		return Bundle{}, fmt.Errorf("assembly collect: dispatch evidence: %w", err)
	}

	baseline, maskProfiles, utf8Profiles, _ := expectedProfiles(cfg.GOARCH)
	runtimeProfile := RuntimeProfile{}
	if cfg.RunRuntime {
		runtimeBytes, err := run(ctx, env, binaryPath)
		if err != nil {
			return Bundle{}, fmt.Errorf("assembly collect: execute %s/%s target probe without ISA override: %w", cfg.GOOS, cfg.GOARCH, err)
		}
		if err := json.Unmarshal(runtimeBytes, &runtimeProfile); err != nil {
			return Bundle{}, fmt.Errorf("assembly collect: decode runtime profile: %w", err)
		}
		runtimeProfile.Available = true
		runtimeProfile.ExecutionEvidence = addArtifact(artifacts, "runtime/"+targetID+"/profile.json", runtimeBytes)
	}

	manifest := Manifest{
		SchemaVersion: SchemaVersion,
		Repository:    repository.Identity,
		Modules:       repository.Modules,
		Target: Target{
			GOOS:         effectiveGoEnv.GOOS,
			GOARCH:       effectiveGoEnv.GOARCH,
			GOEXPERIMENT: effectiveGoEnv.GOEXPERIMENT,
			GOENV:        "off",
			GOTOOLCHAIN:  effectiveGoEnv.GOTOOLCHAIN,
			GOFLAGS:      effectiveGoEnv.GOFLAGS,
			GOFIPS140:    effectiveGoEnv.GOFIPS140,
			GOAMD64:      targetSetting(cfg.GOARCH, "amd64", effectiveGoEnv.GOAMD64),
			GOARM64:      targetSetting(cfg.GOARCH, "arm64", effectiveGoEnv.GOARM64),
			CGOEnabled:   effectiveGoEnv.CGOEnabled,
			Stock:        effectiveGoEnv.GOEXPERIMENT == "",
		},
		Toolchain: Toolchain{
			GoVersion:      effectiveGoEnv.GOVERSION,
			GoBinaryPath:   goTool,
			GoBinarySHA256: goToolSum,
			GoBinarySize:   goToolSize,
		},
		Binary:  binaryArtifact,
		Version: versionArtifact,
		GoEnv:   goEnvArtifact,
		BuildGraph: BuildGraph{
			GoList:            graphArtifact,
			Linked:            graphNodes,
			ReferenceExcluded: slices.Clone(referencePrefixes),
			Corpus:            repository.Corpus,
		},
		Packages: packages,
		Symbols: SymbolEvidence{
			NM:      nmArtifact,
			Records: symbolRecords,
		},
		Dispatch: dispatch,
		CPU: CPUProfile{
			ArchitectureBaseline: baseline,
			LinkedMaskProfiles:   maskProfiles,
			LinkedUTF8Profiles:   utf8Profiles,
			Runtime:              runtimeProfile,
		},
	}
	finalRepository, err := collectRepositorySnapshot(ctx, repoRoot)
	if err != nil {
		return Bundle{}, fmt.Errorf("assembly collect: final repository identity: %w", err)
	}
	stableRepository := equalRepositorySnapshot(repository, finalRepository)
	if !stableRepository && !cfg.AllowDirty {
		return Bundle{}, errors.New("assembly collect: repository identity changed during collection")
	}
	manifest.Repository.Stable = stableRepository
	if cfg.RunRuntime && !cfg.AllowDirty {
		err = manifest.ValidateFinal()
	} else {
		err = manifest.Validate()
	}
	if err != nil {
		return Bundle{}, fmt.Errorf("assembly collect: generated manifest: %w", err)
	}
	return Bundle{Manifest: manifest, Artifacts: artifacts}, nil
}

// resolveTargetGoRoot resolves and validates the compiler used to produce a
// target bundle. Explicit roots must already be absolute, clean and canonical;
// rejecting aliases prevents provenance from depending on invocation spelling.
func resolveTargetGoRoot(explicit string) (string, string, error) {
	root := explicit
	if root == "" {
		root = compilerGoRoot()
	}
	if !filepath.IsAbs(root) {
		return "", "", fmt.Errorf("GOROOT %q is not absolute", root)
	}
	cleanRoot := filepath.Clean(root)
	if cleanRoot != root {
		return "", "", fmt.Errorf("GOROOT %q is not clean", root)
	}
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", "", fmt.Errorf("resolve GOROOT %q: %w", root, err)
	}
	canonicalRoot, err = filepath.Abs(canonicalRoot)
	if err != nil {
		return "", "", fmt.Errorf("absolute GOROOT %q: %w", root, err)
	}
	if canonicalRoot != root {
		return "", "", fmt.Errorf("GOROOT %q is not symlink-canonical (want %q)", root, canonicalRoot)
	}
	goTool := filepath.Join(canonicalRoot, "bin", "go")
	canonicalTool, err := filepath.EvalSymlinks(goTool)
	if err != nil {
		return "", "", fmt.Errorf("resolve Go tool %q: %w", goTool, err)
	}
	canonicalTool, err = filepath.Abs(canonicalTool)
	if err != nil {
		return "", "", fmt.Errorf("absolute Go tool %q: %w", goTool, err)
	}
	if canonicalTool != goTool {
		return "", "", fmt.Errorf("Go tool %q is not symlink-canonical (want %q)", goTool, canonicalTool)
	}
	return canonicalRoot, canonicalTool, nil
}

// compilerGoRoot returns the exact compiler toolchain that built asmprobe;
// assembly provenance must not silently switch to a different PATH toolchain.
func compilerGoRoot() string {
	//lint:ignore SA1019 Exact build-toolchain identity is required by assembly provenance.
	return runtime.GOROOT() //nolint:staticcheck // Exact build-toolchain identity is required by assembly provenance.
}

func targetEnvironment(base []string, goos, goarch, goroot, gofips140 string) []string {
	overrides := map[string]string{
		"CGO_ENABLED":  "0",
		"GOARCH":       goarch,
		"GOENV":        "off",
		"GOEXPERIMENT": "",
		"GOFIPS140":    gofips140,
		"GOFLAGS":      "-mod=mod",
		"GOOS":         goos,
		"GOROOT":       goroot,
		"GOTOOLCHAIN":  "local",
		"GOWS_SIMD":    "",
	}
	if goarch == "amd64" {
		overrides["GOAMD64"] = "v1"
	}
	if goarch == "arm64" {
		overrides["GOARM64"] = "v8.0"
	}
	env := make([]string, 0, len(base)+len(overrides))
	for _, entry := range base {
		name, _, _ := strings.Cut(entry, "=")
		if name == "GOAMD64" || name == "GOARM64" {
			continue
		}
		if _, overridden := overrides[name]; overridden {
			continue
		}
		env = append(env, entry)
	}
	keys := make([]string, 0, len(overrides))
	for name := range overrides {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	for _, name := range keys {
		env = append(env, name+"="+overrides[name])
	}
	return env
}

func targetSetting(goarch, targetArch, value string) string {
	if goarch == targetArch {
		return value
	}
	return ""
}

func run(ctx context.Context, env []string, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func addArtifact(artifacts map[string][]byte, path string, data []byte) Artifact {
	copyOfData := bytes.Clone(data)
	artifacts[path] = copyOfData
	sum := sha256.Sum256(copyOfData)
	return Artifact{Path: path, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(copyOfData))}
}

func decodeGraph(data []byte) ([]GraphNode, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var nodes []GraphNode
	for {
		var listed listedPackage
		if err := decoder.Decode(&listed); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		class := classifyPackage(listed.ImportPath)
		if class != "" {
			nodes = append(nodes, GraphNode{ImportPath: listed.ImportPath, Class: class})
		}
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ImportPath < nodes[j].ImportPath })
	return nodes, nil
}

func classifyPackage(importPath string) string {
	if importPath == probeImportPath {
		return GraphClassProbe
	}
	for _, prefix := range referencePrefixes {
		if strings.HasPrefix(importPath, prefix) {
			return GraphClassReference
		}
	}
	if importPath == "github.com/zchee/gows" ||
		(strings.HasPrefix(importPath, "github.com/zchee/gows/") &&
			!strings.HasPrefix(importPath, "github.com/zchee/gows/bench/")) {
		return GraphClassProduction
	}
	return ""
}

func hashSelectedFiles(repoRoot string, listed listedPackage) ([]SourceFile, error) {
	files := make([]SourceFile, 0, len(listed.GoFiles)+len(listed.CgoFiles)+len(listed.SFiles))
	for _, group := range []struct {
		kind  string
		names []string
	}{
		{kind: "go", names: listed.GoFiles},
		{kind: "cgo", names: listed.CgoFiles},
		{kind: "assembly", names: listed.SFiles},
	} {
		for _, name := range group.names {
			path := filepath.Join(listed.Dir, name)
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, err
			}
			rel, err := filepath.Rel(repoRoot, path)
			if err != nil || strings.HasPrefix(rel, "..") {
				return nil, fmt.Errorf("selected source %q is outside repository", path)
			}
			sum := sha256.Sum256(data)
			files = append(files, SourceFile{
				Path:   filepath.ToSlash(rel),
				Kind:   group.kind,
				SHA256: hex.EncodeToString(sum[:]),
				Size:   int64(len(data)),
			})
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

func findSymbolLine(nm []byte, symbol string) (string, error) {
	for line := range strings.SplitSeq(string(nm), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name := fields[len(fields)-1]
		if name == symbol || name == symbol+".abi0" {
			return line, nil
		}
	}
	return "", fmt.Errorf("expected assembly symbol %q is not present in linked binary", symbol)
}

func collectDispatchEvidence(
	ctx context.Context,
	env []string,
	goTool, binaryPath string,
	nmBytes []byte,
	packages []PackageProvenance,
	goarch, targetID string,
	artifacts map[string][]byte,
) (DispatchEvidence, error) {
	expected, err := expectedDispatchers(goarch)
	if err != nil {
		return DispatchEvidence{}, err
	}
	packageByPath := make(map[string]PackageProvenance, len(packages))
	for _, pkg := range packages {
		packageByPath[pkg.ImportPath] = pkg
	}
	records := make([]DispatchRecord, 0, len(expected))
	for _, dispatcher := range expected {
		pkg, ok := packageByPath[dispatcher.Package]
		if !ok {
			return DispatchEvidence{}, fmt.Errorf("dispatcher package %q is absent", dispatcher.Package)
		}
		var source SourceFile
		for _, selected := range pkg.SelectedFiles {
			if selected.Path == dispatcher.Source {
				source = selected
				break
			}
		}
		if source.Path == "" {
			return DispatchEvidence{}, fmt.Errorf("dispatcher source %q is not selected", dispatcher.Source)
		}
		nmLine, err := findSymbolLine(nmBytes, dispatcher.Name)
		if err != nil {
			return DispatchEvidence{}, err
		}
		objdumpBytes, err := run(ctx, env, goTool, "tool", "objdump", "-s", regexp.QuoteMeta(dispatcher.Name), binaryPath)
		if err != nil {
			return DispatchEvidence{}, err
		}
		if len(bytes.TrimSpace(objdumpBytes)) == 0 {
			return DispatchEvidence{}, fmt.Errorf("dispatcher objdump %q is empty", dispatcher.Name)
		}
		calls := make([]CallEdge, 0, len(dispatcher.Calls))
		for _, callee := range dispatcher.Calls {
			line, err := findCallEdge(objdumpBytes, callee)
			if err != nil {
				return DispatchEvidence{}, fmt.Errorf("dispatcher %q: %w", dispatcher.Name, err)
			}
			calls = append(calls, CallEdge{Callee: callee, EvidenceLine: line})
		}
		records = append(records, DispatchRecord{
			Name:         dispatcher.Name,
			Package:      dispatcher.Package,
			Source:       source,
			ObjectSHA256: pkg.Object.SHA256,
			NMLine:       nmLine,
			Objdump: addArtifact(
				artifacts,
				"dispatch/"+targetID+"/"+symbolSlug(dispatcher.Name)+".txt",
				objdumpBytes,
			),
			Calls: calls,
		})
	}
	return DispatchEvidence{Records: records}, nil
}

func findCallEdge(objdump []byte, callee string) (string, error) {
	needle := "CALL " + callee
	for line := range strings.SplitSeq(string(objdump), "\n") {
		if strings.Contains(line, needle) {
			return line, nil
		}
	}
	return "", fmt.Errorf("objdump has no call edge to %q", callee)
}

func packageSlug(importPath string) string {
	return strings.NewReplacer("github.com/zchee/gows/", "", "/", "-").Replace(importPath)
}

func symbolSlug(symbol string) string {
	return strings.NewReplacer("github.com/zchee/gows/", "", "/", "-", ".", "-").Replace(symbol)
}

func normalizeVersionM(data []byte, physicalPath, logicalPath string) ([]byte, error) {
	lineEnd := bytes.IndexByte(data, '\n')
	if lineEnd < 0 {
		return nil, errors.New("go version -m output has no metadata lines")
	}
	firstLine := string(data[:lineEnd])
	prefix := physicalPath + ": "
	if !strings.HasPrefix(firstLine, prefix) {
		return nil, fmt.Errorf("first line %q does not start with binary path %q", firstLine, physicalPath)
	}
	normalized := make([]byte, 0, len(data)-len(physicalPath)+len(logicalPath))
	normalized = append(normalized, logicalPath...)
	normalized = append(normalized, firstLine[len(physicalPath):]...)
	normalized = append(normalized, data[lineEnd:]...)
	return normalized, nil
}
