package assembly

import (
	"slices"
	"strings"
	"testing"
)

func TestManifestValidateSupportedTargets(t *testing.T) {
	for _, goarch := range []string{"amd64", "arm64"} {
		t.Run(goarch, func(t *testing.T) {
			manifest := validTestManifest(t, goarch)
			if err := manifest.ValidateFinal(); err != nil {
				t.Fatalf("ValidateFinal() error = %v", err)
			}
		})
	}
}

func TestManifestRejectsUnprovableAssemblyIdentity(t *testing.T) {
	tests := map[string]struct {
		mutate  func(*Manifest)
		wantErr string
	}{
		"old schema": {
			mutate: func(manifest *Manifest) {
				manifest.SchemaVersion--
			},
			wantErr: "schema_version",
		},
		"custom experiment": {
			mutate: func(manifest *Manifest) {
				manifest.Target.GOEXPERIMENT = "greenteagc"
				manifest.Target.Stock = false
			},
			wantErr: "not stock Go",
		},
		"wrong architecture source": {
			mutate: func(manifest *Manifest) {
				manifest.Packages[1].SelectedFiles = append(manifest.Packages[1].SelectedFiles, SourceFile{
					Path:   "internal/mask/mask_arm64.s",
					Kind:   "assembly",
					SHA256: testSHA,
					Size:   1,
				})
			},
			wantErr: "wrong-architecture",
		},
		"missing selected assembly source": {
			mutate: func(manifest *Manifest) {
				files := manifest.Packages[1].SelectedFiles
				manifest.Packages[1].SelectedFiles = slices.DeleteFunc(files, func(file SourceFile) bool {
					return file.Path == "internal/mask/mask_amd64.s"
				})
			},
			wantErr: "did not select required source",
		},
		"missing linked kernel symbol": {
			mutate: func(manifest *Manifest) {
				manifest.Symbols.Records = manifest.Symbols.Records[1:]
			},
			wantErr: "expected assembly symbol",
		},
		"reference oracle linked": {
			mutate: func(manifest *Manifest) {
				manifest.BuildGraph.Linked = append(manifest.BuildGraph.Linked, GraphNode{
					ImportPath: "github.com/zchee/gows/bench/internal/thirdparty/coder",
					Class:      GraphClassReference,
				})
			},
			wantErr: "reference-oracle package",
		},
		"runtime ISA override": {
			mutate: func(manifest *Manifest) {
				manifest.CPU.Runtime.GOWSSIMD = "sse2"
			},
			wantErr: "overridden",
		},
		"runtime dispatch mismatch": {
			mutate: func(manifest *Manifest) {
				manifest.CPU.Runtime.SelectedMask["4096"] = "sse2"
			},
			wantErr: "selected mask profile",
		},
		"uppercase source tree hash": {
			mutate: func(manifest *Manifest) {
				manifest.Repository.SourceTreeSHA256 = strings.Repeat("A", 64)
			},
			wantErr: "source-tree identity",
		},
		"uppercase git identity": {
			mutate: func(manifest *Manifest) {
				manifest.Repository.SourceHEAD = strings.Repeat("A", 40)
			},
			wantErr: "repository object identity",
		},
		"noncanonical artifact path": {
			mutate: func(manifest *Manifest) {
				manifest.Binary.Path = "binary/../probe"
			},
			wantErr: "binary artifact is invalid",
		},
		"relative Go tool path": {
			mutate: func(manifest *Manifest) {
				manifest.Toolchain.GoBinaryPath = "toolchain/bin/go"
			},
			wantErr: "Go toolchain binary identity",
		},
		"uppercase module hash": {
			mutate: func(manifest *Manifest) {
				manifest.Modules.BenchFilesSHA256 = strings.Repeat("B", 64)
			},
			wantErr: "module file hashes",
		},
		"linked reference corpus": {
			mutate: func(manifest *Manifest) {
				manifest.BuildGraph.Corpus[0].Linked = true
			},
			wantErr: "corpus identity",
		},
		"corpus hash mismatch": {
			mutate: func(manifest *Manifest) {
				manifest.BuildGraph.Corpus[0].SHA256 = strings.Repeat("a", 64)
			},
			wantErr: "corpus hash",
		},
		"dispatcher object mismatch": {
			mutate: func(manifest *Manifest) {
				manifest.Dispatch.Records[0].ObjectSHA256 = strings.Repeat("a", 64)
			},
			wantErr: "source/object/package identity mismatch",
		},
		"dispatcher call edge mismatch": {
			mutate: func(manifest *Manifest) {
				manifest.Dispatch.Records[0].Calls[0].EvidenceLine = "0 CALL example.invalid.abi0(SB)"
			},
			wantErr: "invalid call edge",
		},
		"translated execution spoof": {
			mutate: func(manifest *Manifest) {
				manifest.Target.GOOS = "darwin"
				manifest.CPU.Runtime.GOOS = "darwin"
				manifest.CPU.Runtime.Execution = ExecutionIdentity{
					Method:               "darwin-sysctl",
					Machine:              "x86_64",
					TranslationAvailable: true,
					Translated:           true,
				}
			},
			wantErr: "invalid translated execution identity",
		},
		"dirty final identity": {
			mutate: func(manifest *Manifest) {
				manifest.Repository.Dirty = true
				manifest.Repository.Status.Size = 1
			},
			wantErr: "requires a clean repository",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			manifest := validTestManifest(t, "amd64")
			test.mutate(&manifest)
			err := manifest.ValidateFinal()
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("ValidateFinal() error = %v, want substring %q", err, test.wantErr)
			}
		})
	}
}

func TestManifestAcceptsNativeAndTranslatedDarwinIdentity(t *testing.T) {
	tests := map[string]struct {
		execution ExecutionIdentity
	}{
		"arm64": {
			execution: ExecutionIdentity{
				Method:                 "darwin-sysctl",
				Machine:                "arm64",
				TranslationAvailable:   true,
				PhysicalARM64Available: true,
			},
		},
		"amd64": {
			execution: ExecutionIdentity{
				Method:                 "darwin-sysctl",
				Machine:                "x86_64",
				TranslationAvailable:   true,
				Translated:             true,
				PhysicalARM64Available: true,
			},
		},
	}
	for goarch, test := range tests {
		t.Run(goarch, func(t *testing.T) {
			manifest := validTestManifest(t, goarch)
			manifest.Target.GOOS = "darwin"
			manifest.CPU.Runtime.GOOS = "darwin"
			manifest.CPU.Runtime.Execution = test.execution
			if err := manifest.ValidateFinal(); err != nil {
				t.Fatalf("ValidateFinal() error = %v", err)
			}
		})
	}
}

func TestManifestValidateFinalRequiresRuntimeDispatch(t *testing.T) {
	manifest := validTestManifest(t, "arm64")
	manifest.CPU.Runtime = RuntimeProfile{}
	if err := manifest.Validate(); err != nil {
		t.Fatalf("Validate() static evidence error = %v", err)
	}
	if err := manifest.ValidateFinal(); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("ValidateFinal() error = %v, want unavailable", err)
	}
}

const testSHA = "0000000000000000000000000000000000000000000000000000000000000000"

func validTestManifest(t *testing.T, goarch string) Manifest {
	t.Helper()
	baseline, maskProfiles, utf8Profiles, err := expectedProfiles(goarch)
	if err != nil {
		t.Fatal(err)
	}
	symbols, err := ExpectedSymbols(goarch)
	if err != nil {
		t.Fatal(err)
	}
	artifact := func(name string) Artifact {
		return Artifact{Path: name, SHA256: testSHA, Size: 0}
	}
	archSources := map[string]map[string][]SourceFile{
		"amd64": {
			"github.com/zchee/gows/internal/cpu": {
				{Path: "internal/cpu/cpu.go", Kind: "go", SHA256: testSHA, Size: 1},
				{Path: "internal/cpu/cpu_amd64.go", Kind: "go", SHA256: testSHA, Size: 1},
				{Path: "internal/cpu/cpuid_amd64.s", Kind: "assembly", SHA256: testSHA, Size: 1},
			},
			"github.com/zchee/gows/internal/mask": {
				{Path: "internal/mask/mask_generic.go", Kind: "go", SHA256: testSHA, Size: 1},
				{Path: "internal/mask/mask_amd64.go", Kind: "go", SHA256: testSHA, Size: 1},
				{Path: "internal/mask/mask_amd64.s", Kind: "assembly", SHA256: testSHA, Size: 1},
			},
			"github.com/zchee/gows/internal/utf8x": {
				{Path: "internal/utf8x/valid.go", Kind: "go", SHA256: testSHA, Size: 1},
				{Path: "internal/utf8x/valid_simd.go", Kind: "go", SHA256: testSHA, Size: 1},
				{Path: "internal/utf8x/valid_simd_amd64.go", Kind: "go", SHA256: testSHA, Size: 1},
				{Path: "internal/utf8x/valid_amd64.s", Kind: "assembly", SHA256: testSHA, Size: 1},
			},
		},
		"arm64": {
			"github.com/zchee/gows/internal/cpu": {
				{Path: "internal/cpu/cpu.go", Kind: "go", SHA256: testSHA, Size: 1},
				{Path: "internal/cpu/cpu_arm64.go", Kind: "go", SHA256: testSHA, Size: 1},
			},
			"github.com/zchee/gows/internal/mask": {
				{Path: "internal/mask/mask_generic.go", Kind: "go", SHA256: testSHA, Size: 1},
				{Path: "internal/mask/mask_arm64.go", Kind: "go", SHA256: testSHA, Size: 1},
				{Path: "internal/mask/mask_arm64.s", Kind: "assembly", SHA256: testSHA, Size: 1},
			},
			"github.com/zchee/gows/internal/utf8x": {
				{Path: "internal/utf8x/valid.go", Kind: "go", SHA256: testSHA, Size: 1},
				{Path: "internal/utf8x/valid_simd.go", Kind: "go", SHA256: testSHA, Size: 1},
				{Path: "internal/utf8x/valid_simd_arm64.go", Kind: "go", SHA256: testSHA, Size: 1},
				{Path: "internal/utf8x/valid_arm64.s", Kind: "assembly", SHA256: testSHA, Size: 1},
			},
		},
	}

	packages := make([]PackageProvenance, 0, len(productionPackages))
	graph := []GraphNode{{ImportPath: probeImportPath, Class: GraphClassProbe}}
	for index, importPath := range productionPackages {
		packages = append(packages, PackageProvenance{
			ImportPath:    importPath,
			Class:         GraphClassProduction,
			SelectedFiles: archSources[goarch][importPath],
			GoList:        artifact("packages/list-" + string(rune('a'+index))),
			Object:        artifact("objects/object-" + string(rune('a'+index))),
		})
		graph = append(graph, GraphNode{ImportPath: importPath, Class: GraphClassProduction})
	}
	records := make([]SymbolRecord, 0, len(symbols))
	for index, symbol := range symbols {
		records = append(records, SymbolRecord{
			Name:    symbol,
			NMLine:  "0 1 T " + symbol + ".abi0",
			Objdump: artifact("symbols/objdump-" + string(rune('a'+index))),
		})
	}
	dispatchers, err := expectedDispatchers(goarch)
	if err != nil {
		t.Fatal(err)
	}
	dispatchRecords := make([]DispatchRecord, 0, len(dispatchers))
	packageByPath := make(map[string]PackageProvenance, len(packages))
	for _, pkg := range packages {
		packageByPath[pkg.ImportPath] = pkg
	}
	for index, dispatcher := range dispatchers {
		pkg := packageByPath[dispatcher.Package]
		var source SourceFile
		for _, selected := range pkg.SelectedFiles {
			if selected.Path == dispatcher.Source {
				source = selected
			}
		}
		calls := make([]CallEdge, 0, len(dispatcher.Calls))
		for _, callee := range dispatcher.Calls {
			calls = append(calls, CallEdge{Callee: callee, EvidenceLine: "0 CALL " + callee + ".abi0(SB)"})
		}
		dispatchRecords = append(dispatchRecords, DispatchRecord{
			Name:         dispatcher.Name,
			Package:      dispatcher.Package,
			Source:       source,
			ObjectSHA256: pkg.Object.SHA256,
			NMLine:       "0 1 T " + dispatcher.Name,
			Objdump:      artifact("dispatch/objdump-" + string(rune('a'+index))),
			Calls:        calls,
		})
	}
	runtimeProfile := RuntimeProfile{
		Available:         true,
		SchemaVersion:     SchemaVersion,
		GOOS:              "testos",
		GOARCH:            goarch,
		CPUFeatures:       map[string]bool{},
		SelectedMask:      map[string]string{},
		MaskSelfCheck:     true,
		UTF8SelfCheck:     true,
		ExecutionEvidence: artifact("runtime/profile"),
		Execution: ExecutionIdentity{
			Method:  "runtime",
			Machine: goarch,
		},
	}
	if goarch == "amd64" {
		runtimeProfile.CPUFeatures = map[string]bool{"sse2": true, "avx2": true, "avx512": false}
		runtimeProfile.SelectedMask = map[string]string{"64": "sse2", "128": "avx2", "4096": "avx2", "65536": "avx2"}
		runtimeProfile.SelectedUTF8 = "avx2"
	} else {
		runtimeProfile.CPUFeatures = map[string]bool{"neon": true}
		runtimeProfile.SelectedMask = map[string]string{"32": "neon", "64": "neon", "4096": "neon"}
		runtimeProfile.SelectedUTF8 = "neon"
	}
	manifest := Manifest{
		SchemaVersion: SchemaVersion,
		Repository: RepositoryIdentity{
			Root:                "/repo",
			Remote:              "git@github.com:zchee/gows.git",
			Branch:              "fastest-claude",
			SourceHEAD:          "1111111111111111111111111111111111111111",
			GitTree:             "2222222222222222222222222222222222222222",
			Status:              artifact("repository/status.txt"),
			Stable:              true,
			SourceTreeSHA256:    testSHA,
			SourceTreeFiles:     1,
			SourceTreeAlgorithm: SourceTreeHashAlgorithm,
		},
		Modules: ModuleIdentity{
			RootFilesSHA256:  testSHA,
			BenchFilesSHA256: testSHA,
			Graph:            artifact("modules/graph.json"),
		},
		Target: Target{
			GOOS:        "testos",
			GOARCH:      goarch,
			GOENV:       "off",
			GOTOOLCHAIN: "local",
			GOFLAGS:     "-mod=mod",
			GOFIPS140:   "latest",
			GOAMD64:     map[string]string{"amd64": "v1"}[goarch],
			GOARM64:     map[string]string{"arm64": "v8.0"}[goarch],
			CGOEnabled:  "0",
			Stock:       true,
		},
		Toolchain: Toolchain{
			GoVersion:      "go1.test",
			GoBinaryPath:   "/toolchain/bin/go",
			GoBinarySHA256: testSHA,
			GoBinarySize:   1,
		},
		Binary:  artifact("binary/probe"),
		Version: artifact("binary/version"),
		GoEnv:   artifact("toolchain/env"),
		BuildGraph: BuildGraph{
			GoList:            artifact("graph/list"),
			Linked:            graph,
			ReferenceExcluded: slices.Clone(referencePrefixes),
			Corpus: []Corpus{
				{
					Class:         GraphClassReference,
					HashAlgorithm: CorpusHashAlgorithm,
					Files: []SourceFile{{
						Path: "bench/internal/thirdparty/coder/mask.go", Kind: GraphClassReference, SHA256: testSHA, Size: 1,
					}},
				},
				{
					Class:         GraphClassTest,
					HashAlgorithm: CorpusHashAlgorithm,
					Files: []SourceFile{{
						Path: "internal/mask/mask_test.go", Kind: GraphClassTest, SHA256: testSHA, Size: 1,
					}},
				},
			},
		},
		Packages: packages,
		Symbols: SymbolEvidence{
			NM:      artifact("symbols/nm"),
			Records: records,
		},
		Dispatch: DispatchEvidence{Records: dispatchRecords},
		CPU: CPUProfile{
			ArchitectureBaseline: baseline,
			LinkedMaskProfiles:   maskProfiles,
			LinkedUTF8Profiles:   utf8Profiles,
			Runtime:              runtimeProfile,
		},
	}
	for index := range manifest.BuildGraph.Corpus {
		entry := &manifest.BuildGraph.Corpus[index]
		entry.SHA256 = corpusHash(entry.Class, entry.Files)
	}
	return manifest
}
