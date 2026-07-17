// Package assembly collects and validates assembly provenance for the
// supported gows benchmark targets.
package assembly

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

const (
	// SchemaVersion is incremented whenever the manifest validation contract
	// changes. Older versions are rejected rather than accepted implicitly.
	SchemaVersion = 2

	GraphClassProduction = "production"
	GraphClassProbe      = "probe"
	GraphClassReference  = "reference_oracle"
	GraphClassTest       = "test_oracle"

	SourceTreeHashAlgorithm = "sha256-path-content-excluding-phase0-receipts-v1"
	CorpusHashAlgorithm     = "sha256-class-path-content-v1"
)

// Manifest is the complete provenance record for one supported target.
type Manifest struct {
	SchemaVersion int                 `json:"schema_version"`
	Repository    RepositoryIdentity  `json:"repository"`
	Modules       ModuleIdentity      `json:"modules"`
	Target        Target              `json:"target"`
	Toolchain     Toolchain           `json:"toolchain"`
	Binary        Artifact            `json:"binary"`
	Version       Artifact            `json:"binary_version_m"`
	GoEnv         Artifact            `json:"go_env"`
	BuildGraph    BuildGraph          `json:"build_graph"`
	Packages      []PackageProvenance `json:"packages"`
	Symbols       SymbolEvidence      `json:"symbols"`
	Dispatch      DispatchEvidence    `json:"dispatch"`
	CPU           CPUProfile          `json:"cpu_profile"`
}

type RepositoryIdentity struct {
	Root                string   `json:"root"`
	Remote              string   `json:"remote"`
	Branch              string   `json:"branch"`
	Detached            bool     `json:"detached"`
	SourceHEAD          string   `json:"source_head"`
	GitTree             string   `json:"git_tree"`
	Dirty               bool     `json:"dirty"`
	Stable              bool     `json:"stable"`
	Status              Artifact `json:"status"`
	SourceTreeSHA256    string   `json:"source_tree_sha256"`
	SourceTreeFiles     int      `json:"source_tree_files"`
	SourceTreeAlgorithm string   `json:"source_tree_algorithm"`
}

type ModuleIdentity struct {
	RootFilesSHA256  string   `json:"root_files_sha256"`
	BenchFilesSHA256 string   `json:"bench_files_sha256"`
	Graph            Artifact `json:"graph"`
}

type Target struct {
	GOOS         string `json:"goos"`
	GOARCH       string `json:"goarch"`
	GOEXPERIMENT string `json:"goexperiment"`
	GOENV        string `json:"goenv"`
	GOTOOLCHAIN  string `json:"gotoolchain"`
	GOFLAGS      string `json:"goflags"`
	GOFIPS140    string `json:"gofips140,omitempty"`
	GOAMD64      string `json:"goamd64,omitempty"`
	GOARM64      string `json:"goarm64,omitempty"`
	CGOEnabled   string `json:"cgo_enabled"`
	Stock        bool   `json:"stock"`
}

type Toolchain struct {
	GoVersion      string `json:"go_version"`
	GoBinaryPath   string `json:"go_binary_path"`
	GoBinarySHA256 string `json:"go_binary_sha256"`
	GoBinarySize   int64  `json:"go_binary_size"`
}

// Artifact identifies immutable bytes within the bundle.
type Artifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type SourceFile struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type PackageProvenance struct {
	ImportPath    string       `json:"import_path"`
	Class         string       `json:"class"`
	SelectedFiles []SourceFile `json:"selected_files"`
	GoList        Artifact     `json:"go_list"`
	Object        Artifact     `json:"object"`
}

type BuildGraph struct {
	GoList            Artifact    `json:"go_list"`
	Linked            []GraphNode `json:"linked"`
	ReferenceExcluded []string    `json:"reference_excluded"`
	Corpus            []Corpus    `json:"corpus"`
}

type Corpus struct {
	Class         string       `json:"class"`
	Linked        bool         `json:"linked"`
	SHA256        string       `json:"sha256"`
	HashAlgorithm string       `json:"hash_algorithm"`
	Files         []SourceFile `json:"files"`
}

type GraphNode struct {
	ImportPath string `json:"import_path"`
	Class      string `json:"class"`
}

type SymbolEvidence struct {
	NM      Artifact       `json:"nm"`
	Records []SymbolRecord `json:"records"`
}

type SymbolRecord struct {
	Name    string   `json:"name"`
	NMLine  string   `json:"nm_line"`
	Objdump Artifact `json:"objdump"`
}

type DispatchEvidence struct {
	Records []DispatchRecord `json:"records"`
}

type DispatchRecord struct {
	Name         string     `json:"name"`
	Package      string     `json:"package"`
	Source       SourceFile `json:"source"`
	ObjectSHA256 string     `json:"object_sha256"`
	NMLine       string     `json:"nm_line"`
	Objdump      Artifact   `json:"objdump"`
	Calls        []CallEdge `json:"calls"`
}

type CallEdge struct {
	Callee       string `json:"callee"`
	EvidenceLine string `json:"evidence_line"`
}

type CPUProfile struct {
	ArchitectureBaseline []string       `json:"architecture_baseline"`
	LinkedMaskProfiles   []string       `json:"linked_mask_profiles"`
	LinkedUTF8Profiles   []string       `json:"linked_utf8_profiles"`
	Runtime              RuntimeProfile `json:"runtime"`
}

// RuntimeProfile is emitted by the linked probe binary. Selected profiles are
// derived from the exact production dispatch predicates in the linked source;
// the source and object hashes bind those predicates to this record.
type RuntimeProfile struct {
	Available         bool              `json:"available"`
	SchemaVersion     int               `json:"schema_version,omitempty"`
	GOOS              string            `json:"goos,omitempty"`
	GOARCH            string            `json:"goarch,omitempty"`
	GOWSSIMD          string            `json:"gows_simd,omitempty"`
	CPUFeatures       map[string]bool   `json:"cpu_features,omitempty"`
	SelectedMask      map[string]string `json:"selected_mask,omitempty"`
	SelectedUTF8      string            `json:"selected_utf8,omitempty"`
	MaskSelfCheck     bool              `json:"mask_self_check,omitempty"`
	UTF8SelfCheck     bool              `json:"utf8_self_check,omitempty"`
	ExecutionEvidence Artifact          `json:"execution_evidence"`
	Execution         ExecutionIdentity `json:"execution"`
}

type ExecutionIdentity struct {
	Method                 string `json:"method,omitempty"`
	Machine                string `json:"machine,omitempty"`
	TranslationAvailable   bool   `json:"translation_available,omitempty"`
	Translated             bool   `json:"translated,omitempty"`
	PhysicalARM64Available bool   `json:"physical_arm64_available,omitempty"`
}

// ExpectedSymbols returns the production kernels that must be linked for a
// supported target. It deliberately has no fallback for other architectures.
func ExpectedSymbols(goarch string) ([]string, error) {
	switch goarch {
	case "amd64":
		return []string{
			"github.com/zchee/gows/internal/cpu.cpuid",
			"github.com/zchee/gows/internal/cpu.xgetbv",
			"github.com/zchee/gows/internal/mask.maskSSE2",
			"github.com/zchee/gows/internal/mask.maskAVX2",
			"github.com/zchee/gows/internal/mask.maskAVX512",
			"github.com/zchee/gows/internal/utf8x.utf8ValidAVX2",
		}, nil
	case "arm64":
		return []string{
			"github.com/zchee/gows/internal/mask.maskNEON",
			"github.com/zchee/gows/internal/utf8x.utf8ValidNEON",
		}, nil
	default:
		return nil, fmt.Errorf("unsupported assembly target %q", goarch)
	}
}

type expectedDispatch struct {
	Name    string
	Package string
	Source  string
	Calls   []string
}

func expectedDispatchers(goarch string) ([]expectedDispatch, error) {
	switch goarch {
	case "amd64":
		return []expectedDispatch{
			{
				Name:    "github.com/zchee/gows/internal/cpu.init.0",
				Package: "github.com/zchee/gows/internal/cpu",
				Source:  "internal/cpu/cpu_amd64.go",
				Calls: []string{
					"github.com/zchee/gows/internal/cpu.cpuid",
					"github.com/zchee/gows/internal/cpu.xgetbv",
				},
			},
			{
				Name:    "github.com/zchee/gows/internal/mask.Mask",
				Package: "github.com/zchee/gows/internal/mask",
				Source:  "internal/mask/mask_amd64.go",
				Calls: []string{
					"github.com/zchee/gows/internal/mask.maskSSE2",
					"github.com/zchee/gows/internal/mask.maskAVX2",
					"github.com/zchee/gows/internal/mask.maskAVX512",
				},
			},
			{
				Name:    "github.com/zchee/gows/internal/utf8x.simdBulk",
				Package: "github.com/zchee/gows/internal/utf8x",
				Source:  "internal/utf8x/valid_simd_amd64.go",
				Calls:   []string{"github.com/zchee/gows/internal/utf8x.utf8ValidAVX2"},
			},
		}, nil
	case "arm64":
		return []expectedDispatch{
			{
				Name:    "github.com/zchee/gows/internal/cpu.init.0",
				Package: "github.com/zchee/gows/internal/cpu",
				Source:  "internal/cpu/cpu_arm64.go",
			},
			{
				Name:    "github.com/zchee/gows/internal/mask.Mask",
				Package: "github.com/zchee/gows/internal/mask",
				Source:  "internal/mask/mask_arm64.go",
				Calls:   []string{"github.com/zchee/gows/internal/mask.maskNEON"},
			},
			{
				Name:    "github.com/zchee/gows/internal/utf8x.simdBulk",
				Package: "github.com/zchee/gows/internal/utf8x",
				Source:  "internal/utf8x/valid_simd_arm64.go",
				Calls:   []string{"github.com/zchee/gows/internal/utf8x.utf8ValidNEON"},
			},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported assembly target %q", goarch)
	}
}

func expectedProfiles(goarch string) (baseline, mask, utf8 []string, err error) {
	switch goarch {
	case "amd64":
		return []string{"sse2"}, []string{"sse2", "avx2", "avx512"}, []string{"avx2"}, nil
	case "arm64":
		return []string{"neon"}, []string{"neon"}, []string{"neon"}, nil
	default:
		return nil, nil, nil, fmt.Errorf("unsupported assembly target %q", goarch)
	}
}

// Validate checks the static provenance contract and, when runtime evidence is
// present, its dispatch contract. Use ValidateFinal to require runtime proof.
func (m Manifest) Validate() error {
	if m.SchemaVersion != SchemaVersion {
		return fmt.Errorf("assembly manifest schema_version %d, want %d", m.SchemaVersion, SchemaVersion)
	}
	if m.Target.GOOS == "" {
		return errors.New("assembly manifest target goos is empty")
	}
	if err := validateRepositoryIdentity(m.Repository); err != nil {
		return err
	}
	if !validSHA256(m.Modules.RootFilesSHA256) || !validSHA256(m.Modules.BenchFilesSHA256) {
		return fmt.Errorf("invalid module file hashes: root=%q bench=%q", m.Modules.RootFilesSHA256, m.Modules.BenchFilesSHA256)
	}
	if err := validateArtifact("module graph", m.Modules.Graph); err != nil {
		return err
	}
	if m.Target.GOEXPERIMENT != "" || !m.Target.Stock {
		return fmt.Errorf("assembly manifest is not stock Go: goexperiment=%q stock=%t", m.Target.GOEXPERIMENT, m.Target.Stock)
	}
	if m.Target.CGOEnabled != "0" {
		return fmt.Errorf("assembly manifest cgo_enabled=%q, want 0", m.Target.CGOEnabled)
	}
	if m.Toolchain.GoVersion == "" {
		return errors.New("assembly manifest Go version is empty")
	}
	if m.Target.GOENV != "off" || m.Target.GOTOOLCHAIN != "local" || m.Target.GOFLAGS != "-mod=mod" || m.Target.GOFIPS140 != "latest" {
		return fmt.Errorf("uncontrolled Go environment: goenv=%q gotoolchain=%q goflags=%q gofips140=%q", m.Target.GOENV, m.Target.GOTOOLCHAIN, m.Target.GOFLAGS, m.Target.GOFIPS140)
	}
	if m.Toolchain.GoBinaryPath == "" || !filepath.IsAbs(m.Toolchain.GoBinaryPath) || filepath.Clean(m.Toolchain.GoBinaryPath) != m.Toolchain.GoBinaryPath ||
		m.Toolchain.GoBinarySize <= 0 || !validSHA256(m.Toolchain.GoBinarySHA256) {
		return fmt.Errorf("invalid Go toolchain binary identity: %+v", m.Toolchain)
	}
	expectedSymbols, err := ExpectedSymbols(m.Target.GOARCH)
	if err != nil {
		return err
	}
	baseline, maskProfiles, utf8Profiles, _ := expectedProfiles(m.Target.GOARCH)
	if !slices.Equal(m.CPU.ArchitectureBaseline, baseline) {
		return fmt.Errorf("architecture baseline %v, want %v", m.CPU.ArchitectureBaseline, baseline)
	}
	if !slices.Equal(m.CPU.LinkedMaskProfiles, maskProfiles) {
		return fmt.Errorf("linked mask profiles %v, want %v", m.CPU.LinkedMaskProfiles, maskProfiles)
	}
	if !slices.Equal(m.CPU.LinkedUTF8Profiles, utf8Profiles) {
		return fmt.Errorf("linked utf8 profiles %v, want %v", m.CPU.LinkedUTF8Profiles, utf8Profiles)
	}
	if m.Target.GOARCH == "amd64" && (m.Target.GOAMD64 != "v1" || m.Target.GOARM64 != "") {
		return fmt.Errorf("amd64 target levels goamd64=%q goarm64=%q, want v1 and empty", m.Target.GOAMD64, m.Target.GOARM64)
	}
	if m.Target.GOARCH == "arm64" && (m.Target.GOARM64 != "v8.0" || m.Target.GOAMD64 != "") {
		return fmt.Errorf("arm64 target levels goarm64=%q goamd64=%q, want v8.0 and empty", m.Target.GOARM64, m.Target.GOAMD64)
	}
	if err := validateArtifact("binary", m.Binary); err != nil {
		return err
	}
	if err := validateArtifact("binary version", m.Version); err != nil {
		return err
	}
	if err := validateArtifact("go env", m.GoEnv); err != nil {
		return err
	}
	if err := validateArtifact("build graph", m.BuildGraph.GoList); err != nil {
		return err
	}
	if err := validateArtifact("nm", m.Symbols.NM); err != nil {
		return err
	}

	linked := make(map[string]string, len(m.BuildGraph.Linked))
	for _, node := range m.BuildGraph.Linked {
		if node.ImportPath == "" {
			return errors.New("build graph contains an empty import path")
		}
		if _, exists := linked[node.ImportPath]; exists {
			return fmt.Errorf("build graph contains duplicate package %q", node.ImportPath)
		}
		linked[node.ImportPath] = node.Class
		if node.Class == GraphClassReference {
			return fmt.Errorf("reference-oracle package %q is linked into the production probe", node.ImportPath)
		}
	}
	for _, pkg := range []string{
		"github.com/zchee/gows/internal/cpu",
		"github.com/zchee/gows/internal/mask",
		"github.com/zchee/gows/internal/utf8x",
	} {
		if linked[pkg] != GraphClassProduction {
			return fmt.Errorf("production package %q missing or misclassified in linked graph", pkg)
		}
	}
	for _, prefix := range m.BuildGraph.ReferenceExcluded {
		for importPath := range linked {
			if strings.HasPrefix(importPath, prefix) {
				return fmt.Errorf("excluded reference-oracle prefix %q linked as %q", prefix, importPath)
			}
		}
	}
	if !slices.Equal(m.BuildGraph.ReferenceExcluded, referencePrefixes) {
		return fmt.Errorf("reference exclusions %v, want %v", m.BuildGraph.ReferenceExcluded, referencePrefixes)
	}
	if linked[probeImportPath] != GraphClassProbe {
		return fmt.Errorf("probe package %q missing or misclassified in linked graph", probeImportPath)
	}
	if err := validateCorpus(m.BuildGraph.Corpus); err != nil {
		return err
	}

	packages := make(map[string]PackageProvenance, len(m.Packages))
	for _, pkg := range m.Packages {
		if pkg.Class != GraphClassProduction {
			return fmt.Errorf("package %q class %q, want production", pkg.ImportPath, pkg.Class)
		}
		if err := validateArtifact(pkg.ImportPath+" go list", pkg.GoList); err != nil {
			return err
		}
		if err := validateArtifact(pkg.ImportPath+" object", pkg.Object); err != nil {
			return err
		}
		if len(pkg.SelectedFiles) == 0 {
			return fmt.Errorf("package %q has no selected source files", pkg.ImportPath)
		}
		for _, file := range pkg.SelectedFiles {
			if err := validateSourceFile(file); err != nil {
				return fmt.Errorf("package %q has invalid selected source %+v", pkg.ImportPath, file)
			}
		}
		if _, exists := packages[pkg.ImportPath]; exists {
			return fmt.Errorf("duplicate package provenance for %q", pkg.ImportPath)
		}
		packages[pkg.ImportPath] = pkg
	}
	if err := validateSelectedFiles(packages, m.Target.GOARCH); err != nil {
		return err
	}

	records := make(map[string]SymbolRecord, len(m.Symbols.Records))
	for _, record := range m.Symbols.Records {
		if record.NMLine == "" {
			return fmt.Errorf("symbol %q has no nm evidence", record.Name)
		}
		if err := validateArtifact(record.Name+" objdump", record.Objdump); err != nil {
			return err
		}
		if _, exists := records[record.Name]; exists {
			return fmt.Errorf("duplicate symbol provenance for %q", record.Name)
		}
		records[record.Name] = record
	}
	for _, symbol := range expectedSymbols {
		if _, ok := records[symbol]; !ok {
			return fmt.Errorf("expected assembly symbol %q is absent", symbol)
		}
	}
	if err := validateDispatch(m.Dispatch, packages, m.Target.GOARCH); err != nil {
		return err
	}
	if m.CPU.Runtime.Available {
		if err := m.validateRuntime(); err != nil {
			return err
		}
	}
	return nil
}

// ValidateFinal requires a clean source identity and execution evidence in
// addition to the static checks.
func (m Manifest) ValidateFinal() error {
	if err := m.Validate(); err != nil {
		return err
	}
	if !m.CPU.Runtime.Available {
		return errors.New("assembly runtime dispatch evidence is unavailable")
	}
	if m.Repository.Dirty || m.Repository.Detached || !m.Repository.Stable || m.Repository.Status.Size != 0 {
		return errors.New("assembly final provenance requires a clean repository identity")
	}
	return nil
}

func (m Manifest) validateRuntime() error {
	r := m.CPU.Runtime
	if r.SchemaVersion != SchemaVersion {
		return fmt.Errorf("runtime profile schema_version %d, want %d", r.SchemaVersion, SchemaVersion)
	}
	if r.GOOS != m.Target.GOOS || r.GOARCH != m.Target.GOARCH {
		return fmt.Errorf("runtime target %s/%s does not match manifest %s/%s", r.GOOS, r.GOARCH, m.Target.GOOS, m.Target.GOARCH)
	}
	if r.GOWSSIMD != "" {
		return fmt.Errorf("runtime dispatch was overridden by GOWS_SIMD=%q", r.GOWSSIMD)
	}
	if !r.MaskSelfCheck || !r.UTF8SelfCheck {
		return fmt.Errorf("runtime self-check failed: mask=%t utf8=%t", r.MaskSelfCheck, r.UTF8SelfCheck)
	}
	if err := validateArtifact("runtime execution", r.ExecutionEvidence); err != nil {
		return err
	}
	if err := validateExecutionIdentity(r.Execution, m.Target); err != nil {
		return err
	}
	switch m.Target.GOARCH {
	case "arm64":
		if !r.CPUFeatures["neon"] || len(r.SelectedMask) != 3 ||
			r.SelectedMask["32"] != "neon" || r.SelectedMask["64"] != "neon" ||
			r.SelectedMask["4096"] != "neon" || r.SelectedUTF8 != "neon" {
			return fmt.Errorf("arm64 runtime dispatch is not NEON: features=%v mask=%v utf8=%q", r.CPUFeatures, r.SelectedMask, r.SelectedUTF8)
		}
	case "amd64":
		if !r.CPUFeatures["sse2"] {
			return errors.New("amd64 runtime profile does not report baseline SSE2")
		}
		if r.CPUFeatures["avx512"] && !r.CPUFeatures["avx2"] {
			return errors.New("amd64 runtime reports AVX-512 without AVX2")
		}
		wantMask := map[string]string{
			"64":    "sse2",
			"128":   amd64Profile(r.CPUFeatures, false),
			"4096":  amd64Profile(r.CPUFeatures, true),
			"65536": amd64Profile(r.CPUFeatures, false),
		}
		if len(r.SelectedMask) != len(wantMask) {
			return fmt.Errorf("amd64 runtime selected-mask cells %v, want %v", r.SelectedMask, wantMask)
		}
		for size, profile := range wantMask {
			if r.SelectedMask[size] != profile {
				return fmt.Errorf("amd64 runtime selected mask profile %q at size %s, want %q", r.SelectedMask[size], size, profile)
			}
		}
		if r.CPUFeatures["avx2"] && r.SelectedUTF8 != "avx2" {
			return fmt.Errorf("amd64 runtime has AVX2 but selected utf8 profile %q", r.SelectedUTF8)
		}
		if !r.CPUFeatures["avx2"] && r.SelectedUTF8 != "scalar" {
			return fmt.Errorf("amd64 runtime lacks AVX2 but selected utf8 profile %q", r.SelectedUTF8)
		}
	}
	return nil
}

func validateSelectedFiles(packages map[string]PackageProvenance, goarch string) error {
	expected := map[string][]string{
		"github.com/zchee/gows/internal/cpu":   {"internal/cpu/cpu_" + goarch + ".go"},
		"github.com/zchee/gows/internal/mask":  {"internal/mask/mask_" + goarch + ".go", "internal/mask/mask_" + goarch + ".s"},
		"github.com/zchee/gows/internal/utf8x": {"internal/utf8x/valid_simd_" + goarch + ".go", "internal/utf8x/valid_" + goarch + ".s"},
	}
	if goarch == "amd64" {
		expected["github.com/zchee/gows/internal/cpu"] = append(expected["github.com/zchee/gows/internal/cpu"], "internal/cpu/cpuid_amd64.s")
	}
	otherArch := map[string]string{"amd64": "arm64", "arm64": "amd64"}[goarch]
	for importPath, names := range expected {
		pkg, ok := packages[importPath]
		if !ok {
			return fmt.Errorf("selected-file provenance missing package %q", importPath)
		}
		selected := make(map[string]bool, len(pkg.SelectedFiles))
		for _, file := range pkg.SelectedFiles {
			base := file.Path[strings.LastIndex(file.Path, "/")+1:]
			if selected[file.Path] {
				return fmt.Errorf("package %q contains duplicate selected source %q", importPath, file.Path)
			}
			selected[file.Path] = true
			if strings.Contains(base, "_"+otherArch+".") {
				return fmt.Errorf("package %q selected wrong-architecture file %q", importPath, file.Path)
			}
			if strings.HasSuffix(base, ".s") && file.Kind != "assembly" {
				return fmt.Errorf("package %q classified assembly source %q as %q", importPath, file.Path, file.Kind)
			}
		}
		for _, filename := range names {
			if !selected[filename] {
				return fmt.Errorf("package %q did not select required source %q", importPath, filename)
			}
		}
	}
	return nil
}

func validateRepositoryIdentity(repository RepositoryIdentity) error {
	if repository.Root == "" || !filepath.IsAbs(repository.Root) || filepath.Clean(repository.Root) != repository.Root {
		return fmt.Errorf("repository root %q is not a canonical absolute path", repository.Root)
	}
	if repository.Remote == "" || repository.Branch == "" {
		return fmt.Errorf("repository remote or branch is empty: remote=%q branch=%q", repository.Remote, repository.Branch)
	}
	if !validateGitObjectID(repository.SourceHEAD) || !validateGitObjectID(repository.GitTree) {
		return fmt.Errorf("invalid repository object identity: head=%q tree=%q", repository.SourceHEAD, repository.GitTree)
	}
	if repository.SourceTreeAlgorithm != SourceTreeHashAlgorithm || !validSHA256(repository.SourceTreeSHA256) || repository.SourceTreeFiles <= 0 {
		return fmt.Errorf("invalid repository source-tree identity: %+v", repository)
	}
	if err := validateArtifact("repository status", repository.Status); err != nil {
		return err
	}
	if repository.Dirty != (repository.Status.Size != 0) {
		return fmt.Errorf("repository dirty=%t does not match status size %d", repository.Dirty, repository.Status.Size)
	}
	if !repository.Stable && !repository.Dirty {
		return errors.New("clean repository identity cannot be marked unstable")
	}
	return nil
}

func validateCorpus(corpus []Corpus) error {
	wantClasses := []string{GraphClassReference, GraphClassTest}
	if len(corpus) != len(wantClasses) {
		return fmt.Errorf("corpus classes %d, want %d", len(corpus), len(wantClasses))
	}
	seenPaths := make(map[string]bool)
	for index, entry := range corpus {
		if entry.Class != wantClasses[index] || entry.Linked || entry.HashAlgorithm != CorpusHashAlgorithm || !validSHA256(entry.SHA256) || len(entry.Files) == 0 {
			return fmt.Errorf("invalid %s corpus identity: %+v", wantClasses[index], entry)
		}
		previous := ""
		for _, file := range entry.Files {
			if err := validateSourceFile(file); err != nil || file.Kind != entry.Class {
				return fmt.Errorf("invalid %s corpus source %+v: %v", entry.Class, file, err)
			}
			if previous >= file.Path || seenPaths[file.Path] {
				return fmt.Errorf("corpus source order/uniqueness violation at %q", file.Path)
			}
			previous = file.Path
			seenPaths[file.Path] = true
		}
		if got := corpusHash(entry.Class, entry.Files); got != entry.SHA256 {
			return fmt.Errorf("%s corpus hash %s, recomputed %s", entry.Class, entry.SHA256, got)
		}
	}
	return nil
}

func validateDispatch(dispatch DispatchEvidence, packages map[string]PackageProvenance, goarch string) error {
	expected, err := expectedDispatchers(goarch)
	if err != nil {
		return err
	}
	if len(dispatch.Records) != len(expected) {
		return fmt.Errorf("dispatcher records %d, want %d", len(dispatch.Records), len(expected))
	}
	byName := make(map[string]DispatchRecord, len(dispatch.Records))
	for _, record := range dispatch.Records {
		if _, exists := byName[record.Name]; exists {
			return fmt.Errorf("duplicate dispatcher record %q", record.Name)
		}
		byName[record.Name] = record
	}
	for _, want := range expected {
		record, ok := byName[want.Name]
		if !ok {
			return fmt.Errorf("missing dispatcher record %q", want.Name)
		}
		pkg, ok := packages[want.Package]
		if !ok || record.Package != want.Package || record.Source.Path != want.Source || record.ObjectSHA256 != pkg.Object.SHA256 || !validSHA256(record.ObjectSHA256) {
			return fmt.Errorf("dispatcher %q source/object/package identity mismatch", want.Name)
		}
		if err := validateSourceFile(record.Source); err != nil {
			return fmt.Errorf("dispatcher %q source: %w", want.Name, err)
		}
		sourceMatched := slices.Contains(pkg.SelectedFiles, record.Source)
		if !sourceMatched {
			return fmt.Errorf("dispatcher %q source is not selected in package object", want.Name)
		}
		if record.NMLine == "" {
			return fmt.Errorf("dispatcher %q has no nm evidence", want.Name)
		}
		if err := validateArtifact(want.Name+" dispatcher objdump", record.Objdump); err != nil {
			return err
		}
		if len(record.Calls) != len(want.Calls) {
			return fmt.Errorf("dispatcher %q call edges %d, want %d", want.Name, len(record.Calls), len(want.Calls))
		}
		for index, callee := range want.Calls {
			edge := record.Calls[index]
			if edge.Callee != callee || edge.EvidenceLine == "" || !strings.Contains(edge.EvidenceLine, "CALL "+callee) {
				return fmt.Errorf("dispatcher %q invalid call edge %+v, want %q", want.Name, edge, callee)
			}
		}
	}
	return nil
}

func validateExecutionIdentity(execution ExecutionIdentity, target Target) error {
	if execution.Method == "" || execution.Machine == "" {
		return fmt.Errorf("runtime execution identity is incomplete: %+v", execution)
	}
	if target.GOOS == "darwin" {
		if execution.Method != "darwin-sysctl" || !execution.TranslationAvailable {
			return fmt.Errorf("darwin translation identity is not available: %+v", execution)
		}
		if target.GOARCH == "arm64" && execution.Translated {
			return errors.New("arm64 runtime cannot be a translated x86 process")
		}
		if execution.Translated && (target.GOARCH != "amd64" || !execution.PhysicalARM64Available) {
			return fmt.Errorf("invalid translated execution identity: %+v", execution)
		}
	} else if execution.Translated || execution.TranslationAvailable {
		return fmt.Errorf("non-Darwin target reports Darwin translation identity: %+v", execution)
	}
	return nil
}

func validateSourceFile(file SourceFile) error {
	if err := validateCanonicalRelativePath(file.Path); err != nil {
		return err
	}
	if file.Kind == "" || file.Size < 0 || !validSHA256(file.SHA256) {
		return fmt.Errorf("invalid source identity %+v", file)
	}
	return nil
}

func amd64Profile(features map[string]bool, allowAVX512 bool) string {
	if allowAVX512 && features["avx512"] {
		return "avx512"
	}
	if features["avx2"] {
		return "avx2"
	}
	return "sse2"
}

func validateArtifact(label string, a Artifact) error {
	if _, err := cleanArtifactPath(a.Path); err != nil || a.Size < 0 || !validSHA256(a.SHA256) {
		return fmt.Errorf("%s artifact is invalid: %+v", label, a)
	}
	return nil
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	if value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
