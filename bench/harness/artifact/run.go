package artifact

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"slices"
	"strings"

	"github.com/go-json-experiment/json"
	"github.com/zchee/gows/bench/harness/support"
)

const RunReceiptSchemaVersion = 2

// RunReceipt resolves every raw artifact in one completed benchrun session.
type RunReceipt struct {
	SchemaVersion       int               `json:"schema_version"`
	SessionID           string            `json:"session_id"`
	SourceHead          string            `json:"source_head"`
	GitRemote           string            `json:"git_remote"`
	GitBranch           string            `json:"git_branch"`
	GitStatus           string            `json:"git_status"`
	GitDirty            bool              `json:"git_dirty"`
	GitTree             string            `json:"git_tree"`
	SourceSHA256        string            `json:"source_sha256"`
	ModulePath          string            `json:"module_path"`
	ModuleFilesSHA256   string            `json:"module_files_sha256"`
	GoVersion           string            `json:"go_version"`
	GoBinarySHA256      string            `json:"go_binary_sha256"`
	GOOS                string            `json:"goos"`
	GOARCH              string            `json:"goarch"`
	GoExperiment        string            `json:"go_experiment"`
	Client              string            `json:"client"`
	EchoserverSHA256    string            `json:"echoserver_sha256"`
	LoadgenSHA256       string            `json:"loadgen_sha256"`
	AdapterSHA256       map[string]string `json:"adapter_sha256"`
	LibraryBinarySHA256 map[string]string `json:"library_binary_sha256"`
	PolicySHA256        string            `json:"policy_sha256"`
	RunKind             string            `json:"run_kind"`
	EvidenceClass       string            `json:"evidence_class"`
	ToolchainSeries     string            `json:"toolchain_series"`
	Files               map[string]Ref    `json:"files"`
}

type runMeta struct {
	SessionID           string            `json:"session_id"`
	GitCommit           string            `json:"git_commit"`
	GitRemote           string            `json:"git_remote"`
	GitBranch           string            `json:"git_branch"`
	GitStatus           string            `json:"git_status"`
	GitDirty            bool              `json:"git_dirty"`
	GitTree             string            `json:"git_tree"`
	SourceSHA256        string            `json:"source_sha256"`
	ModulePath          string            `json:"module_path"`
	ModuleFilesSHA256   string            `json:"module_files_sha256"`
	GoVersion           string            `json:"go_version"`
	GoBinarySHA256      string            `json:"go_binary_sha256"`
	GOOS                string            `json:"goos"`
	GOARCH              string            `json:"goarch"`
	GoExperiment        string            `json:"go_experiment"`
	Client              string            `json:"client"`
	EchoserverSHA256    string            `json:"echoserver_sha256"`
	LoadgenSHA256       string            `json:"loadgen_sha256"`
	AdapterSHA256       map[string]string `json:"adapter_sha256"`
	LibraryBinarySHA256 map[string]string `json:"library_binaries_sha256"`
	PolicySHA256        string            `json:"policy_sha256"`
	RunKind             string            `json:"run_kind"`
	EvidenceClass       string            `json:"evidence_class"`
	ToolchainSeries     string            `json:"toolchain_series"`
}

func SealRun(store Store, runDir string) (RunReceipt, Ref, error) {
	if _, err := os.Stat(filepath.Join(runDir, "INVALIDATED.json")); err == nil {
		return RunReceipt{}, Ref{}, fmt.Errorf("artifact: refusing invalidated run %s", runDir)
	} else if !os.IsNotExist(err) {
		return RunReceipt{}, Ref{}, fmt.Errorf("artifact: inspect invalidation marker: %w", err)
	}
	for _, required := range []string{"policy.json", "manifest.json", "env-start.json", "env-end.json", "samples.jsonl", "done.json", "echoserver", "loadgen"} {
		if info, err := os.Lstat(filepath.Join(runDir, required)); err != nil || !info.Mode().IsRegular() {
			return RunReceipt{}, Ref{}, fmt.Errorf("artifact: completed run is missing regular file %s", required)
		}
	}
	rawMeta, err := os.ReadFile(filepath.Join(runDir, "manifest.json"))
	if err != nil {
		return RunReceipt{}, Ref{}, err
	}
	var meta runMeta
	// The evaluator performs strict full-schema manifest decoding. The artifact
	// layer extracts the identity header while allowing the manifest's complete
	// provenance payload, and then binds that header into the receipt.
	if err := json.Unmarshal(rawMeta, &meta); err != nil {
		return RunReceipt{}, Ref{}, fmt.Errorf("artifact: parse run metadata: %w", err)
	}
	if err := meta.validate(); err != nil {
		return RunReceipt{}, Ref{}, fmt.Errorf("artifact: run metadata identity is incomplete")
	}

	var names []string
	err = filepath.WalkDir(runDir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == runDir || entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("artifact: symlink is forbidden in run bundle: %s", path)
		}
		relative, err := filepath.Rel(runDir, path)
		if err != nil {
			return err
		}
		if relative == "receipt.json" || strings.Contains(filepath.Base(relative), ".tmp-") {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("artifact: non-regular run artifact: %s", path)
		}
		names = append(names, filepath.ToSlash(relative))
		return nil
	})
	if err != nil {
		return RunReceipt{}, Ref{}, err
	}
	slices.Sort(names)
	files := make(map[string]Ref, len(names))
	for _, name := range names {
		ref, err := store.PutFile(filepath.Join(runDir, filepath.FromSlash(name)), mediaType(name))
		if err != nil {
			return RunReceipt{}, Ref{}, fmt.Errorf("artifact: seal %s: %w", name, err)
		}
		files[name] = ref
	}
	receipt := RunReceipt{
		SchemaVersion: RunReceiptSchemaVersion,
		SessionID:     meta.SessionID, SourceHead: meta.GitCommit,
		GitRemote: meta.GitRemote, GitBranch: meta.GitBranch, GitStatus: meta.GitStatus, GitDirty: meta.GitDirty,
		GitTree: meta.GitTree, SourceSHA256: meta.SourceSHA256,
		ModulePath: meta.ModulePath, ModuleFilesSHA256: meta.ModuleFilesSHA256,
		GoVersion: meta.GoVersion, GoBinarySHA256: meta.GoBinarySHA256,
		GOOS: meta.GOOS, GOARCH: meta.GOARCH, GoExperiment: meta.GoExperiment,
		Client: meta.Client, EchoserverSHA256: meta.EchoserverSHA256, LoadgenSHA256: meta.LoadgenSHA256,
		AdapterSHA256: meta.AdapterSHA256, LibraryBinarySHA256: meta.LibraryBinarySHA256,
		PolicySHA256: meta.PolicySHA256, RunKind: meta.RunKind,
		EvidenceClass: meta.EvidenceClass, ToolchainSeries: meta.ToolchainSeries, Files: files,
	}
	if err := receipt.Validate(); err != nil {
		return RunReceipt{}, Ref{}, err
	}
	receiptPath := filepath.Join(runDir, "receipt.json")
	if err := support.WriteJSONFile(receiptPath, receipt); err != nil {
		return RunReceipt{}, Ref{}, err
	}
	receiptRef, err := store.PutFile(receiptPath, "application/vnd.gows.bench-run-receipt+json")
	if err != nil {
		return RunReceipt{}, Ref{}, err
	}
	return receipt, receiptRef, nil
}

func (receipt RunReceipt) Validate() error {
	if receipt.SchemaVersion != RunReceiptSchemaVersion {
		return fmt.Errorf("artifact: run receipt schema_version = %d, want %d", receipt.SchemaVersion, RunReceiptSchemaVersion)
	}
	if err := receipt.identityMeta().validate(); err != nil {
		return fmt.Errorf("artifact: run receipt identity is incomplete")
	}
	for _, required := range []string{"policy.json", "manifest.json", "env-start.json", "env-end.json", "samples.jsonl", "done.json", "echoserver", "loadgen"} {
		if _, ok := receipt.Files[required]; !ok {
			return fmt.Errorf("artifact: run receipt lacks %s", required)
		}
	}
	for name, ref := range receipt.Files {
		if err := validateArtifactName(name); err != nil {
			return fmt.Errorf("artifact: invalid run artifact name %q", name)
		}
		if name == "INVALIDATED.json" {
			return fmt.Errorf("artifact: run receipt contains invalidation marker")
		}
		if err := ref.Validate(); err != nil {
			return fmt.Errorf("artifact: %s: %w", name, err)
		}
		if want := mediaType(name); ref.MediaType != want {
			return fmt.Errorf("artifact: %s media_type = %q, want %q", name, ref.MediaType, want)
		}
	}
	if receipt.Files["policy.json"].SHA256 != receipt.PolicySHA256 {
		return fmt.Errorf("artifact: policy receipt hash disagrees with policy identity")
	}
	if receipt.Files["echoserver"].SHA256 != receipt.EchoserverSHA256 || receipt.Files["loadgen"].SHA256 != receipt.LoadgenSHA256 {
		return fmt.Errorf("artifact: binary receipt hashes disagree with binary identity")
	}
	return nil
}

func LoadRunReceipt(path string) (RunReceipt, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return RunReceipt{}, fmt.Errorf("artifact: read run receipt: %w", err)
	}
	var receipt RunReceipt
	if err := decodeStrictJSON(raw, &receipt); err != nil {
		return RunReceipt{}, fmt.Errorf("artifact: parse run receipt: %w", err)
	}
	if err := receipt.Validate(); err != nil {
		return RunReceipt{}, err
	}
	return receipt, nil
}

func ResolveRun(store Store, receiptRef Ref) (RunReceipt, map[string]string, error) {
	if receiptRef.MediaType != "application/vnd.gows.bench-run-receipt+json" {
		return RunReceipt{}, nil, fmt.Errorf("artifact: run receipt media_type = %q", receiptRef.MediaType)
	}
	path, err := store.Resolve(receiptRef)
	if err != nil {
		return RunReceipt{}, nil, err
	}
	receipt, err := LoadRunReceipt(path)
	if err != nil {
		return RunReceipt{}, nil, err
	}
	resolved := make(map[string]string, len(receipt.Files))
	for name, ref := range receipt.Files {
		path, err := store.Resolve(ref)
		if err != nil {
			return RunReceipt{}, nil, fmt.Errorf("artifact: resolve %s: %w", name, err)
		}
		resolved[name] = path
	}
	rawMeta, err := os.ReadFile(resolved["manifest.json"])
	if err != nil {
		return RunReceipt{}, nil, fmt.Errorf("artifact: read resolved manifest: %w", err)
	}
	var meta runMeta
	if err := json.Unmarshal(rawMeta, &meta); err != nil {
		return RunReceipt{}, nil, fmt.Errorf("artifact: parse resolved manifest identity: %w", err)
	}
	if !reflect.DeepEqual(meta, receipt.identityMeta()) {
		return RunReceipt{}, nil, fmt.Errorf("artifact: run receipt identity disagrees with resolved manifest")
	}
	return receipt, resolved, nil
}

func (meta runMeta) validate() error {
	if meta.SessionID == "" || meta.GitCommit == "" || meta.GitRemote == "" || meta.GitBranch == "" ||
		meta.GitTree == "" || !validSHA256(meta.SourceSHA256) || meta.ModulePath == "" || !validSHA256(meta.ModuleFilesSHA256) ||
		meta.GoVersion == "" || !validSHA256(meta.GoBinarySHA256) || meta.GOOS == "" || meta.GOARCH == "" || meta.Client == "" ||
		!validSHA256(meta.EchoserverSHA256) || !validSHA256(meta.LoadgenSHA256) || !validSHA256(meta.PolicySHA256) ||
		meta.RunKind == "" || meta.EvidenceClass == "" || meta.ToolchainSeries == "" ||
		len(meta.AdapterSHA256) == 0 || len(meta.LibraryBinarySHA256) == 0 {
		return fmt.Errorf("incomplete run identity")
	}
	for name, digest := range meta.AdapterSHA256 {
		if name == "" || !validSHA256(digest) {
			return fmt.Errorf("invalid adapter identity")
		}
	}
	for name, digest := range meta.LibraryBinarySHA256 {
		if name == "" || !validSHA256(digest) {
			return fmt.Errorf("invalid library binary identity")
		}
	}
	return nil
}

func (receipt RunReceipt) identityMeta() runMeta {
	return runMeta{
		SessionID: receipt.SessionID, GitCommit: receipt.SourceHead,
		GitRemote: receipt.GitRemote, GitBranch: receipt.GitBranch,
		GitStatus: receipt.GitStatus, GitDirty: receipt.GitDirty,
		GitTree: receipt.GitTree, SourceSHA256: receipt.SourceSHA256,
		ModulePath: receipt.ModulePath, ModuleFilesSHA256: receipt.ModuleFilesSHA256,
		GoVersion: receipt.GoVersion, GoBinarySHA256: receipt.GoBinarySHA256,
		GOOS: receipt.GOOS, GOARCH: receipt.GOARCH, GoExperiment: receipt.GoExperiment,
		Client: receipt.Client, EchoserverSHA256: receipt.EchoserverSHA256,
		LoadgenSHA256: receipt.LoadgenSHA256, AdapterSHA256: receipt.AdapterSHA256,
		LibraryBinarySHA256: receipt.LibraryBinarySHA256, PolicySHA256: receipt.PolicySHA256,
		RunKind: receipt.RunKind, EvidenceClass: receipt.EvidenceClass,
		ToolchainSeries: receipt.ToolchainSeries,
	}
}

func validateArtifactName(name string) error {
	if name == "" || name == "." || strings.Contains(name, `\`) || filepath.ToSlash(name) != name || path.Clean(name) != name || !filepath.IsLocal(filepath.FromSlash(name)) {
		return fmt.Errorf("non-canonical artifact path")
	}
	return nil
}

func mediaType(name string) string {
	switch filepath.Ext(name) {
	case ".json":
		return "application/json"
	case ".jsonl":
		return "application/x-ndjson"
	case ".log", ".txt":
		return "text/plain"
	default:
		return "application/octet-stream"
	}
}
