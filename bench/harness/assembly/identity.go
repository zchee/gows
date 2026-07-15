package assembly

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

type repositorySnapshot struct {
	Identity RepositoryIdentity
	Status   []byte
	Corpus   []Corpus
	Modules  ModuleIdentity
}

const phase0ReceiptPrefix = "bench/evidence/phase0/current/"

func collectRepositorySnapshot(ctx context.Context, repoRoot string) (repositorySnapshot, error) {
	git := func(args ...string) ([]byte, error) {
		fullArgs := append([]string{"-C", repoRoot}, args...)
		return run(ctx, os.Environ(), "git", fullArgs...)
	}
	remoteBytes, err := git("remote", "get-url", "origin")
	if err != nil {
		return repositorySnapshot{}, fmt.Errorf("repository remote: %w", err)
	}
	branchBytes, err := git("branch", "--show-current")
	if err != nil {
		return repositorySnapshot{}, fmt.Errorf("repository branch: %w", err)
	}
	headBytes, err := git("rev-parse", "HEAD")
	if err != nil {
		return repositorySnapshot{}, fmt.Errorf("repository HEAD: %w", err)
	}
	treeBytes, err := git("rev-parse", "HEAD^{tree}")
	if err != nil {
		return repositorySnapshot{}, fmt.Errorf("repository tree: %w", err)
	}
	statusBytes, err := git("status", "--porcelain=v2", "--untracked-files=all")
	if err != nil {
		return repositorySnapshot{}, fmt.Errorf("repository status: %w", err)
	}
	pathsBytes, err := git("ls-files", "-z", "--cached", "--others", "--exclude-standard")
	if err != nil {
		return repositorySnapshot{}, fmt.Errorf("repository source list: %w", err)
	}
	paths, err := parseNULPaths(pathsBytes)
	if err != nil {
		return repositorySnapshot{}, err
	}
	sourcePaths := sourceIdentityPaths(paths)
	sourceTreeSHA256, err := hashRepositoryTree(repoRoot, sourcePaths)
	if err != nil {
		return repositorySnapshot{}, err
	}
	corpus, err := collectCorpus(repoRoot, paths)
	if err != nil {
		return repositorySnapshot{}, err
	}
	rootModuleSHA256, err := hashFileSet(repoRoot, []string{"go.mod", "go.sum"}, "root-module-files-v1")
	if err != nil {
		return repositorySnapshot{}, err
	}
	benchModuleSHA256, err := hashFileSet(repoRoot, []string{"bench/go.mod", "bench/go.sum"}, "bench-module-files-v1")
	if err != nil {
		return repositorySnapshot{}, err
	}
	branch := strings.TrimSpace(string(branchBytes))
	detached := branch == ""
	if detached {
		branch = "HEAD"
	}
	return repositorySnapshot{
		Identity: RepositoryIdentity{
			Root:                repoRoot,
			Remote:              strings.TrimSpace(string(remoteBytes)),
			Branch:              branch,
			Detached:            detached,
			SourceHEAD:          strings.TrimSpace(string(headBytes)),
			GitTree:             strings.TrimSpace(string(treeBytes)),
			Dirty:               len(bytes.TrimSpace(statusBytes)) != 0,
			Stable:              true,
			SourceTreeSHA256:    sourceTreeSHA256,
			SourceTreeFiles:     len(sourcePaths),
			SourceTreeAlgorithm: SourceTreeHashAlgorithm,
		},
		Status: statusBytes,
		Corpus: corpus,
		Modules: ModuleIdentity{
			RootFilesSHA256:  rootModuleSHA256,
			BenchFilesSHA256: benchModuleSHA256,
		},
	}, nil
}

func parseNULPaths(data []byte) ([]string, error) {
	parts := bytes.Split(data, []byte{0})
	paths := make([]string, 0, len(parts))
	for _, part := range parts {
		if len(part) == 0 {
			continue
		}
		name := filepath.ToSlash(string(part))
		if err := validateCanonicalRelativePath(name); err != nil {
			return nil, fmt.Errorf("repository source path: %w", err)
		}
		paths = append(paths, name)
	}
	sort.Strings(paths)
	for index := 1; index < len(paths); index++ {
		if paths[index] == paths[index-1] {
			return nil, fmt.Errorf("repository source list contains duplicate path %q", paths[index])
		}
	}
	return paths, nil
}

func hashRepositoryTree(repoRoot string, paths []string) (string, error) {
	hash := sha256.New()
	hash.Write([]byte(SourceTreeHashAlgorithm))
	hash.Write([]byte{0})
	for _, name := range paths {
		data, mode, err := readRepositoryFile(repoRoot, name)
		if err != nil {
			return "", err
		}
		writeHashField(hash, name)
		writeHashField(hash, mode)
		writeHashBytes(hash, data)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func sourceIdentityPaths(paths []string) []string {
	filtered := make([]string, 0, len(paths))
	for _, name := range paths {
		if strings.HasPrefix(name, phase0ReceiptPrefix) {
			continue
		}
		filtered = append(filtered, name)
	}
	return filtered
}

func hashFileSet(repoRoot string, paths []string, domain string) (string, error) {
	hash := sha256.New()
	hash.Write([]byte(domain))
	hash.Write([]byte{0})
	for _, name := range paths {
		if err := validateCanonicalRelativePath(name); err != nil {
			return "", err
		}
		data, mode, err := readRepositoryFile(repoRoot, name)
		if err != nil {
			return "", err
		}
		writeHashField(hash, name)
		writeHashField(hash, mode)
		writeHashBytes(hash, data)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func collectCorpus(repoRoot string, paths []string) ([]Corpus, error) {
	byClass := map[string][]SourceFile{
		GraphClassReference: nil,
		GraphClassTest:      nil,
	}
	for _, name := range paths {
		class := ""
		switch {
		case strings.HasPrefix(name, "bench/internal/thirdparty/"):
			class = GraphClassReference
		case strings.HasSuffix(name, "_test.go") &&
			(strings.HasPrefix(name, "internal/cpu/") ||
				strings.HasPrefix(name, "internal/mask/") ||
				strings.HasPrefix(name, "internal/utf8x/") ||
				name == "bench/kernels_test.go"):
			class = GraphClassTest
		}
		if class == "" {
			continue
		}
		data, mode, err := readRepositoryFile(repoRoot, name)
		if err != nil {
			return nil, err
		}
		if mode != "file" {
			return nil, fmt.Errorf("corpus path %q is %s, want regular file", name, mode)
		}
		sum := sha256.Sum256(data)
		byClass[class] = append(byClass[class], SourceFile{
			Path:   name,
			Kind:   class,
			SHA256: hex.EncodeToString(sum[:]),
			Size:   int64(len(data)),
		})
	}
	classes := []string{GraphClassReference, GraphClassTest}
	corpus := make([]Corpus, 0, len(classes))
	for _, class := range classes {
		files := byClass[class]
		sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
		if len(files) == 0 {
			return nil, fmt.Errorf("repository has no %s corpus", class)
		}
		corpus = append(corpus, Corpus{
			Class:         class,
			Linked:        false,
			SHA256:        corpusHash(class, files),
			HashAlgorithm: CorpusHashAlgorithm,
			Files:         files,
		})
	}
	return corpus, nil
}

func corpusHash(class string, files []SourceFile) string {
	hash := sha256.New()
	hash.Write([]byte(CorpusHashAlgorithm))
	hash.Write([]byte{0})
	writeHashField(hash, class)
	for _, file := range files {
		writeHashField(hash, file.Path)
		writeHashField(hash, file.Kind)
		writeHashField(hash, file.SHA256)
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(file.Size))
		hash.Write(size[:])
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func readRepositoryFile(repoRoot, name string) ([]byte, string, error) {
	if err := validateCanonicalRelativePath(name); err != nil {
		return nil, "", err
	}
	filename := filepath.Join(repoRoot, filepath.FromSlash(name))
	info, err := os.Lstat(filename)
	if err != nil {
		return nil, "", fmt.Errorf("read repository file %q: %w", name, err)
	}
	switch {
	case info.Mode().IsRegular():
		data, err := os.ReadFile(filename)
		return data, "file", err
	case info.Mode()&fs.ModeSymlink != 0:
		target, err := os.Readlink(filename)
		return []byte(target), "symlink", err
	default:
		return nil, "", fmt.Errorf("repository path %q has unsupported mode %s", name, info.Mode())
	}
}

func writeHashField(hash interface{ Write([]byte) (int, error) }, value string) {
	writeHashBytes(hash, []byte(value))
}

func writeHashBytes(hash interface{ Write([]byte) (int, error) }, value []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	hash.Write(size[:])
	hash.Write(value)
}

func validateCanonicalRelativePath(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsRune(name, '\\') ||
		path.IsAbs(name) || strings.HasPrefix(name, "../") || path.Clean(name) != name {
		return fmt.Errorf("non-canonical relative path %q", name)
	}
	return nil
}

func equalRepositorySnapshot(first, second repositorySnapshot) bool {
	return first.Identity.Root == second.Identity.Root &&
		first.Identity.Remote == second.Identity.Remote &&
		first.Identity.Branch == second.Identity.Branch &&
		first.Identity.Detached == second.Identity.Detached &&
		first.Identity.SourceHEAD == second.Identity.SourceHEAD &&
		first.Identity.GitTree == second.Identity.GitTree &&
		first.Identity.Dirty == second.Identity.Dirty &&
		first.Identity.SourceTreeSHA256 == second.Identity.SourceTreeSHA256 &&
		first.Identity.SourceTreeFiles == second.Identity.SourceTreeFiles &&
		bytes.Equal(first.Status, second.Status) &&
		first.Modules.RootFilesSHA256 == second.Modules.RootFilesSHA256 &&
		first.Modules.BenchFilesSHA256 == second.Modules.BenchFilesSHA256 &&
		corporaEqual(first.Corpus, second.Corpus)
}

func corporaEqual(first, second []Corpus) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index].Class != second[index].Class || first[index].SHA256 != second[index].SHA256 {
			return false
		}
	}
	return true
}

func validateGitObjectID(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	if value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func canonicalRepositoryRoot(root string) (string, error) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", err
	}
	resolved = filepath.Clean(resolved)
	if !filepath.IsAbs(resolved) {
		return "", errors.New("resolved repository root is not absolute")
	}
	return resolved, nil
}
