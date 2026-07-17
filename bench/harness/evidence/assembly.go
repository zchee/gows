package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/zchee/gows/bench/harness/artifact"
	"github.com/zchee/gows/bench/harness/assembly"
	"github.com/zchee/gows/bench/harness/support"
)

func resolveAssemblies(store artifact.Store, records []AssemblyEvidence, repository RepositoryIdentity, root string) ([]AssemblyVerdict, error) {
	records = slices.Clone(records)
	slices.SortFunc(records, func(a, b AssemblyEvidence) int { return strings.Compare(a.GOARCH, b.GOARCH) })
	verdicts := make([]AssemblyVerdict, 0, len(records))
	for _, record := range records {
		wantKind := AssemblyKindPrefix + record.GOOS + "-" + record.GOARCH
		_, paths, err := artifact.ResolveDirectory(store, record.Bundle, wantKind)
		if err != nil {
			return nil, fmt.Errorf("evidence: resolve %s assembly: %w", record.GOARCH, err)
		}
		temporaryRoot, err := os.MkdirTemp("", "gows-phase0-assembly-")
		if err != nil {
			return nil, err
		}
		destination := filepath.Join(temporaryRoot, "bundle")
		materializeErr := artifact.MaterializeDirectory(paths, destination)
		if materializeErr != nil {
			cleanupErr := os.RemoveAll(temporaryRoot)
			return nil, fmt.Errorf("evidence: materialize %s assembly: %w", record.GOARCH, errors.Join(materializeErr, cleanupErr))
		}
		bundle, readErr := assembly.ReadBundle(destination, true)
		removeErr := os.RemoveAll(temporaryRoot)
		if readErr != nil {
			return nil, fmt.Errorf("evidence: validate %s assembly: %w", record.GOARCH, errors.Join(readErr, removeErr))
		}
		if removeErr != nil {
			return nil, fmt.Errorf("evidence: clean assembly materialization: %w", removeErr)
		}
		manifest := bundle.Manifest
		if manifest.Target.GOOS != record.GOOS || manifest.Target.GOARCH != record.GOARCH {
			return nil, fmt.Errorf("evidence: assembly target mismatch %s/%s", manifest.Target.GOOS, manifest.Target.GOARCH)
		}
		if manifest.Toolchain.GoBinarySHA256 != repository.GoBinarySHA256 || manifest.Toolchain.GoBinarySize != repository.GoBinarySizeBytes ||
			!strings.Contains(repository.GoVersion, manifest.Toolchain.GoVersion) || strings.Contains(manifest.Toolchain.GoVersion, "-X:") {
			return nil, fmt.Errorf("evidence: %s assembly toolchain differs from benchmark toolchain", record.GOARCH)
		}
		if err := validateAssemblySources(root, repository.SourceHead, manifest); err != nil {
			return nil, err
		}
		hashes := assemblyHashes(manifest)
		verdicts = append(verdicts, AssemblyVerdict{
			GOOS: record.GOOS, GOARCH: record.GOARCH, BundleSHA256: record.Bundle.SHA256,
			BinarySHA256: manifest.Binary.SHA256, RuntimeProfile: runtimeProfile(manifest),
			SourceObjectSymbols: hashes,
		})
	}
	return verdicts, nil
}

func validateAssemblySources(root, revision string, manifest assembly.Manifest) error {
	seen := make(map[string]bool)
	for _, pkg := range manifest.Packages {
		for _, source := range pkg.SelectedFiles {
			if !filepath.IsLocal(filepath.FromSlash(source.Path)) || !support.ValidSHA256(source.SHA256) || source.Size < 0 {
				return fmt.Errorf("evidence: %s assembly selected source is invalid: %+v", manifest.Target.GOARCH, source)
			}
			if seen[source.Path] {
				return fmt.Errorf("evidence: %s assembly repeats selected source %q", manifest.Target.GOARCH, source.Path)
			}
			seen[source.Path] = true
			raw, err := gitOutputBytes(root, "show", revision+":"+source.Path)
			if err != nil {
				return fmt.Errorf("evidence: resolve assembly source %s: %w", source.Path, err)
			}
			sum := sha256.Sum256(raw)
			if int64(len(raw)) != source.Size || hex.EncodeToString(sum[:]) != source.SHA256 {
				return fmt.Errorf("evidence: assembly source %s does not match source HEAD", source.Path)
			}
		}
	}
	return nil
}

func assemblyHashes(manifest assembly.Manifest) []string {
	var values []string
	for _, pkg := range manifest.Packages {
		values = append(values, "object:"+pkg.ImportPath+":"+pkg.Object.SHA256)
		for _, source := range pkg.SelectedFiles {
			values = append(values, "source:"+source.Path+":"+source.SHA256)
		}
	}
	for _, symbol := range manifest.Symbols.Records {
		values = append(values, "symbol:"+symbol.Name+":"+symbol.Objdump.SHA256)
	}
	slices.Sort(values)
	return values
}

func runtimeProfile(manifest assembly.Manifest) string {
	profile := manifest.CPU.Runtime
	keys := make([]string, 0, len(profile.SelectedMask))
	for size := range profile.SelectedMask {
		keys = append(keys, size)
	}
	slices.Sort(keys)
	var result strings.Builder
	result.WriteString("mask[")
	for i, size := range keys {
		if i > 0 {
			result.WriteByte(',')
		}
		fmt.Fprintf(&result, "%s=%s", size, profile.SelectedMask[size])
	}
	result.WriteString("];utf8=")
	result.WriteString(profile.SelectedUTF8)
	return result.String()
}
