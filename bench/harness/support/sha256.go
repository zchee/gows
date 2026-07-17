package support

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// FileSHA256 streams path through SHA-256 and returns the canonical lowercase
// hex digest together with the exact number of bytes hashed. Streaming keeps
// large binaries such as the Go toolchain out of the heap, and reporting the
// hashed byte count binds any recorded size to the same bytes as the digest.
func FileSHA256(path string) (sum string, size int64, resultErr error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, file.Close())
	}()
	hash := sha256.New()
	size, err = io.Copy(hash, file)
	if err != nil {
		return "", 0, fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

// ValidSHA256 reports whether value is exactly a lowercase hex-encoded SHA-256
// digest (64 lowercase hexadecimal characters). Harness identities and
// artifact digests are recorded in this canonical form, and validators reject
// uppercase or oddly sized spellings rather than normalizing them.
func ValidSHA256(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// ValidGitObjectID reports whether value is a lowercase hex git object name:
// a 40-character SHA-1 or 64-character SHA-256 object ID, matching the two
// object formats git can produce. Consumers bind accepted values against the
// actual repository afterward, so admitting both widths never weakens an
// identity check — a fabricated name still fails its downstream resolution.
func ValidGitObjectID(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	if value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
