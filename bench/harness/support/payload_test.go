package support

import (
	"bytes"
	"testing"
	"unicode/utf8"
)

func TestSeededPayloadsAreReproducibleAndConnectionDistinct(t *testing.T) {
	t.Parallel()
	for name, generate := range map[string]func(int, uint64) []byte{
		"binary": DeterministicPayloadSeed,
		"text":   DeterministicTextPayloadSeed,
	} {
		t.Run(name, func(t *testing.T) {
			first := generate(1024, 1)
			if again := generate(1024, 1); !bytes.Equal(first, again) {
				t.Fatal("same seed was not reproducible")
			}
			if other := generate(1024, 2); bytes.Equal(first, other) {
				t.Fatal("distinct connection seeds produced identical payloads")
			}
			if name == "text" && !utf8.Valid(first) {
				t.Fatal("seeded text payload is invalid UTF-8")
			}
		})
	}
}
