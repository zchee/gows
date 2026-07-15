// Command asmprobetarget is a linked production-kernel probe. It is built by
// harness/assembly for one supported architecture at a time.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strconv"

	"github.com/zchee/gows/internal/cpu"
	"github.com/zchee/gows/internal/mask"
	"github.com/zchee/gows/internal/utf8x"
)

type runtimeProfile struct {
	SchemaVersion int               `json:"schema_version"`
	GOOS          string            `json:"goos"`
	GOARCH        string            `json:"goarch"`
	GOWSSIMD      string            `json:"gows_simd"`
	CPUFeatures   map[string]bool   `json:"cpu_features"`
	SelectedMask  map[string]string `json:"selected_mask"`
	SelectedUTF8  string            `json:"selected_utf8"`
	MaskSelfCheck bool              `json:"mask_self_check"`
	UTF8SelfCheck bool              `json:"utf8_self_check"`
	Execution     executionIdentity `json:"execution"`
}

type executionIdentity struct {
	Method                 string `json:"method"`
	Machine                string `json:"machine"`
	TranslationAvailable   bool   `json:"translation_available"`
	Translated             bool   `json:"translated"`
	PhysicalARM64Available bool   `json:"physical_arm64_available"`
}

func main() {
	profile, err := probe()
	if err != nil {
		fmt.Fprintln(os.Stderr, "asmprobetarget:", err)
		os.Exit(1)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(profile); err != nil {
		fmt.Fprintln(os.Stderr, "asmprobetarget: encode:", err)
		os.Exit(1)
	}
}

func probe() (runtimeProfile, error) {
	execution, err := platformExecutionIdentity()
	if err != nil {
		return runtimeProfile{}, err
	}
	features := map[string]bool{}
	selectedMask := map[string]string{}
	switch runtime.GOARCH {
	case "amd64":
		features["sse2"] = true
		features["avx2"] = cpu.X86.HasAVX2
		features["avx512"] = cpu.X86.HasAVX512
		for _, size := range []int{64, 128, 4096, 65536} {
			selectedMask[strconv.Itoa(size)] = amd64MaskProfile(size)
		}
	case "arm64":
		features["neon"] = cpu.HasNEON
		for _, size := range []int{32, 64, 4096} {
			if cpu.HasNEON {
				selectedMask[strconv.Itoa(size)] = "neon"
			} else {
				selectedMask[strconv.Itoa(size)] = "scalar"
			}
		}
	default:
		return runtimeProfile{}, fmt.Errorf("unsupported assembly target %q", runtime.GOARCH)
	}

	maskOK := true
	for _, size := range []int{32, 64, 128, 4096, 65536} {
		if !checkMask(size) {
			maskOK = false
		}
	}
	utf8OK := checkUTF8()
	selectedUTF8 := "scalar"
	if runtime.GOARCH == "amd64" && cpu.X86.HasAVX2 {
		selectedUTF8 = "avx2"
	}
	if runtime.GOARCH == "arm64" && cpu.HasNEON {
		selectedUTF8 = "neon"
	}
	return runtimeProfile{
		SchemaVersion: 2,
		GOOS:          runtime.GOOS,
		GOARCH:        runtime.GOARCH,
		GOWSSIMD:      os.Getenv("GOWS_SIMD"),
		CPUFeatures:   features,
		SelectedMask:  selectedMask,
		SelectedUTF8:  selectedUTF8,
		MaskSelfCheck: maskOK,
		UTF8SelfCheck: utf8OK,
		Execution:     execution,
	}, nil
}

func amd64MaskProfile(size int) string {
	switch {
	case cpu.X86.HasAVX512 && size >= 4096 && size < 65536:
		return "avx512"
	case cpu.X86.HasAVX2 && size >= 128:
		return "avx2"
	default:
		return "sse2"
	}
}

func checkMask(size int) bool {
	const key = uint32(0x44332211)
	original := make([]byte, size)
	for i := range original {
		original[i] = byte(i*31 + 7)
	}
	got := bytes.Clone(original)
	exerciseMask(got, key)
	for i := range got {
		want := original[i] ^ byte(key>>(8*(i%4)))
		if got[i] != want {
			return false
		}
	}
	return true
}

//go:noinline
func exerciseMask(payload []byte, key uint32) uint32 {
	return mask.Mask(payload, key)
}

func checkUTF8() bool {
	valid := bytes.Repeat([]byte("gows-日本語-"), 256)
	invalid := append(bytes.Clone(valid), 0xff)
	return exerciseUTF8(valid) && !exerciseUTF8(invalid)
}

//go:noinline
func exerciseUTF8(payload []byte) bool {
	return utf8x.Valid(payload)
}
