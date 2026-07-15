package support

import (
	"runtime"
	"strings"
	"testing"
)

func TestFormatBootIdentity(t *testing.T) {
	t.Parallel()

	got, err := formatBootIdentity(darwinBootIdentitySource, " 821CD8D9-34E2-4B79-9CAD-90C6E736EA19\n")
	if err != nil {
		t.Fatalf("formatBootIdentity: %v", err)
	}
	const want = "darwin:kern.bootsessionuuid=821CD8D9-34E2-4B79-9CAD-90C6E736EA19"
	if got != want {
		t.Fatalf("formatBootIdentity = %q, want %q", got, want)
	}

	for _, test := range []struct {
		name, source, value string
	}{
		{name: "empty source", value: "uuid"},
		{name: "empty value", source: darwinBootIdentitySource},
		{name: "source delimiter", source: "darwin=other", value: "uuid"},
		{name: "multiple tokens", source: darwinBootIdentitySource, value: "uuid other"},
		{name: "value delimiter", source: darwinBootIdentitySource, value: "uuid=other"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := formatBootIdentity(test.source, test.value); err == nil {
				t.Fatal("formatBootIdentity unexpectedly accepted invalid identity")
			}
		})
	}
}

func TestCaptureBootIdentity(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skipf("boot identity is unsupported on %s", runtime.GOOS)
	}

	first, err := CaptureBootIdentity()
	if err != nil {
		t.Fatalf("CaptureBootIdentity first call: %v", err)
	}
	second, err := CaptureBootIdentity()
	if err != nil {
		t.Fatalf("CaptureBootIdentity second call: %v", err)
	}
	if first != second {
		t.Fatalf("boot identity changed across consecutive calls: %q != %q", first, second)
	}
	if !strings.Contains(first, "=") {
		t.Fatalf("boot identity %q lacks source prefix", first)
	}
	if err := ValidateBootIdentity(runtime.GOOS, first); err != nil {
		t.Fatalf("ValidateBootIdentity(%q): %v", first, err)
	}
}

func TestValidateBootIdentityRejectsLegacyAndForeignSources(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name, goos, identity string
	}{
		{name: "legacy Darwin boottime", goos: "darwin", identity: "{ sec = 1, usec = 2 }"},
		{name: "foreign Linux source", goos: "darwin", identity: linuxBootIdentitySource + "=uuid"},
		{name: "foreign Darwin source", goos: "linux", identity: darwinBootIdentitySource + "=uuid"},
		{name: "noncanonical whitespace", goos: "darwin", identity: darwinBootIdentitySource + "=uuid\n"},
		{name: "unsupported OS", goos: "freebsd", identity: "freebsd:boot=uuid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := ValidateBootIdentity(test.goos, test.identity); err == nil {
				t.Fatal("ValidateBootIdentity unexpectedly accepted invalid identity")
			}
		})
	}
}
