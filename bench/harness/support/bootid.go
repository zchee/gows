package support

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

const (
	darwinBootIdentitySource = "darwin:kern.bootsessionuuid"
	linuxBootIdentitySource  = "linux:/proc/sys/kernel/random/boot_id"
)

// CaptureBootIdentity returns the kernel's stable identifier for the current
// boot session. The source prefix prevents evidence collected from different
// operating-system identity mechanisms from being compared as if equivalent.
func CaptureBootIdentity() (string, error) {
	source, err := bootIdentitySource(runtime.GOOS)
	if err != nil {
		return "", err
	}
	var raw string
	switch runtime.GOOS {
	case "darwin":
		output, err := exec.Command("/usr/sbin/sysctl", "-n", "kern.bootsessionuuid").Output()
		if err != nil {
			return "", fmt.Errorf("capture Darwin boot session UUID: %w", err)
		}
		raw = string(output)
	case "linux":
		output, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
		if err != nil {
			return "", fmt.Errorf("capture Linux boot ID: %w", err)
		}
		raw = string(output)
	}
	return formatBootIdentity(source, raw)
}

// ValidateBootIdentity rejects boot identities that are empty, malformed, or
// were captured with a mechanism other than the one defined for goos.
func ValidateBootIdentity(goos, identity string) error {
	source, err := bootIdentitySource(goos)
	if err != nil {
		return err
	}
	wantPrefix := source + "="
	if !strings.HasPrefix(identity, wantPrefix) {
		return fmt.Errorf("boot identity %q lacks required source prefix %q", identity, wantPrefix)
	}
	canonical, err := formatBootIdentity(source, strings.TrimPrefix(identity, wantPrefix))
	if err != nil {
		return err
	}
	if canonical != identity {
		return fmt.Errorf("boot identity %q is not canonical", identity)
	}
	return nil
}

func bootIdentitySource(goos string) (string, error) {
	switch goos {
	case "darwin":
		return darwinBootIdentitySource, nil
	case "linux":
		return linuxBootIdentitySource, nil
	default:
		return "", fmt.Errorf("capture boot identity: unsupported OS %q", goos)
	}
}

func formatBootIdentity(source, raw string) (string, error) {
	source = strings.TrimSpace(source)
	value := strings.TrimSpace(raw)
	if source == "" || value == "" {
		return "", fmt.Errorf("boot identity source or value is empty")
	}
	if strings.ContainsAny(source, "=\r\n\x00") {
		return "", fmt.Errorf("boot identity source %q contains a delimiter or control byte", source)
	}
	if len(strings.Fields(value)) != 1 || strings.ContainsAny(value, "=\r\n\x00") {
		return "", fmt.Errorf("boot identity value %q is not one canonical token", value)
	}
	return source + "=" + value, nil
}
