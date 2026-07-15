//go:build darwin

package main

import (
	"fmt"
	"strings"
	"syscall"
)

func platformExecutionIdentity() (executionIdentity, error) {
	translatedValue, err := syscall.SysctlUint32("sysctl.proc_translated")
	if err != nil {
		return executionIdentity{}, fmt.Errorf("read sysctl.proc_translated: %w", err)
	}
	physicalARM64 := false
	if arm64Value, sysctlErr := syscall.SysctlUint32("hw.optional.arm64"); sysctlErr == nil {
		physicalARM64 = arm64Value == 1
	}
	machine, err := syscall.Sysctl("hw.machine")
	if err != nil {
		return executionIdentity{}, fmt.Errorf("read hw.machine: %w", err)
	}
	return executionIdentity{
		Method:                 "darwin-sysctl",
		Machine:                strings.TrimSpace(machine),
		TranslationAvailable:   true,
		Translated:             translatedValue == 1,
		PhysicalARM64Available: physicalARM64,
	}, nil
}
