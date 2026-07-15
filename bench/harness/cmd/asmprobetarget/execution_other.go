//go:build !darwin

package main

import "runtime"

func platformExecutionIdentity() (executionIdentity, error) {
	return executionIdentity{
		Method:  "runtime",
		Machine: runtime.GOARCH,
	}, nil
}
