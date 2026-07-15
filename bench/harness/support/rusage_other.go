//go:build !darwin && !linux

package support

func processRusage(any) Usage { return Usage{} }

func selfRusage() Usage { return Usage{} }
