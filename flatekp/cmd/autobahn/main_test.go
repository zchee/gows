// Copyright 2026 The gows Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"net"
	"strings"
	"testing"

	"github.com/zchee/gows/internal/autobahnapp"
)

func TestFeatureConfig(t *testing.T) {
	cfg := featureConfig()
	if cfg.AgentName != "gows-v04-feature-client" {
		t.Fatalf("agent name = %q, want gows-v04-feature-client", cfg.AgentName)
	}
	if !cfg.Upgrader.NegotiateWindowBits || cfg.Upgrader.ClientWindowBits != 9 || !cfg.Upgrader.AllowContextTakeover {
		t.Fatalf("server config = %+v", cfg.Upgrader)
	}
	if cfg.Dialer.ServerWindowBits != 9 || !cfg.Dialer.OfferClientMaxWindowBits || !cfg.Dialer.AllowContextTakeover {
		t.Fatalf("client config = %+v", cfg.Dialer)
	}
}

// TestCLIAcceptsModeForms runs the feature profile through the shared flag set
// and checks that each spelling of -mode reaches the requested direction: the
// server fails at listen and the client fails dialing a closed port, both with
// exit code 1 rather than the usage exit code 2.
func TestCLIAcceptsModeForms(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := "ws://" + ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"-mode", "server", "-addr", "invalid-address"}, "listen invalid-address"},
		{[]string{"-mode=server", "-addr", "invalid-address"}, "listen invalid-address"},
		{[]string{"-echo", "stream", "-mode", "client", "-server", closed}, "client: get case count"},
		{[]string{"-mode=client", "-server", closed}, "client: get case count"},
	} {
		var stderr bytes.Buffer
		code := autobahnapp.Run(tc.args, featureConfig(), &stderr)
		if code != 1 || strings.Contains(stderr.String(), "usage:") || !strings.Contains(stderr.String(), tc.want) {
			t.Fatalf("Run(%q) = %d, stderr %q, want exit 1 containing %q", tc.args, code, stderr.String(), tc.want)
		}
	}
}
