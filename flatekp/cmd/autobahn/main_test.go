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

import "testing"

func TestFeatureConfig(t *testing.T) {
	server := featureConfig("server")
	if server.AgentName != "gows-v04-feature-server" || !server.Upgrader.NegotiateWindowBits || server.Upgrader.ClientWindowBits != 9 || !server.Upgrader.AllowContextTakeover {
		t.Fatalf("server config = %+v", server)
	}
	client := featureConfig("client")
	if client.AgentName != "gows-v04-feature-client" || client.Dialer.ServerWindowBits != 9 || !client.Dialer.OfferClientMaxWindowBits || !client.Dialer.AllowContextTakeover {
		t.Fatalf("client config = %+v", client)
	}
}

func TestModeFromArgs(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"-mode", "server"}, "server"},
		{[]string{"-mode=server"}, "server"},
		{[]string{"-echo", "stream", "-mode", "client"}, "client"},
	} {
		if got := modeFromArgs(tc.args); got != tc.want {
			t.Fatalf("modeFromArgs(%q)=%q, want %q", tc.args, got, tc.want)
		}
	}
}
