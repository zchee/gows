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

//go:build race

package gows

// RaceEnabled reports whether this test binary was built with -race. The race
// detector's sync.Pool instrumentation can add a phantom allocation to
// AllocsPerRun, so the zero-alloc assertions are enforced only on non-race
// builds; the observed value is always logged. Declared in a _test.go file of
// package gows so the external gows_test package can consult it as
// gows.RaceEnabled; its counterpart in norace_test.go defines it false.
const RaceEnabled = true
