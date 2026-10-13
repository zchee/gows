package evidence

import (
	"testing"

	jsonv2 "github.com/go-json-experiment/json"

	"github.com/zchee/gows/bench/harness/artifact"
	"github.com/zchee/gows/bench/harness/policy"
)

func TestValidateTrackedRunPolicyBindsBytesSeriesAndCompleteMatrix(t *testing.T) {
	root := t.TempDir()
	initTestGitRepository(t, root)
	pol := aaTestPolicy()
	raw, err := jsonv2.Marshal(pol, jsonv2.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	const path = "bench/harness/policy/phase0/aa.json"
	writeTestFile(t, root, path, string(raw))
	runTestGit(t, root, "add", ".")
	runTestGit(t, root, "commit", "-m", "policy")
	revision := testGitOutput(t, root, "rev-parse", "HEAD")
	requirement := trackedPolicyRequirement{Path: path, SeriesID: pol.Series.ID, Scenarios: []string{pol.Scenarios[0].Name}}
	run := resolvedRun{
		Policy: pol, PolicyRaw: raw,
		Receipt: artifact.RunReceipt{PolicySHA256: policy.Sum(raw)},
	}
	if err := validateTrackedRunPolicy(root, revision, requirement, run); err != nil {
		t.Fatalf("exact tracked policy: %v", err)
	}

	drifted := run
	drifted.PolicyRaw = append(append([]byte(nil), raw...), '\n')
	if err := validateTrackedRunPolicy(root, revision, requirement, drifted); err == nil {
		t.Fatal("policy byte drift was accepted")
	}
	incomplete := requirement
	incomplete.Scenarios = append(incomplete.Scenarios, "required-second-cell")
	if err := validateTrackedRunPolicy(root, revision, incomplete, run); err == nil {
		t.Fatal("incomplete scenario matrix was accepted")
	}
	wrongSeries := requirement
	wrongSeries.SeriesID = "other-series"
	if err := validateTrackedRunPolicy(root, revision, wrongSeries, run); err == nil {
		t.Fatal("wrong policy series ID was accepted")
	}
}
