package support

// The types in this file are the on-disk schema of a benchrun run directory:
// benchrun writes manifest.json, env-start.json, env-end.json, done.json and
// the per-block guard logs with them, and the evidence package decodes the
// same files strictly to validate a sealed run. Keeping one definition means a
// field added on the writing side cannot silently go unread on the validating
// side.

// RunManifest is the provenance record written before execution starts.
// OverrideBinariesSHA256 is present only when a policy's library_overrides
// force a dedicated echoserver build (a build_env override); it is omitted
// otherwise, so manifest.json stays byte-identical for override-free policies.
type RunManifest struct {
	SchemaVersion          int                         `json:"schema_version"`
	SessionID              string                      `json:"session_id"`
	GitCommit              string                      `json:"git_commit"`
	GitDirty               bool                        `json:"git_dirty"`
	GitRemote              string                      `json:"git_remote"`
	GitBranch              string                      `json:"git_branch"`
	GitStatus              string                      `json:"git_status"`
	GitTree                string                      `json:"git_tree"`
	SourceSHA256           string                      `json:"source_sha256"`
	ModulePath             string                      `json:"module_path"`
	ModuleFilesSHA256      string                      `json:"module_files_sha256"`
	GoVersion              string                      `json:"go_version"`
	GoBinaryPath           string                      `json:"go_binary_path"`
	GoBinarySHA256         string                      `json:"go_binary_sha256"`
	GoBinarySizeBytes      int64                       `json:"go_binary_size_bytes"`
	HarnessRuntimeVersion  string                      `json:"harness_runtime_version"`
	GOOS                   string                      `json:"goos"`
	GOARCH                 string                      `json:"goarch"`
	GoEnv                  ProvenanceArtifact          `json:"go_env"`
	ModuleGraph            ProvenanceArtifact          `json:"module_graph"`
	BinaryProvenance       map[string]BinaryProvenance `json:"binary_provenance"`
	OSVersion              ProvenanceArtifact          `json:"os_version"`
	SystemProfile          ProvenanceArtifact          `json:"system_profile"`
	Limits                 ProvenanceArtifact          `json:"limits"`
	Hostname               string                      `json:"hostname"`
	Kernel                 string                      `json:"kernel"`
	BootIdentityStart      string                      `json:"boot_identity_start"`
	BootIdentityEnd        string                      `json:"boot_identity_end"`
	Client                 string                      `json:"client"`
	EchoserverSHA256       string                      `json:"echoserver_sha256"`
	LoadgenSHA256          string                      `json:"loadgen_sha256"`
	OverrideBinariesSHA256 map[string]string           `json:"override_binaries_sha256,omitzero"`
	PolicySHA256           string                      `json:"policy_sha256"`
	AdapterSHA256          map[string]string           `json:"adapter_sha256"`
	LibraryBinariesSHA256  map[string]string           `json:"library_binaries_sha256"`
	RunKind                string                      `json:"run_kind"`
	EvidenceClass          string                      `json:"evidence_class"`
	ToolchainSeries        string                      `json:"toolchain_series"`
	GoExperiment           string                      `json:"go_experiment"`
	ToolchainEnvironment   ToolchainEnvironment        `json:"toolchain_environment"`
	RuntimeEnvironment     RuntimeEnvironment          `json:"runtime_environment"`
	Seed                   uint64                      `json:"seed"`
	Smoke                  bool                        `json:"smoke"`
	StartedAt              string                      `json:"started_at"`
	EndedAt                string                      `json:"ended_at"`
}

// ProvenanceArtifact names one captured provenance file inside the run
// directory together with its content hash and size.
type ProvenanceArtifact struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

// BinaryProvenance identifies one built benchmark binary and the captured
// "go version -m" output for it.
type BinaryProvenance struct {
	Path       string             `json:"path"`
	SHA256     string             `json:"sha256"`
	SizeBytes  int64              `json:"size_bytes"`
	GoVersionM ProvenanceArtifact `json:"go_version_m"`
}

// ToolchainEnvironment is the pinned build environment every benchmark binary
// is compiled under.
type ToolchainEnvironment struct {
	GOENV        string `json:"goenv"`
	GOTOOLCHAIN  string `json:"gotoolchain"`
	GOFLAGS      string `json:"goflags"`
	GOEXPERIMENT string `json:"goexperiment"`
	GOOS         string `json:"goos"`
	GOARCH       string `json:"goarch"`
	GOAMD64      string `json:"goamd64"`
	GOARM64      string `json:"goarm64"`
	GOFIPS140    string `json:"gofips140"`
	CGOEnabled   string `json:"cgo_enabled"`
}

// Assignments returns the environment as KEY=value entries, including the
// empty ones, so that applying them also clears inherited values.
func (environment ToolchainEnvironment) Assignments() []string {
	return []string{
		"GOENV=" + environment.GOENV,
		"GOTOOLCHAIN=" + environment.GOTOOLCHAIN,
		"GOFLAGS=" + environment.GOFLAGS,
		"GOEXPERIMENT=" + environment.GOEXPERIMENT,
		"GOOS=" + environment.GOOS,
		"GOARCH=" + environment.GOARCH,
		"GOAMD64=" + environment.GOAMD64,
		"GOARM64=" + environment.GOARM64,
		"GOFIPS140=" + environment.GOFIPS140,
		"CGO_ENABLED=" + environment.CGOEnabled,
	}
}

// RuntimeEnvironment is the pinned runtime environment every benchmark child
// process runs under.
type RuntimeEnvironment struct {
	GOMAXPROCS string `json:"gomaxprocs"`
	GOGC       string `json:"gogc"`
	GOMEMLIMIT string `json:"gomemlimit"`
	GODEBUG    string `json:"godebug"`
	GOWSSIMD   string `json:"gows_simd"`
}

// Assignments returns the environment as KEY=value entries, including the
// empty ones, so that applying them also clears inherited values.
func (environment RuntimeEnvironment) Assignments() []string {
	return []string{
		"GOMAXPROCS=" + environment.GOMAXPROCS,
		"GOGC=" + environment.GOGC,
		"GOMEMLIMIT=" + environment.GOMEMLIMIT,
		"GODEBUG=" + environment.GODEBUG,
		"GOWS_SIMD=" + environment.GOWSSIMD,
	}
}

// EnvSnapshot is a point-in-time host environment reading written to
// env-start.json and env-end.json, and one line of each guard log.
type EnvSnapshot struct {
	Load1                  float64 `json:"load1"`
	Load5                  float64 `json:"load5"`
	Load15                 float64 `json:"load15"`
	PMSetBattery           string  `json:"pmset_batt"`
	PMSetThermal           string  `json:"pmset_therm"`
	LogicalCPUs            int     `json:"logical_cpus"`
	MemoryBytes            uint64  `json:"memory_bytes"`
	BootIdentity           string  `json:"boot_identity"`
	Uptime                 string  `json:"uptime"`
	CapturedAt             string  `json:"captured_at"`
	ObservationNanoseconds int64   `json:"observation_nanoseconds"`
}

// Done is the run-complete marker written to done.json on success.
type Done struct {
	FinishedAt string `json:"finished_at"`
	Samples    int    `json:"samples"`
	Scenarios  int    `json:"scenarios"`
}
