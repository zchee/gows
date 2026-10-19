package support

import "testing"

func TestRunLogPrefix(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		scenario, block, library string
		want                     string
	}{
		"success: plain components are joined with double underscores": {
			scenario: "echo-1k", block: "block-000", library: "gows",
			want: "echo-1k__block-000__gows",
		},
		"success: separators and spaces become dashes": {
			scenario: "a/b\\c:d e", block: "x/y", library: "lib name",
			want: "a-b-c-d-e__x-y__lib-name",
		},
		"success: dots and underscores are kept": {
			scenario: "s.v_1", block: "b", library: "l",
			want: "s.v_1__b__l",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if got := RunLogPrefix(tt.scenario, tt.block, tt.library); got != tt.want {
				t.Fatalf("RunLogPrefix(%q, %q, %q) = %q, want %q", tt.scenario, tt.block, tt.library, got, tt.want)
			}
		})
	}
}

func TestSafeName(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		value string
		want  string
	}{
		"success: unchanged":              {value: "gows-rbuf1k", want: "gows-rbuf1k"},
		"success: path separators":        {value: "a/b\\c", want: "a-b-c"},
		"success: colon and space":        {value: "x:y z", want: "x-y-z"},
		"success: other bytes untouched":  {value: "a*b?c", want: "a*b?c"},
		"success: empty stays empty":      {value: "", want: ""},
		"success: multibyte is untouched": {value: "日本/語", want: "日本-語"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if got := SafeName(tt.value); got != tt.want {
				t.Fatalf("SafeName(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestValidArtifactID(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		value string
		want  bool
	}{
		"success: session identifier":        {value: "session-20260715T000000Z-0011223344556677", want: true},
		"success: letters digits dash dot _": {value: "gows_v0.4-rc1", want: true},
		"success: leading dot name":          {value: ".hidden", want: true},
		"error: empty":                       {value: "", want: false},
		"error: dot":                         {value: ".", want: false},
		"error: dot dot":                     {value: "..", want: false},
		"error: slash":                       {value: "a/b", want: false},
		"error: backslash":                   {value: "a\\b", want: false},
		"error: space":                       {value: "a b", want: false},
		"error: colon":                       {value: "a:b", want: false},
		"error: non-ASCII letter":            {value: "é", want: false},
		"error: NUL byte":                    {value: "a\x00", want: false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if got := ValidArtifactID(tt.value); got != tt.want {
				t.Fatalf("ValidArtifactID(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}
