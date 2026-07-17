package support

import (
	"strings"
	"testing"
)

func TestValidSHA256(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		value string
		want  bool
	}{
		"canonical lowercase digest": {value: strings.Repeat("0123456789abcdef", 4), want: true},
		"uppercase digest":           {value: strings.Repeat("A", 64), want: false},
		"mixed case digest":          {value: "a" + strings.Repeat("B", 63), want: false},
		"too short":                  {value: strings.Repeat("a", 63), want: false},
		"too long":                   {value: strings.Repeat("a", 65), want: false},
		"non-hex characters":         {value: strings.Repeat("g", 64), want: false},
		"empty":                      {value: "", want: false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := ValidSHA256(tc.value); got != tc.want {
				t.Fatalf("ValidSHA256(%q) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}
