package main

import "testing"

func TestParseClientKind(t *testing.T) {
	tests := map[string]struct {
		input   string
		want    clientKind
		wantErr bool
	}{
		"success: gows":            {input: "gows", want: clientGoWS},
		"success: gobwas":          {input: "gobwas", want: clientGobwas},
		"error: empty":             {input: "", wantErr: true},
		"error: unknown value":     {input: "coder", wantErr: true},
		"error: wrong case":        {input: "GOWS", wantErr: true},
		"error: leading space":     {input: " gows", wantErr: true},
		"error: trailing newline":  {input: "gobwas\n", wantErr: true},
		"error: superset misspell": {input: "gowss", wantErr: true},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := parseClientKind(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseClientKind(%q): got nil error, want error", tt.input)
				}
				if got != "" {
					t.Fatalf("parseClientKind(%q): got kind %q on error, want empty", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseClientKind(%q): unexpected error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("parseClientKind(%q): got %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
