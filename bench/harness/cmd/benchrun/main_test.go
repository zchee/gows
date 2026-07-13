package main

import "testing"

func TestParseLoadavg(t *testing.T) {
	tests := map[string]struct {
		raw     string
		want1   float64
		wantErr bool
	}{
		"darwin braces":   {raw: "{ 1.23 4.56 7.89 }", want1: 1.23},
		"plain triple":    {raw: "0.50 0.60 0.70", want1: 0.50},
		"trailing spaces": {raw: "  2.00 2.10 2.20 \n", want1: 2.00},
		"too few":         {raw: "{ 1.23 }", wantErr: true},
		"non numeric":     {raw: "{ a b c }", wantErr: true},
		"empty":           {raw: "", wantErr: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			l1, l5, l15, err := parseLoadavg(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got (%v,%v,%v)", l1, l5, l15)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if l1 != tc.want1 {
				t.Fatalf("load1 = %v, want %v", l1, tc.want1)
			}
			if l5 == 0 && l15 == 0 {
				t.Fatalf("load5/load15 not parsed: %v %v", l5, l15)
			}
		})
	}
}

func TestOffendersFromPgrep(t *testing.T) {
	const self = 4242
	tests := map[string]struct {
		out       string
		wantCount int
	}{
		"none":           {out: "", wantCount: 0},
		"one foreign":    {out: "1234 echoserver -lib gows\n", wantCount: 1},
		"only self":      {out: "4242 benchrun -policy p.json\n", wantCount: 0},
		"self and other": {out: "4242 benchrun\n1234 loadgen -addr x\n", wantCount: 1},
		"blank lines":    {out: "\n1234 echoserver\n\n", wantCount: 1},
		"two foreign":    {out: "1234 echoserver\n5678 echoserver\n", wantCount: 2},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := offendersFromPgrep(tc.out, self)
			if len(got) != tc.wantCount {
				t.Fatalf("offenders = %v (len %d), want %d", got, len(got), tc.wantCount)
			}
		})
	}
}
