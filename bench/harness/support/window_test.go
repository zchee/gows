package support

import (
	"slices"
	"testing"
)

func TestVerifyEcho(t *testing.T) {
	pay := DeterministicPayload(64)
	corrupt := slices.Clone(pay)
	corrupt[32] ^= 0xFF

	tests := map[string]struct {
		expected []byte
		got      []byte
		wantErr  bool
	}{
		"match":            {expected: pay, got: slices.Clone(pay), wantErr: false},
		"length short":     {expected: pay, got: pay[:len(pay)-1], wantErr: true},
		"length long":      {expected: pay, got: append(slices.Clone(pay), 0x00), wantErr: true},
		"content mismatch": {expected: pay, got: corrupt, wantErr: true},
		"both empty":       {expected: nil, got: nil, wantErr: false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := VerifyEcho(tc.expected, tc.got)
			if tc.wantErr && err == nil {
				t.Fatalf("VerifyEcho(%d bytes, %d bytes) = nil, want error", len(tc.expected), len(tc.got))
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("VerifyEcho: unexpected error: %v", err)
			}
		})
	}
}
