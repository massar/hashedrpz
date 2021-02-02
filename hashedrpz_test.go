package hashedrpz

// Simple golang tests and benchmarks

import (
	"testing"
)

type htest struct {
	Input  string
	Output string
	Error  error
}

// tests provides a list of common tests cases to trigger possible corner cases.
var tests = []htest{
	{"", "", nil},
	{"com", "4n79ero.", nil},
	{"net", "t6mlmog.", nil},
	{"org", "6g3gotg.", nil},
	{"example.com", "j1bpo4rr43bmm.4n79ero.", nil},
	{"example.net", "bntj69s29vpfk.t6mlmog.", nil},
	{"example.org", "nsldgambsfoog.6g3gotg.", nil},
	{"www.example.com", "9m2s0qg.j1bpo4rr43bmm.4n79ero.", nil},
	{"www.example.net", "ik5t5c0.bntj69s29vpfk.t6mlmog.", nil},
	{"wildcard.example.net", "iqgtfiap2gohi1imdjoscdo6b8.bntj69s29vpfk.t6mlmog.", nil},
	{"*.example.net", "*.bntj69s29vpfk.t6mlmog.", nil},
	{"0123456789abcdefghijklmnopqrstuv.0123456789abcdefghijklmnopqrstuv.0123456789abcdefghijklmnopqrstuv.0123456789abcdefghijklmnopqrstuv.0123456789abcdefghijklmnopqrstuv.example.net", "", ErrTooLong},
}

// TestHasher provides a very simple test covering all code paths
func TestHasher(t *testing.T) {
	h := New("teststring")

	for _, tt := range tests {
		t.Run(tt.Input, func(t *testing.T) {
			o, err := h.Hash(tt.Input, 64)

			if err != tt.Error {
				t.Errorf("Expected error %s but got: %s (%q [%d])", tt.Error, err, o, len(o))
				return
			}

			if err != nil {
				return
			}

			if o != tt.Output {
				t.Errorf("Expected output %q but got: %q [%d]", tt.Output, o, len(o))
				return
			}
		})
	}

	return
}

// BenchmarkHasher provides a very simple test benchmark
func BenchmarkHasher(b *testing.B) {
	h := New("teststring")

	for i := 0; i < b.N; i++ {
		for _, tt := range tests {
			i++
			if i >= b.N {
				break
			}

			h.Hash(tt.Input, 64)
		}
	}

	return
}
