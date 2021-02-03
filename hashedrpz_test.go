package hashedrpz

// Simple golang tests and benchmarks for HashedRPZ

import (
	"bufio"
	"compress/gzip"
	"os"
	"strings"
	"testing"
)

type htest struct {
	Input         string
	Output        string
	Error         error
	ErrorWildcard error
	NumCallBacks  int
}

// origindomain indicates the RPZ zone where labels will be generated
const origindomain = "rpz.example.net"

// testkey indicates the key used for tests
const testkey = "teststring: 0KjULoiv d2VFuNPc RVabpOq3 eN6bmK0Z 2gwjCgDf fU2HVN5A 1Bz08wW4 Uy0JTMX0"

// tests provides a list of common tests cases to trigger possible corner cases.
var tests = []htest{
	{"", "", ErrEmptyLabel, ErrEmptyLabel, 0},
	{"com", "8r4m02g", nil, nil, 1},
	{"net", "1qpnbgg", nil, nil, 1},
	{"org", "8v95da8", nil, nil, 1},
	{"example.com", "slhf50h8dgst0.8r4m02g", nil, nil, 2},
	{"example.net", "kj8qsm2gn1o42.1qpnbgg", nil, nil, 2},
	{"example.org", "3m7l96r63tf8u.8v95da8", nil, nil, 2},
	{"www.example.com", "qtr7pq8.slhf50h8dgst0.8r4m02g", nil, nil, 3},
	{"www.example.net", "4ln83mo.kj8qsm2gn1o42.1qpnbgg", nil, nil, 3},
	{"longerlabel.example.net", "n10m898sngepm1u6t1h4hjkqhc.kj8qsm2gn1o42.1qpnbgg", nil, nil, 3},
	{"*.example.net", "*.kj8qsm2gn1o42.1qpnbgg", nil, nil, 3},
	{"notatstart.*.example.net", "", ErrWildcardNotAtStart, ErrWildcardNotAtStart, 2},
	{"*middle.example.net", "", ErrWildcardNotAtStart, ErrWildcardNotAtStart, 2},
	{"m*.example.net", "", ErrWildcardNotAtStart, ErrWildcardNotAtStart, 2},
	{"a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.0123456789abcdefghijklmnopqrstuv.example.net", "*.j5ni418.hv8ls60.ptilhs8.11v1t7g.6esbkao.kce9ido.ib563vg.4dlie60.ckn4lb0.kibrgt8.j2lie10.k481ego.2e8lg50.n1lr5g8.qcs689g.klfks3o.m86tq2g.jsheic0.v3009s8.sou3820.vbkvv38.679i40o.bqfs4mpqnia3vm63efg45eg7t0.kj8qsm2gn1o42.1qpnbgg", ErrTooLong, nil, 16},
}

// TestHash provides a very simple test covering all code paths
func TestHash(t *testing.T) {
	h := New(testkey)

	t.Run("Empty Origin", func(t *testing.T) {
		_, err := h.Hash("ignored", "", NoCallback)
		if err != ErrInvalidOriginDomain {
			return
		}
	})

	for _, tt := range tests {
		t.Run(tt.Input, func(t *testing.T) {
			o, err := h.Hash(tt.Input, origindomain, NoCallback)

			if err != tt.Error {
				t.Errorf("Expected error %s but got: %s (%q [%d+1+%d=%d])", tt.Error, err, o, len(o), len(origindomain), len(o)+1+len(origindomain))
				return
			}

			if err != nil {
				return
			}

			if o != tt.Output {
				t.Errorf("Expected output %q but got: %q [%d+1+%d=%d]", tt.Output, o, len(o), len(origindomain), len(o)+len(origindomain)+1)
				return
			}
		})
	}

	return
}

// TestHashWildcard provides a very simple test covering HashWildCard
func TestHashWildcard(t *testing.T) {
	h := New(testkey)

	t.Run("Empty Origin", func(t *testing.T) {
		_, _, err := h.HashWildcard("ignored", "", NoCallback)
		if err != ErrInvalidOriginDomain {
			return
		}
	})

	for _, tt := range tests {
		t.Run(tt.Input, func(t *testing.T) {
			o, _, err := h.HashWildcard(tt.Input, origindomain, NoCallback)

			if err != tt.ErrorWildcard {
				t.Errorf("Expected error %s but got: %s (%q [%d+1+%d=%d])", tt.Error, err, o, len(o), len(origindomain), len(o)+1+len(origindomain))
				return
			}

			if err != nil {
				return
			}

			if o != tt.Output {
				t.Errorf("Expected output %q but got: %q [%d+1+%d=%d]", tt.Output, o, len(o), len(origindomain), len(o)+len(origindomain)+1)
				return
			}

			t.Logf("%q [%d+1+%d=%d]", o, len(o), len(origindomain)+1, len(o)+1+len(origindomain)+1)
		})
	}

	return
}

// TestHashcallback tests the callback option
func TestHashCallback(t *testing.T) {
	h := New(testkey)

	t.Run("Empty Origin", func(t *testing.T) {
		expcallbacks := 0
		callbacks := 0

		_, err := h.Hash("ignored", "", func(subdomain string, hash string) {
			callbacks++
		})
		if err != ErrInvalidOriginDomain {
			return
		}

		if callbacks != expcallbacks {
			t.Errorf("Expected %d callbacks, got %d", expcallbacks, callbacks)
		}
	})

	for _, tt := range tests {
		t.Run(tt.Input, func(t *testing.T) {
			callbacks := 0

			o, err := h.Hash(tt.Input, origindomain, func(subdomain string, hash string) {
				callbacks++
				t.Logf("Callback for %q %q %q : %q", tt.Input, origindomain, subdomain, hash)
			})

			if err != tt.Error {
				t.Errorf("Expected error %s but got: %s (%q [%d+1+%d=%d])", tt.Error, err, o, len(o), len(origindomain), len(o)+1+len(origindomain))
				return
			}

			if err != nil {
				return
			}

			if o != tt.Output {
				t.Errorf("Expected output %q but got: %q [%d+1+%d=%d]", tt.Output, o, len(o), len(origindomain), len(o)+len(origindomain)+1)
				return
			}

			if callbacks != tt.NumCallBacks {
				t.Errorf("Expected %d callbacks, got %d", tt.NumCallBacks, callbacks)
			}

		})
	}

	return
}

// BenchmarkHasher provides a very simple test benchmark
func BenchmarkHashTests(b *testing.B) {
	h := New("teststring: eXXV1LwF vINdcL7v sXKtYoo7 EU6Cw2oI lM4Fa0ud 6RShLG9C T7ejeHdT gMaC3zV8")

	for i := 0; i < b.N; i++ {
		for _, tt := range tests {
			i++
			if i >= b.N {
				break
			}

			h.Hash(tt.Input, origindomain, NoCallback)

			// We ignore error checking, this is about speed ;)
		}
	}

	return
}

// BenchmarkHashMany tests a ownername that is very long
func BenchmarkHashMany(b *testing.B) {
	h := New("teststring: G8OiYV2A bxzbJv2z eo85UlaA s3Srw0H7 zVm6QSJ5 Uyrbf2mP aczoL4Ft TAc2Suzz")

	const input = "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.example.net"

	for i := 0; i < b.N; i++ {
		_, err := h.Hash(input, origindomain, NoCallback)
		if err != ErrTooLong {
			b.Errorf("Failed, expected ErrTooLong, but got: %s", err)
			return
		}
	}

	return
}

// BenchmarkHashSimple tests a simple domain (three labels)
func BenchmarkHashSimple(b *testing.B) {
	h := New("teststring: HsDNr7R6 PB5YjqtX p7ICqgN5 NDvpb7Ne wDkGLO33 A2P2lGzw wAb4vytB k09yzzAj")

	const input = "jeroen.massar.ch"

	for i := 0; i < b.N; i++ {
		_, err := h.Hash(input, origindomain, NoCallback)
		if err != nil {
			b.Errorf("Failed: %s", err)
			return
		}
	}

	return
}

// BenchmarkHash10M tests upto 10M entries from the tests/queryfile-example-10million-201202 file
// as provided by DNS-OARC for their https://github.com/DNS-OARC/dnsperf tool
// while older, it is a good common set of labels that are in use on the internet
// and thus also tests a variety of failure cases.
//
// (this timing also includes reading/processing the file :)
func BenchmarkHash10M(b *testing.B) {
	h := New("teststring: 2TIjIdz1 kfxooz7K NjfzpX2I AwJ8UODq 9A2QO8b1 tesMp3Kx Ik4qmDsM fB89XVQe")

	testfile := "tests/queryfile-example-10million-201202.gz"

	file, err := os.Open(testfile)

	if err != nil {
		b.Fatalf("Failed opening file %q: %s", testfile, err)
		return
	}

	defer file.Close()

	gz, err := gzip.NewReader(file)
	if err != nil {
		b.Fatalf("Failed to ungz %q: %s", testfile, err)
		return
	}

	scanner := bufio.NewScanner(gz)
	scanner.Split(bufio.ScanLines)

	i := 0
	toolong := 0
	wrongwildcard := 0
	totlength := 0
	totlabels := 0

	for scanner.Scan() {
		input := scanner.Text()

		i++

		// track the total input length
		totlength += len(input)

		// track the amount of labels
		totlabels += strings.Count(input, ".")

		_, err := h.Hash(input, origindomain, NoCallback)

		// Ignore this situation
		if err == ErrTooLong {
			toolong++
			continue
		}

		if err == ErrWildcardNotAtStart {
			wrongwildcard++
			continue
		}

		if err != nil {
			b.Errorf("Failed: %s", err)
			return
		}
	}

	b.N = i
	b.ReportMetric(float64(toolong), "toolong")
	b.ReportMetric(float64(wrongwildcard), "wrongwildcard")
	b.ReportMetric(float64(totlength/i), "avg.length")
	b.ReportMetric(float64(totlabels/i), "avg.#labels")

	// Note that these stats are skewed by broken DNS records that Hash() will reject
	// as the #labels is not correct when there is for instance "....net".
	//
	// Benchmarks are indicators anyway, not conclusive speedtests, as each platform is different
	// and in the above we include the counting of the labels and the error checking.

	return
}
