/*
 * HashedRPZ C-edition, for inclusion into DNS servers written in C
 *
 * XXX: Single-threaded because of BLAKE3, even if you call this multiple times!
 *
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "hashedrpz.h"

#define lengthof(arr) ((uint64_t)(sizeof(arr)/sizeof(arr[0])))

typedef struct {
	const char	*input;
	const char	*output;
	hrpz_err_t	error;
	hrpz_err_t	error_wildcard;
	uint64_t	numcallbacks;
} test_t;

// origindomain indicates the RPZ zone where labels will be generated
const char *origindomain = "rpz.example.net";

// testkey indicates the key used for tests
const char *testkey = "teststring: 0KjULoiv d2VFuNPc RVabpOq3 eN6bmK0Z 2gwjCgDf fU2HVN5A 1Bz08wW4 Uy0JTMX0";

// tests provides a list of common tests cases to trigger possible corner cases.
test_t tests[] = {
	{"", "", HRPZ_ERR_EMPTY_LABEL, HRPZ_ERR_EMPTY_LABEL, 0},
	{"com", "8r4m02g", HRPZ_ERR_NONE, HRPZ_ERR_NONE, 1},
	{"net", "1qpnbgg", HRPZ_ERR_NONE, HRPZ_ERR_NONE, 1},
	{"org.", "8v95da8", HRPZ_ERR_NONE, HRPZ_ERR_NONE, 1},
	{"example.com", "slhf50h8dgst0.8r4m02g", HRPZ_ERR_NONE, HRPZ_ERR_NONE, 2},
	{"example.net", "kj8qsm2gn1o42.1qpnbgg", HRPZ_ERR_NONE, HRPZ_ERR_NONE, 2},
	{"example.org", "3m7l96r63tf8u.8v95da8", HRPZ_ERR_NONE, HRPZ_ERR_NONE, 2},
	{"www.example.com", "qtr7pq8.slhf50h8dgst0.8r4m02g", HRPZ_ERR_NONE, HRPZ_ERR_NONE, 3},
	{"www.example.net", "4ln83mo.kj8qsm2gn1o42.1qpnbgg", HRPZ_ERR_NONE, HRPZ_ERR_NONE, 3},
	{"longerlabel.example.net", "n10m898sngepm1u6t1h4hjkqhc.kj8qsm2gn1o42.1qpnbgg", HRPZ_ERR_NONE, HRPZ_ERR_NONE, 3},
	{"*.example.net", "*.kj8qsm2gn1o42.1qpnbgg", HRPZ_ERR_NONE, HRPZ_ERR_NONE, 3},
	{"*.*.example.net", "", HRPZ_ERR_WILDCARD_NOT_AT_START, HRPZ_ERR_WILDCARD_NOT_AT_START, 2},
	{"notatstart.*.example.net", "", HRPZ_ERR_WILDCARD_NOT_AT_START, HRPZ_ERR_WILDCARD_NOT_AT_START, 2},
	{"*middle.example.net", "", HRPZ_ERR_WILDCARD_NOT_AT_START, HRPZ_ERR_WILDCARD_NOT_AT_START, 2},
	{"m*.example.net", "", HRPZ_ERR_WILDCARD_NOT_AT_START, HRPZ_ERR_WILDCARD_NOT_AT_START, 2},
	{"empty..sublabel.example.net", "", HRPZ_ERR_EMPTY_SUBLABEL, HRPZ_ERR_EMPTY_SUBLABEL, 3},
	{"empty.sublabel..", "", HRPZ_ERR_EMPTY_SUBLABEL, HRPZ_ERR_EMPTY_SUBLABEL, 0},
	{"a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.0123456789abcdefghijklmnopqrstuv.example.net", "*.j5ni418.hv8ls60.ptilhs8.11v1t7g.6esbkao.kce9ido.ib563vg.4dlie60.ckn4lb0.kibrgt8.j2lie10.k481ego.2e8lg50.n1lr5g8.qcs689g.klfks3o.m86tq2g.jsheic0.v3009s8.sou3820.vbkvv38.679i40o.bqfs4mpqnia3vm63efg45eg7t0.kj8qsm2gn1o42.1qpnbgg", HRPZ_ERR_TOO_LONG, HRPZ_ERR_NONE, 24},
};

#define ATTR_FORMAT(type, x, y) __attribute__ ((format(type, x, y)))

int verbosity = 0;

void v(int level, const char *fmt, ...) ATTR_FORMAT(printf, 2, 3);
void v(int level, const char *fmt, ...) {
	va_list ap;

	// Don't print unless verbosity is at desired level
	if (verbosity < level) {
		return;
	}

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
}

/* Global callback, just for testing though and just checks how often it was called */
uint64_t callbacks;
void callback(const char *subdomain, const char *hash);
void callback(const char *subdomain, const char *hash) {
	callbacks++;
	v(3, "Callback %" PRIu64 " for \"%s\" \"%s\"\n", callbacks, subdomain, hash);
}

int testhash(test_t *t);
int testhash(test_t *t) {
	hrpz_err_t	err;
	char		final[1024];
	int		res = 0;
	const char	tname[] = "Hash";

	hrpz_t *h = hrpz_new(testkey);

	while (res == 0) {
		if (h == NULL) {
			fprintf(stderr, "FAIL: Could not initialize HashedRPZ\n");
			res = 1;
			break;
		}

		// Reset callbacks count
		callbacks = 0;

		// Call the hasher
		err = hrpz_hash(h, t->input, origindomain, callback, final, sizeof(final));

		v(2, "%-20s (%d/%d): \"%s\" => \"%s\" (callbacks=%" PRIu64 "/%" PRIu64 ")\n", tname, err, t->error, t->input, final, callbacks, t->numcallbacks);

		if (callbacks != t->numcallbacks) {
			fprintf(stderr, "FAIL: %s(%s) Expected callbacks %" PRIu64 ", got %" PRIu64 "\n", tname, t->input, t->numcallbacks, callbacks);
			res = 1;
			break;
		}

		if (err != t->error) {
			fprintf(stderr, "FAIL: %s(%s) Expected error %d (\"%s\") but got error %d (\"%s\")\n", tname, t->input, t->error, hrpz_errstr(t->error), err, hrpz_errstr(err));
			res = 1;
			break;
		}

		if (err != HRPZ_ERR_NONE) {
			break;
		}

		if (strcmp(t->output, final) != 0) {
			fprintf(stderr, "FAIL: %s(%s) Expected \"%s\", got \"%s\"\n", tname, t->input, t->output, final);
			res = 1;
			break;
		}

		break;
	}

	hrpz_cleanup(h);

	return res;
}

int testhashwildcard(test_t *t);
int testhashwildcard(test_t *t) {
	hrpz_err_t	err;
	char		final[1024];
	int		res = 0;
	int		iswildcard;
	const char	tname[] = "HashWildcard";

	hrpz_t *h = hrpz_new(testkey);

	while (res == 0) {
		if (h == NULL) {
			fprintf(stderr, "FAIL: Could not initialize HashedRPZ\n");
			res = 1;
			break;
		}

		err = hrpz_hashwildcard(h, t->input, origindomain, HRPZ_NOCALLBACK, final, sizeof(final), &iswildcard);

		v(2, "%-20s (%d/%d): \"%s\" => \"%s\"\n", tname, err, t->error_wildcard, t->input, final);

		if (err != t->error_wildcard) {
			fprintf(stderr, "FAIL: %s(%s) Expected error %d (\"%s\") but got error %d (\"%s\")\n", tname, t->input, t->error, hrpz_errstr(t->error), err, hrpz_errstr(err));
			res = 1;
			break;
		}

		if (err != HRPZ_ERR_NONE) {
			break;
		}


		if (strcmp(t->output, final) != 0) {
			fprintf(stderr, "FAIL: %s(%s) Expected \"%s\", got \"%s\"\n", tname, t->input, t->output, final);
			res = 1;
			break;
		}

		break;
	}

	hrpz_cleanup(h);

	return res;
}

int main(int argc, char* argv[]) {
	unsigned int	i;
	int		a, n, totfails = 0;

	for (a = 0; a < argc; a++) {
		if (strcmp(argv[a], "-v") == 0) verbosity++;
	}

	for (i = 0; i < lengthof(tests); i++) {
		test_t *t = &tests[i];

		v(2, "############################################################# %s\n", "TEST");
		v(2, "Test/%s => \"%s\", errhash=%d, errhashwild=%d, numcallbacks=%" PRIu64 "\n", t->input, t->output, t->error, t->error_wildcard, t->numcallbacks);

		n = 0;
		n += testhash(t);
		n += testhashwildcard(t);

		v(1, "    --- %s: Test/%s\n", (n == 0 ? "PASS" : "FAIL"), t->input);
		totfails += n;
	}

	// Always print PASS / FAIL
	printf("%s\n", totfails == 0 ? "PASS" : "FAIL");

	return totfails == 0 ? 0 : 1;
}
