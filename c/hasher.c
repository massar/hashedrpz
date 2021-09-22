/*
 * HashedRPZ C-edition, for inclusion into DNS servers written in C
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#include "hashedrpz.h"

static struct option long_options[] =
{
	{"key",			required_argument, NULL, 'k'},
	{"origindomain",	required_argument, NULL, 'o'},
	{"addwildcards",	optional_argument, NULL, 'w'},
	{"ignoretoolong",	optional_argument, NULL, 'i'},
	{NULL, 0, NULL, 0}
};

int main(int argc, char* argv[]) {
	int		ch, i;
	char		*key = NULL;
	char		*origindomain = NULL;
	hrpz_t		*h;
	char		*in = NULL;
	char		out[BUFSIZ];
	size_t		inlen = 0;
	hrpz_err_t	err;

	// loop over all of the options
	while ((ch = getopt_long(argc, argv, "k:o:wi", long_options, NULL)) != -1)
	{
		// check to see if a single character or long option came through
		switch (ch)
		{
			case 'k':
				if (key != NULL) {
					free(key);
				}
				key = strdup(optarg);
				break;

			case 'o':
				if (origindomain != NULL) {
					free(origindomain);
				}
				origindomain = strdup(optarg);
				break;

			case 'w':
				break;

			case 'i':
				break;

			default:
				fprintf(stderr, "Unknown option '%c'\n", ch);
				return 1;
		}
	}

	for(; optind < argc; optind++){ //when some extra arguments are passed
		printf("Given extra arguments: %s\n", argv[optind]);
	}

	if (key == NULL) {
		fprintf(stderr, "A key is required\n");
		return 1;
	}

	if (origindomain == NULL) {
		fprintf(stderr, "A origindomain is required\n");
		return 1;
	}

	h = hrpz_new(key);

	while (1) {
		ssize_t n = getline(&in, &inlen, stdin);
		if (n <= 0 || in == NULL) {
			break;
		}

		for (i=0;in[i] != '\0'; i++) {
			if (in[i] == '\n') {
				in[i] = '\0';
				break;
			}
		}

		err = hrpz_hash(h, in, origindomain, NULL, out, sizeof(out));
		if (err != HRPZ_ERR_NONE) {
			fprintf(stderr, "Error: %s (%d)\n", hrpz_errstr(err), err);
			break;
		}

		fprintf(stderr, "%s => %s\n", in, out);
	}

	free(in);

	hrpz_cleanup(h);

	return 0;
}
