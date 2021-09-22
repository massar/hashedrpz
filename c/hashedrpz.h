/*
 * HashedRPZ C-edition, for inclusion into DNS servers written in C
 */

#ifndef HASHEDRPZ_H
#define HASHEDRPZ_H 1

/* Get the PRI* and SCN* formats from inttypes.h */
#define __STDC_FORMAT_MACROS 1

#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * Official BLAKE3 implementation (CC0 1.0 Universal / Apache License 2.0)
 * https://github.com/BLAKE3-team/BLAKE3/blob/master/c/
 */
#include "BLAKE3/c/blake3.h"

/*
 * Storage for HashedRPZ abstraction
 */
typedef struct hrpz {
	char		*key;
	blake3_hasher	hasher;
} hrpz_t;

#define HRPZ_NOCALLBACK NULL
typedef void (*hrpz_callback_t)(const char *subdomain, const char *hash);

typedef int hrpz_bool_t;
#define HRPZ_FALSE 0
#define HRPZ_TRUE (!HRPZ_FALSE)

typedef unsigned int hrpz_err_t;

enum HRPZ_ERR {
       	HRPZ_ERR_NONE = 0,
	HRPZ_INVALID_INPUTS,
	HRPZ_ERR_INVALID_ORIGIN_DOMAIN,
	HRPZ_ERR_EMPTY_LABEL,
	HRPZ_ERR_WILDCARD_NOT_AT_START,
	HRPZ_ERR_TOO_LONG,
	HRPZ_ERR_EMPTY_SUBLABEL
};

const char *hrpz_errstr(hrpz_err_t err);

hrpz_t *hrpz_new(const char *key);

void hrpz_reset(hrpz_t *h);

void hrpz_cleanup(hrpz_t *h);

hrpz_err_t hrpz_hash(hrpz_t *h, const char *lefthandside, const char *origindomain, hrpz_callback_t callback, char *final, size_t finallen);

hrpz_err_t hrpz_hashwildcard(hrpz_t *h, const char *lefthandside, const char *origindomain, hrpz_callback_t callback, char *final, size_t finallen, hrpz_bool_t *iswildcard);

#endif /* !defined HASHEDRPZ_H */
