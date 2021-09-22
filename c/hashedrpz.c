/*
 * HashedRPZ C-edition, for inclusion into DNS servers written in C
 *
 * Note: Single-threaded because of BLAKE3, even if you call this multiple times!
 *       A global lock around the blake3 calls prevents re-entry. 
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "hashedrpz.h"

// RFC4648 Hex base32 Lowercased
#include "base32hex_lc.h"

#define lengthof(arr) ((uint64_t)(sizeof(arr)/sizeof(arr[0])))
#define memzero(obj,len) memset(obj,0,len)

// Global lock as the BLAKE3 library is not re-entrant
pthread_mutex_t hrpz_blake3_mutex;

// Error strings, see hrpz_errstr()
const char *hrpzerrs[] = {
	"No Error",
	"Invalid Inputs provided",
	"Invalid Origin Domain (empty/root/leading-dot)",
	"Empty Label provided (RPZ the root?)",
	"Wildcard (*) not at start of left hand side",
	"Domain too long to hash",
	"Empty Sub Label (eg. dom..example.com)",
};

// hrpz_errstr returns an error string for a given HashedRPZ error
const char *hrpz_errstr(hrpz_err_t err) {
	if (err >= lengthof(hrpzerrs)) {
		return "Unknown Error";
	}

	return hrpzerrs[err];
}

// hrpz_new creates a new HashedRPZ for other operations
hrpz_t *hrpz_new(const char *key) {
	hrpz_t *h = calloc(sizeof(*h), 1);
	if (h == NULL) {
		return NULL;
	}

	// Keep the key for reset() purposes
	h->key = strdup(key);
	if (h->key == NULL) {
		return NULL;
	}

	// Initialize the hasher and derive the key
	blake3_hasher_init_derive_key(&h->hasher, key);
	// Note: we actually re-init before doing anything

	return h;
}

// hrpz_cleanup cleans up and frees the HashedRPZ structure
void hrpz_cleanup(hrpz_t *h) {
	if (h == NULL) {
		return;
	}

	// Cleanup the key copy
	free(h->key);

	// BLAKE3 does not have a cleanup

	// Free memory
	free(h);

	return;
}

/*
 * hrpz_hash hashes the lefthandside that should be in domain format (thus ```host.example.org```)
 * and returns the HashedRPZ hashed variant of that in the caller-allocated 'final' variable limited by finallen.
 *
 * Lefthandside is allowed to end to be fully qualified (ending in a '.') but it will be ignored.
 *
 * The origindomain (e.g. ```rpz.example.com```) is supplied to limit the
 * length of the resulting ownername to ensure it does not exceed the full
 * length of a domain name.
 *
 * The origindomain is not used for hashing, only for limiting/detecting length issues.
 *
 * A mutex ensures that only one hasher at the same time runs
 * Create multiple HashedRPZ, e.g. one per go process, for parallel operation.
 *
 * The callback will be called for every hashed label, thus allowing the user to do intermediate lookups.
 * One can use a function closure to pass parameters that the callback might need.
 *
 * Will return HRPZ_ERR_INVALID_ORIGIN_DOMAIN if the origin domain is empty or root, or start with a '.'.
 *
 * Will return HRPZ_ERR_EMPTY_LABEL if the label to hash is empty, this to avoid blocking the root of DNS.
 *
 * Will return HRPZ_ERR_WILDCARD_NOT_AT_START when there is a wildcard not at the start of the left hand side.
 *
 * Might return HRPZ_ERR_TOOLONG (see description for details on how to handle it),
 * thus do check for error returns.
 *
 * Will return HRPZ_ERR_EMPTY_SUB_LABEL if an empty sublabel is found.
 */
hrpz_err_t hrpz_hash(hrpz_t *h, const char *lefthandside, const char *origindomain, hrpz_callback_t callback, char *final, size_t finallen) {
	size_t		lhslen,
			lhs,
			label,
			maxdomainlen,
			m,
			finalcur = 0,
			blen,
			i;
	char		c;
	uint8_t		hsh[16],
			b32[BASE32_LEN(16)];

	// We need a place to put things back into and at least a TLD
	if (final == NULL || finallen < 5) {
		return HRPZ_INVALID_INPUTS;
	}

	// Ensure that the final buffer is empty
	memzero(final, finallen);

	// Ensure that the origindomain is not empty or the root or has a leading dot
	if (origindomain == NULL || origindomain[0] == '\0' || origindomain[0] == '.') {
		return HRPZ_ERR_INVALID_ORIGIN_DOMAIN;
	}

	/*
	 * The maximum domain length:
	 * 255 - max ownername length as per RFC1035
	 *  16 - maximum hash length for a label
	 *   1 - the dot separating hash and origindomain
	 *   l - the length of the origindomain
	 *
	 * Noting that the 'spare' 16 bytes when triggered accomodates a '*.' wildcard easily.
	 */
	maxdomainlen = 255 - 16 - 1 - strlen(origindomain);

	/*
	 * Reject encoding an empty label (root effectively) to empty.
	 * Callers likely will want to avoid that situation unless one wants to block the whole Internet...
	 */
	lhslen = strlen(lefthandside);
	if (lhslen == 0) {
		return HRPZ_ERR_EMPTY_LABEL;
	}

	// lhs tracks the left hand side upto the level we are hashing.
	lhs = lhslen - 1;

	// Ignore the final dot if it exists
	if (lefthandside[lhs] == '.') {
		lhslen--;
		lhs--;

		// Still got a dot at the end?
		if  (lefthandside[lhs] == '.') {
			return HRPZ_ERR_EMPTY_SUBLABEL;
		}
	}

	/*	
	 * We use offsets (lhs + label) into lefthandside to avoid copying of the string.
 	 *
	 * This includes the whole domain up to that point in the subdomain,
	 * as then 'example' in 'example.net' will not hash the same as in 'example.org'
	 * and even better 'www' in 'www.example.net' will also be different from 'www.example.org'.
	 * thus making it near impossible to even distinguish between 'www' or any other hostname.
	 *	
	 * label indicates the 'end' of the label
	 *	
	 *          +--- label
	 *          V
	 * left.hand.side
	 *      ^
	 *      +-- lhs
 	 *
	 * Thus  lefthandside[lhs:] gives us 'hand.side'.
	 * while lefthandside[lhs:label] gives us 'hand'.
 	 *	
	 * We start at the end of the label.
	 */
	label = lhs + 1;

	// Each label, starting at the TLD (right to left)
	for (i = lhs; ; i--) {
		c = lefthandside[i];

		// When no dot yet, this is the left hand side
		if (c != '.') {
			lhs = (size_t)i;
		}

		// Encode a wildcard verbatim, as wildcards have special handling in DNS.
		// Wildcards can only be at the start, thus stop processing further.
		if (c == '*') {
			// Wildcard has to be at the start of the label and the only char in that label
			if (i != 0 || label != lhs+1) {
				return HRPZ_ERR_WILDCARD_NOT_AT_START;
			}

			if ((finalcur + 2) > finallen) {
				return HRPZ_ERR_TOO_LONG;
			}

			// No need to hash this further
			memmove(&final[2], final, finalcur);
			final[0] = '*';
			final[1] = '.';
			finalcur += 2;

			// Call the callback
			if (callback != NULL) {
				callback(&lefthandside[lhs], final);
			}

			// Nothing left (i = 0, thus would break next anyway)
			return HRPZ_ERR_NONE;
		}

		// Not a label separator and not at the start, then continue looking
		if (c != '.' && i != 0) {
			continue;
		}

		// We hit a separator or start of the lefthandside, thus hash this portion and test

		// Determine the hash size based on the input string, this to limit
		// the amount of hashed output characters, if we hash everything at
		// 16 bytes, it would explode quickly.
		// Noting that a longer string results in more digest
		// thus a short string does not quickly clash with a longer one.
		//
		// The output string length (digest length) does not fully disclose
		// left hand side length, though gives a decent hint.
		m = label - lhs;
		if (lhs >= label) {
			return HRPZ_ERR_EMPTY_SUBLABEL;
		} else if (m < 4) {
			m = 4;
		} else if (m < 8) {
			m = 8;
		} else {
			m = 16;
		}

		// Due to BLAKE3 library not being re-entrant, lock globally
		pthread_mutex_lock(&hrpz_blake3_mutex);

		// Golang version has a nice Reset() function.
		// C has not, thus re-init completely, wee bit slower to the key derivation
		blake3_hasher_init_derive_key(&h->hasher, h->key);

		// Hash the current part of the lefthandside
		blake3_hasher_update(&h->hasher, &lefthandside[lhs], lhslen - lhs);

		// Get the digest and store it in the hashed buffer
		blake3_hasher_finalize(&h->hasher, hsh, m);

		// Due to BLAKE3 library, unlock globally
		pthread_mutex_unlock(&hrpz_blake3_mutex);

		// Encode the hash into a base32-hex-lowercase string akin RFC4648
		memzero(b32, sizeof(b32));
		base32_encode(hsh, m, b32);

		// Length of base32 of the hash
		blen = strlen((const char *)b32);

		// Will it still fit?
		if ((finalcur + blen + 1) > finallen) {
			return HRPZ_ERR_TOO_LONG;
		}

		if (finalcur != 0) {
			// Move the current final out of the way so that we prepend the base32hex_lc label
			memmove(&final[blen+1], final, finalcur);
			final[blen] = '.';
			finalcur++;
		}

		memcpy(final, b32, blen);
		finalcur += blen;

		/*
		 * Unfortunately, input domains can be very long already e.g. if
		 * there is a hash for a video-id or tracking purposes encoded in them
		 * thus we limit generating very long RPZ elements as they would not
		 * fit in the destination domain.
		 * and replace it with a wildcard; which might mean more gets blocked
		 * than needed.
		 */
		if (finalcur >= maxdomainlen) {
			return HRPZ_ERR_TOO_LONG;
		}

		if (callback != NULL) {
			callback(&lefthandside[lhs], final);
		}

		// The label ends just before the current separator (.)
		label = lhs - 1;

		// i is size_t and thus can't go negative, thus break when we need to
		if (i == 0) break;
	}

	return HRPZ_ERR_NONE;
}

/*
 * hrpz_hashwildcard calls hrpz_hash() but when the maxdomainlength is exceeded, it encodes
 * the remaining labels as a wildcard inside the domain that fitted.
 *
 * Thus for example an input of ```host.v.e.r.y.l.o.n.g.example.com``` would
 * encode as ```*.n.g.example.com```
 * (if the domainname would be much longer than given in this example, see test cases for the real version).
 */
hrpz_err_t hrpz_hashwildcard(hrpz_t *h, const char *lefthandside, const char *origindomain, hrpz_callback_t callback, char *final, size_t finallen, hrpz_bool_t *iswildcard) {
	hrpz_err_t err = hrpz_hash(h, lefthandside, origindomain, callback, final, finallen);

	if (err == HRPZ_ERR_TOO_LONG) {
		*iswildcard = HRPZ_TRUE;

		memmove(&final[2], final, finallen-2);
		final[0] = '*';
		final[1] = '.';
		err = HRPZ_ERR_NONE;
	} else {
		*iswildcard = HRPZ_FALSE;
	}

	return err;
}
