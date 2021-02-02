package hashedrpz

// HashedRPZ implements a hasher for generating HashedRPZ output from input domainnames.
// See the presentation included in this repository for more details.

import (
	"encoding/base32"
	"errors"
	"strings"
	"sync"

	"github.com/zeebo/blake3"
)

// ErrTooLong indicates that the input domain was too long when hashed
// the result from the Hash function is that final only contains the hashed
// labels upto that error. The caller can decide to wildcard the domain or not.
var ErrTooLong = errors.New("Domain too long to hash")

// encodeHexLowerCase is our base32 set akin to RFC4648 but lowercased
const encodeHexLowerCase = "0123456789abcdefghijklmnopqrstuv"

// noPadHexEncoding is our base32 encoder
var noPadHexEncoding = base32.NewEncoding(encodeHexLowerCase).WithPadding(base32.NoPadding)

// HashedRPZ represents a hasher, it has a mutex to ensure only a single caller at a time
type HashedRPZ struct {
	sync.Mutex
	h *blake3.Hasher
}

// Hash hashes the given string s that should be in domain format (thus subdomain.example.com)
// and returns the HashedRPZ hashed variant of that.
//
// A mutex ensures that only one hasher at the same time runs
// Create multiple HashedRPZ for parallel operation.
//
// Might return ErrTooLong (see description for details), thus do check.
func (h *HashedRPZ) Hash(s string, maxdomainlen int) (final string, err error) {
	h.Lock()
	defer h.Unlock()

	// Encode an empty label (root effectively) to empty
	// Callers likely will want to avoid that situation unless one wants to block the whole Internet...
	if len(s) == 0 {
		return
	}

	// Split the full left hand side into labels
	spl := strings.Split(s, ".")

	// The full label upto the level we are hashing it
	label := ""

	// Each label, starting at the TLD
	for i := len(spl) - 1; i >= 0; i-- {

		// Unfortunately, input domains can be very long already e.g. if
		// there is a hash for a video-id or tracking purposes encoded in them
		// thus we limit generating very long RPZ elements as they would not
		// fit in the destination domain.
		// and replace it with a wildcard; which might mean more gets blocked
		// than needed.
		if len(final) > maxdomainlen {
			err = ErrTooLong
			break
		}

		l := spl[i]

		// Encode a wildcard verbatim, as wildcards have special handling in DNS.
		if l == "*" {
			final = "*." + final
			continue
		}

		// Include the whole domain up to that point in the label,
		// as then 'example' in 'example.net' will not hash the same as in 'example.org'
		// and even better 'www' in 'www.example.net' will also be different from 'www.example.org'.
		// thus making it near impossible to even distinguish between 'www' or any other hostname.
		label = l + "." + label

		// Hash the label and summarize it.
		h.h.Reset()
		h.h.WriteString(label)

		// Determine the hash size based on the input string, this to limit
		// the amount of hashed output characters, if we hash everything at
		// 16 bytes, it would explode quickly.
		// Noting that a longer string results in more digest
		// thus a short string does not quickly clash with a longer one.
		//
		// The output string length (digest length) does not fully disclose
		// label length, though gives a decent hint.
		m := len(l)
		if m < 4 {
			m = 4
		} else if m < 8 {
			m = 8
		} else {
			m = 16
		}

		// Create a buffer for the output hash of the given length
		hsh := make([]byte, m)

		// Get the digest and store it in the hashed buffer
		d := h.h.Digest()
		d.Read(hsh)

		// Encode the hash into a base32-hex-lowercase string akin RRFC4648
		b32 := noPadHexEncoding.EncodeToString(hsh)

		// Prepend the base32hex-lc string
		final = b32 + "." + final
	}

	// Prepare for re-use, at least free up some things where possible
	h.h.Reset()

	return
}

// New creates a new HashedRPZ deriving the BLAKE3 key from the given string
// The string should be composed of both an inline and a out-of-band key.
func New(key string) (h HashedRPZ) {
	// Include a new blake3 hasher
	h.h = blake3.NewDeriveKey(key)
	return
}
