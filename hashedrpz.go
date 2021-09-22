package hashedrpz

// HashedRPZ implements a hasher for generating HashedRPZ output from input domainnames.
// See the README.md and the presentation included in this repository for more details.

import (
	"encoding/base32"
	"errors"
	"sync"

	"github.com/zeebo/blake3"
)

// ErrInvalidOriginDomain is returned when the provided is empty, the root (.) or has a leading dot.
var ErrInvalidOriginDomain = errors.New("Invalid Origin Domain (empty/root/leading-dot)")

// ErrEmptyLabel is returned when it is attempted to encode an empty label
var ErrEmptyLabel = errors.New("Empty Label provided (RPZ the root?)")

// ErrWildcardNotAtStart is returned when there is a wildcard in the middle of the left hand side
var ErrWildcardNotAtStart = errors.New("Wildcard (*) not at start of left hand side")

// ErrTooLong indicates that the input domain was too long when hashed
// the result from the Hash function is that final only contains the hashed
// labels upto that error. The caller can decide to wildcard the domain or not.
//
// This is used for a very simple check that just checks that we will never exceed
// the maximum domainlength; though, one already has to substract the $ORIGIN of
// the domain (e.g. ```.rpz.example.net```) that this RPZ ownername is part of.
// Thus typically, eg. given ```.rpz.example.net``` of length 14, it already becomes
// 255-16-15 = 224; hence why 200 is normally the suggested value, but one can
// accurately guess this value given the origin.
var ErrTooLong = errors.New("Domain too long to hash")

// ErrEmptySublabel is returned when a situation like "dom..example.com" is encountered
var ErrEmptySublabel = errors.New("Empty Sub Label (eg. dom..example.com)")

// encodeHexLowerCase is our base32 set akin to RFC4648 but lowercased
const encodeHexLowerCase = "0123456789abcdefghijklmnopqrstuv"

// noPadHexEncoding is our base32 encoder
var noPadHexEncoding = base32.NewEncoding(encodeHexLowerCase).WithPadding(base32.NoPadding)

// HashedRPZ represents a hasher, it has a mutex to ensure only a single caller at a time
type HashedRPZ struct {
	sync.Mutex
	h *blake3.Hasher
}

// HashCallback is called by Hash after each sublabel has been hashed allowing
// a caller to check at each part of the lefthandside the label that has been hashed.
type HashCallback func(subdomain string, hash string)

// NoCallback can be used to clearly show in the calling function that no callback is being used
// (opposed to having a 'nil' and having to check what that nil is for)
var NoCallback HashCallback = nil

// Hash hashes the lefthandside that should be in domain format (thus ```host.example.org```)
// and returns the HashedRPZ hashed variant of that.
//
// Lefthandside is allowed to end to be fully qualified (ending in a '.') but it will be ignored.
//
// The origindomain (e.g. ```rpz.example.com```) is supplied to limit the
// length of the resulting ownername to ensure it does not exceed the full
// length of a domain name.
//
// The origindomain is not used for hashing, only for limiting/detecting length issues.
//
// A mutex ensures that only one hasher at the same time runs
// Create multiple HashedRPZ, e.g. one per go process, for parallel operation.
//
// The callback will be called for every hashed label, thus allowing the user to do intermediate lookups.
// One can use a function closure to pass parameters that the callback might need.
//
// Will return ErrInvalidOriginDomain if the origin domain is empty or root, or start with a '.'.
//
// Will return ErrEmptyLabel if the label to hash is empty, this to avoid blocking the root of DNS.
//
// Will return ErrWildcardNotAtStart when there is a wildcard not at the start of the left hand side.
//
// Might return ErrTooLong (see description for details on how to handle it),
// thus do check for error returns.
//
// Will return ErrEmptySubLabel if an empty sublabel is found.
func (h *HashedRPZ) Hash(lefthandside string, origindomain string, callback HashCallback) (final string, err error) {
	// Ensure that the origindomain is not empty or the root or has a leading dot.
	if origindomain == "" || origindomain == "." || origindomain[0] == '.' {
		err = ErrInvalidOriginDomain
		return
	}

	// The maximum domain length:
	// 255 - max ownername length as per RFC1035
	//  16 - maximum hash length for a label
	//   1 - the dot separating hash and origindomain
	//   l - the length of the origindomain
	//
	// Noting that the 'spare' 16 bytes when triggered accomodates a '*.' wildcard easily.
	maxdomainlen := 255 - 16 - 1 - len(origindomain)

	// Reject encoding an empty label (root effectively) to empty.
	// Callers likely will want to avoid that situation unless one wants to block the whole Internet...
	if len(lefthandside) == 0 {
		err = ErrEmptyLabel
		return
	}

	// lhs tracks the left hand side upto the level we are hashing.
	lhs := len(lefthandside)-1

	// Remove the final dot if it exists
	if (lefthandside[lhs] == '.') {
		lefthandside = lefthandside[:lhs]
		lhs--

		// Still got a dot at the end?
		if (lefthandside[lhs] == '.') {
			err = ErrEmptySublabel
			return
		}
	}

	// We use offsets (lhs + label) into lefthandside to avoid copying of the string.
	//
	// This includes the whole domain up to that point in the subdomain,
	// as then 'example' in 'example.net' will not hash the same as in 'example.org'
	// and even better 'www' in 'www.example.net' will also be different from 'www.example.org'.
	// thus making it near impossible to even distinguish between 'www' or any other hostname.
	//
	// label indicates the 'end' of the label
	//
	//          +--- label
	//          V
	// left.hand.side
	//      ^
	//      +-- lhs
	//
	// Thus  lefthandside[lhs:] gives us 'hand.side'.
	// while lefthandside[lhs:label] gives us 'hand'.
	//
	// We start at the end of the label.
	label := lhs + 1

	// Lock, to ensure we do not use the blake3 hasher recursively from multiple goprocs
	h.Lock()
	defer h.Unlock()

	// Each label, starting at the TLD (right to left)
	for i := lhs; i >= 0; i-- {
		c := lefthandside[i]

		// When no dot yet, this is the left hand side
		if c != '.' {
			lhs = i
		}

		// Encode a wildcard verbatim, as wildcards have special handling in DNS.
		// Wildcards can only be at the start, thus stop processing further.
		if c == '*' {
			// Wildcard has to be at the start of the label and the only char in that label
			if i != 0 || label != lhs+1 {
				err = ErrWildcardNotAtStart
				return
			}

			// No need to hash this further
			final = "*." + final

			// Call the callback
			if callback != nil {
				callback(lefthandside[lhs:], final)
			}

			// Nothing left (i = 0, thus would break next anyway)
			break
		}

		// Not a label separator and not at the start, then continue looking
		if c != '.' && i != 0 {
			continue
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
		m := label - lhs
		if m <= 0 {
			err = ErrEmptySublabel
			return
		} else if m < 4 {
			m = 4
		} else if m < 8 {
			m = 8
		} else {
			m = 16
		}

		// Reset what we had upto now
		h.h.Reset()

		// Hash the current part of the lefthandside
		h.h.WriteString(lefthandside[lhs:])

		// Create a buffer for the output hash of the given length
		hsh := make([]byte, m)

		// Get the digest and store it in the hashed buffer
		d := h.h.Digest()
		d.Read(hsh)

		// Encode the hash into a base32-hex-lowercase string akin RFC4648
		b32 := noPadHexEncoding.EncodeToString(hsh)

		if final == "" {
			// First label thus it is the TLD
			final = b32
		} else {
			// Prepend the base32hex-lowercase string
			final = b32 + "." + final
		}

		// Unfortunately, input domains can be very long already e.g. if
		// there is a hash for a video-id or tracking purposes encoded in them
		// thus we limit generating very long RPZ elements as they would not
		// fit in the destination domain.
		// and replace it with a wildcard; which might mean more gets blocked
		// than needed.
		if len(final) >= maxdomainlen {
			err = ErrTooLong
			break
		}

		if callback != nil {
			callback(lefthandside[lhs:], final)
		}

		// The label ends just before the current separator (.)
		label = lhs - 1
	}

	// Prepare for re-use, at least free up some things where possible
	h.h.Reset()

	return
}

// HashWildcard calls Hash() but when the maxdomainlength is exceeded, it encodes
// the remaining labels as a wildcard inside the domain that fitted.
//
// Thus for example an input of ```host.v.e.r.y.l.o.n.g.example.com``` would
// encode as ```*.n.g.example.com```.
// (if the domainname would be much longer than given in this example, see test cases for the real version).
func (h *HashedRPZ) HashWildcard(lefthandside string, origindomain string, callback HashCallback) (final string, iswildcard bool, err error) {
	final, err = h.Hash(lefthandside, origindomain, callback)

	// When the string was to long, prefix a wildcard and ignore the error
	if err == ErrTooLong {
		iswildcard = true
		final = "*." + final
		err = nil
	}

	return
}

// New creates a new HashedRPZ deriving the BLAKE3 key from the given string
// The string should be composed of both an inline and a out-of-band key.
func New(key string) (h HashedRPZ) {
	// Include a new blake3 hasher
	h.h = blake3.NewDeriveKey(key)
	return
}
