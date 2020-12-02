package hashedrpz

import (
	"encoding/base32"
	"strings"
	"sync"

	"github.com/zeebo/blake3"
)

// Our base32 set akin to RFC4648 but lowercase
const encodeHexLowerCase = "0123456789abcdefghijklmnopqrstuv"

// Our base32 encoder
var noPadHexEncoding = base32.NewEncoding(encodeHexLowerCase).WithPadding(base32.NoPadding)

type HashedRPZ struct {
	sync.Mutex
	h *blake3.Hasher
}

// Hash hashes the given string s that should be in domain format (thus subdomain.example.com)
// and returns the HashedRPZ hashed variant of that.
//
// A mutex ensures that only one hasher at the same time runs
// Create multiple HashedRPZ for parallel operation.
func (h *HashedRPZ) Hash(s string) (final string) {
	h.Lock()
	defer h.Unlock()

	spl := strings.Split(s, ".")

	// The full label upto the level we are hashing it
	label := ""

	// Each label, starting at the TLD
	for i := len(spl) - 1; i >= 0; i-- {

		if len(final) > 200 {
			final = "*." + final
			break
		}

		l := spl[i]

		// Encode a wildcard verbatim
		if l == "*" {
			final = "*." + final
			continue
		}

		// Include the whole domain up to that point in the label,
		// as then 'example' in 'example.net' will not hash the same as in 'example.org'
		// and even better 'www' in 'www.example.net' will also be different from 'www.example.org'.
		// thus making it near impossible to even distinguish between 'www' or any other hostname
		label = l + "." + label

		// Hash the label and summarize it
		h.h.Reset()
		h.h.WriteString(label)

		// Determine the hash size based on the input string
		// Noting that a longer string results in more digest
		// thus a short string does not quickly clash with a longer one.
		//
		// The output string length (digest length) does not fully disclose label length, though gives a decent hint.
		m := len(l)
		if m < 4 {
			m = 4
		} else if m < 8 {
			m = 8
		} else {
			m = 16
		}

		hsh := make([]byte, m)

		// Get the digest
		d := h.h.Digest()
		d.Read(hsh)

		// Encode the hash into a base32-hex-lowercase string
		b32 := noPadHexEncoding.EncodeToString(hsh)

		// Prepend the base32hex-lc string
		final = b32 + "." + final
	}

	// Prepare for re-use, at least free up some things where possible
	h.h.Reset()

	return
}

func New(key string) (h HashedRPZ) {
	// Include a new blake3 hasher
	h.h = blake3.NewDeriveKey(key)
	return
}
