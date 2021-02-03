# HashedRPZ by Jeroen Massar

This repository provides Golang code for the HashedRPZ implementation.

HashedRPZ provides a method of being able to distribute RPZ and normal domain block lists,
without exposing the real contents to the world. This can be used for instance to block
malicious and illegal domains without exposing the actual domains to anybody able to see the entries of the list.

HashedRPZ hashes domainnames, thus making it hard to find out what the original domain is.
It hashes per sub-domain/label, thus enabling inclusion in RPZ and allowing wildcard matching.

HashedRPZ uses [BLAKE3](https://github.com/BLAKE3-team/BLAKE3) which was selected as it is
secure, fast, keyed and can be used on shorter strings.

# Usage

These hashed domains can be used in RPZ, but also can be used in plain blocklists.
Of course, given support by the software that checks the RPZ or blocklist.

The example [hasher](cmd/hasher/) command can be used to take a list of domains on stdin and produce a hashed version on stdout with the provided key.

## Example Code

```
package main

import (
	"fmt"
	"github.com/massar/hashedrpz"
)

function main() {
	h := hashedrpz.New("teststring")

	o, err := h.Hash("host.example.net", 200)
	if err != nil {
		fmt.Printf("Hashing gave error %s", err)
		return
	}

	fmt.Printf("Hashed to:\n%s\n", o)
	return
}
```

# Key selection & distribution

The blake3 key can be based off any string, please select a long and complex one.

The blake3 key is typically derived from a combination of two strings.
One is optionally included in-band in the zone as a TXT record in ```_rpzhashkey.<domain>```.
The other is a configuration-time per-zone key that is out-of-band and thus not public.

Depending on paranoia, these keys could be as simple as the domain of the RPZ zone
or as complex as a 256 char randomly generated string.

The in-band key gets rotated often, as an adversary could grab it, so that the time it
would take to construct a rainbow table would be useless as before one has generated
a full list, the key would rotate away already.

The out-of-band key exists so that knowing the in-band key (which is included in the
clear in the zone file) is not enough either, especially as it rotates.

# Adversary Model

The adversary model is that if somebody wants to get to the list, the best they could do
is monitor DNS and check which labels are being NXDOMAINed by logging them on the recursor
while having to check separately that those domains really exist.
Which means they have to wait for a hit to find a single entry, and they cannot retrieve
the complete list in clear text.

Even having the current key though, one could attempt to do a rainbow-style DNS list
and try to guess all the domains that are on it, but that will take quite a bit of time
for that list then to materialize, as one even has to hash for each one separately and
with a rotating key, that becomes rather hard.

# HashedRPZ Algorithm

The algorithm is relatively simple (the hard part lives in blake3):

 - Split the label by component
 - if the label is a wildcard (*), keep it verbatim (unencrypted)
 - Hash with blake3 keyed with key each sublabel, but as a complete domain upto that point
 - Output the hash using base32hex lowercase (RFC4648)

e.g. www.example.com is actually hash(www.example.com) + '.' + hash(example.com) + '.' + hash(com)

Indeed, TLDs can thus be identified, but as there are 'few' TLDs in comparison and most commonly
it is '.com' this is not a huge worry.

# Example

Given for instance the domains (and depending on the key):
```
www.example.net
one.example.com
two.example.com
```

Results:
```
9mgrvf8.qa4gjtuvuia82ubhh705n29hm0.0hjg4h0
fca618e.r939194s2f5m5rdougo4rvc0gg.u32p0s0
w21jice.r939194s2f5m5rdougo4rvc0gg.u32p0s0
```

The same domain level is thus encoded the same (and TLDs become obvious that they are the same).

Short labels can thus be indentified (and one could guess that is 'www') as they produce shorter sub-hashes.
But even given that, one does not learn enough about the label for it to allow reversing to the real domain.

# Thanks

I'd like to thank the BLAKE3 team: [Jack O'Connor](https://github.com/oconnor663), [Samuel Neves](https://github.com/sneves), [Jean-Philippe Aumasson](https://github.com/veorq), [Zooko](https://github.com/zookozcash) for handling the cryptography, I have lots to learn there still, thus I am not 'rolling my own crypto'.
I recommend [Serious Cryptography by Jean-Philippe Aumasson](https://www.penguinrandomhouse.com/books/564922/serious-cryptography-by-jean-philippe-aumasson/) as a very good primer and background read and reference on these subjects.

Thanks to [Paul Vixie](https://redbarn.org) and [Vernon Schryver](https://www.rhyolite.com) for [RPZ](https://tools.ietf.org/html/draft-ietf-dnsop-dns-rpz-00) and the many implementors of RPZ for enabling the blocking of malicious and the amazing work they have put into making the Internet a better place.

Last, not least, thanks to [Peter van Dijk](https://github.com/habbie/) for many inputs and improvement suggestions.
