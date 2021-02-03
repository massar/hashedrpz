package main

// This golang code simply reads from stdin takes a DNS label per line and outputs them as hashedrpz to stdout

import (
	"bufio"
	"flag"
	"fmt"
	"os"

	"github.com/massar/hashedrpz"
)

func init() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "hasher takes one or more domainnames on stdin and hashes the output using the HashedRPZ method.\n\n")
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
		return
	}
}

// main is the core program, calling hashedrpz.Hash() to hash
// the domainnames given on stdin.
//
// A key has to be specified using '-key'
func main() {
	var (
		key           string
		origindomain  string
		makewildcard  bool
		ignoretoolong bool
		echoownername bool
		addwildcards  bool
	)

	flag.StringVar(&key, "key", "", "The HashedRPZ Key")
	flag.StringVar(&origindomain, "origindomain", "", "The origindomain where this label will be included in (e.g. ```rpz.example.com```)")
	flag.BoolVar(&makewildcard, "makewildcard", false, "For domains exceeding the maxdomainlength either: false: cause an error (default), true: encode the too long items as a wildcard (will overblock adjacent labels in the same subdomain)")
	flag.BoolVar(&ignoretoolong, "ignoretoolong", false, "Ignores domains that exceed the maxdomainlength")
	flag.BoolVar(&echoownername, "echoownername", false, "Echos the ownername before the resulting hash")
	flag.BoolVar(&addwildcards, "addwildcards", false, "Inputs are domains, thus also output a wildcard hostname, to be able to block the labels inside the domain")
	flag.Parse()

	if key == "" {
		fmt.Fprintf(os.Stderr, "Missing HashedRPZ Key, please provide using '-key <keystring>'\n")
		os.Exit(1)
		return
	}

	if origindomain == "" {
		fmt.Fprintf(os.Stderr, "Missing OriginDomain, please provide using '-origindomain rpz.example.com'\n")
		os.Exit(1)
		return
	}

	// Create a new HashedRPZ
	h := hashedrpz.New(key)

	lineno := 0

	// Scan through stdin line by line
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		lineno++
		line := scanner.Text()

		var (
			r   string
			err error
		)

		iswildcard := false

		if makewildcard {
			r, iswildcard, err = h.HashWildcard(line, origindomain, hashedrpz.NoCallback)
		} else {
			r, err = h.Hash(line, origindomain, hashedrpz.NoCallback)
			if ignoretoolong && err == hashedrpz.ErrTooLong {
				err = nil
			}
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "Hashing of line %d (%q) failed: %s\n", lineno, line, err)
			os.Exit(1)
			return
		}

		r = r[0 : len(r)-1]

		if echoownername {
			fmt.Printf("; %s\n", line)
		}

		fmt.Printf("%s\n", r)

		if addwildcards && !iswildcard {
			fmt.Printf("*.%s\n", r)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stdout, "Error: %s\n", err)
		os.Exit(1)
	}

	return
}
