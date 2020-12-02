package main

// This golang code simply reads from stdin takes a DNS label per line and outputs them as hashedrpz to stdout

import (
	"bufio"
	"flag"
	"fmt"
	"os"

	"github.com/massar/hashedrpz"
)

func main() {
	var key string

	flag.StringVar(&key, "key", "", "The HashedRPZ Key")
	flag.Parse()

	if key == "" {
		fmt.Fprintf(os.Stderr, "Missing HashedRPZ Key")
		os.Exit(1)
		return
	}

	// Create a new HashedRPZ
	h := hashedrpz.New(key)

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()

		r := h.Hash(line)
		r = r[0 : len(r)-1]

		fmt.Printf("%s\n", r)
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stdout, "Error: %s\n", err)
		os.Exit(1)
	}

	return
}
