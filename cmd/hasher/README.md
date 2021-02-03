# Hasher

Hasher can be used to apply HashedRPZ to a large set of input names as read from stdin.

Various options allow controlling the output and what actions to take.

It primarily serves as an example on how to use HashedRPZ and what options one has.

## Usage

```
$ ./hasher -h
hasher takes one or more domainnames on stdin and hashes the output using the HashedRPZ method.

Usage of ./hasher:
  -addwildcards
    	Inputs are domains, thus also output a wildcard hostname, to be able to block the labels inside the domain
  -echoownername
    	Echos the ownername before the resulting hash
  -ignoretoolong
    	Ignores domains that exceed the maxdomainlength
  -key string
    	The HashedRPZ Key
  -makewildcard
    	For domains exceeding the maxdomainlength either: false: cause an error (default), true: encode the too long items as a wildcard (will overblock adjacent labels in the same subdomain)
  -origindomain
    	The origindomain where this label will be included in (e.g. `rpz.example.com```)
```

## Example

Use the included queryfile-example-10million-201202 to do a large test and see the resulting labels:

```
go build .
cat ../../tests/queryfile-example-10million-201202 | awk '{print $1}' | ./hasher -key "n8dVJAIG G3ZTk6wF bo9cC5qC zjz3pePF K1q0YxqX GiIEio9R V9DdtNxx 1kLQYDuI" -origindomain rpz.example.net -makewildcard -echoownername -addwildcards
```

