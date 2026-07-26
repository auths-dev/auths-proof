// auths-corpus-check audits the canonical V1 corpus with the production
// independent Go package.
package main

import (
	"errors"
	"fmt"
	"os"

	"auths.dev/independent-verifier/auths"
)

func main() {
	if len(os.Args) != 2 && !(len(os.Args) == 3 && os.Args[1] == "--semantic") {
		exit(errors.New("usage: auths-corpus-check [--semantic] <manifest.json>"))
	}
	digest, err := auths.AuditCorpus(os.Args[len(os.Args)-1], len(os.Args) == 3)
	if err != nil {
		exit(err)
	}
	fmt.Println(digest)
}

func exit(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
