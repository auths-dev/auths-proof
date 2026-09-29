// auths-corpus-check audits the canonical V1 corpus with the production
// independent Go package.
package main

import (
	"errors"
	"fmt"
	"os"

	"auths.dev/independent-verifier/auths"
)

const usage = "usage: auths-corpus-check [--semantic [--report <file>]] <manifest.json>"

func main() {
	digest, err := run(os.Args[1:])
	if err != nil {
		exit(err)
	}
	fmt.Println(digest)
}

// run dispatches the three accepted argument shapes: the wire audit, the
// semantic audit, and the semantic audit with a per-vector report.
func run(args []string) (string, error) {
	switch {
	case len(args) == 1 && args[0] != "--semantic":
		return auths.AuditCorpus(args[0])
	case len(args) == 2 && args[0] == "--semantic":
		return auths.AuditSemantic(args[1], "")
	case len(args) == 4 && args[0] == "--semantic" && args[1] == "--report" && args[2] != "":
		return auths.AuditSemantic(args[3], args[2])
	default:
		return "", errors.New(usage)
	}
}

func exit(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
